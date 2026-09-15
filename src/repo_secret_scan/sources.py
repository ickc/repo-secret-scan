"""Scan targets and how they are materialised on disk.

A *source* turns a target description (a local directory, ``Org/Repo`` or a
GitHub URL) into a :class:`Checkout` that scanners can read.
"""

from __future__ import annotations

import base64
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ._proc import CommandError, git, run
from .models import RepoInfo

_SLUG_RE = re.compile(r"^(?P<owner>[A-Za-z0-9_.-]+)/(?P<name>[A-Za-z0-9_.-]+?)(?:\.git)?$")
_GITHUB_URL_RE = re.compile(
    r"^(?:https://github\.com/|git@github\.com:|ssh://git@github\.com/)"
    r"(?P<owner>[A-Za-z0-9_.-]+)/(?P<name>[A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)


# --------------------------------------------------------------------------- scopes


@dataclass(frozen=True)
class FullHistory:
    """Every commit reachable from any branch or tag."""

    def describe(self) -> str:
        return "history"


@dataclass(frozen=True)
class CommitRange:
    """Commits in ``base..head``, e.g. the commits of a push or pull request."""

    base: str
    head: str = "HEAD"

    def describe(self) -> str:
        return f"range:{self.base}..{self.head}"


@dataclass(frozen=True)
class WorkingTree:
    """Files currently on disk, ignoring history."""

    def describe(self) -> str:
        return "tree"


Scope = FullHistory | CommitRange | WorkingTree


# ------------------------------------------------------------------------- checkout


@dataclass
class Checkout:
    repo: RepoInfo
    git_dir: Path | None
    worktree: Path | None
    head: str | None

    @property
    def is_bare(self) -> bool:
        return self.git_dir is not None and self.worktree is None

    @property
    def has_commits(self) -> bool:
        return self.head is not None


class Source(Protocol):
    repo: RepoInfo

    def materialize(self, workdir: Path) -> Checkout: ...


def _resolve_head(git_dir: Path, rev: str = "HEAD") -> str | None:
    result = git("rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}", git_dir=git_dir, check=False)
    return result.stdout.strip() or None


# ---------------------------------------------------------------------------- local


@dataclass
class LocalSource:
    path: Path
    repo: RepoInfo

    @classmethod
    def from_path(cls, path: Path) -> LocalSource:
        path = path.resolve()
        return cls(path=path, repo=RepoInfo(slug=path.name, visibility="local"))

    def materialize(self, workdir: Path) -> Checkout:
        probe = git("rev-parse", "--is-bare-repository", "--absolute-git-dir", cwd=self.path, check=False)
        if probe.returncode != 0:
            return Checkout(repo=self.repo, git_dir=None, worktree=self.path, head=None)
        is_bare, git_dir = probe.stdout.split()
        git_dir_path = Path(git_dir)
        worktree = None
        if is_bare != "true":
            worktree = Path(git("rev-parse", "--show-toplevel", cwd=self.path).stdout.strip())
        remote = git("remote", "get-url", "origin", git_dir=git_dir_path, check=False).stdout.strip()
        match = _GITHUB_URL_RE.match(remote) if remote else None
        if match:
            self.repo.url = f"https://github.com/{match['owner']}/{match['name']}"
        return Checkout(repo=self.repo, git_dir=git_dir_path, worktree=worktree, head=_resolve_head(git_dir_path))


# --------------------------------------------------------------------------- github


def github_token() -> str | None:
    for var in ("GH_TOKEN", "GITHUB_TOKEN"):
        if os.environ.get(var):
            return os.environ[var]
    if shutil.which("gh"):
        result = run(["gh", "auth", "token"], check=False)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    return None


def _auth_env(token: str | None) -> dict[str, str]:
    """Pass credentials through git config env vars, keeping them out of argv."""
    if not token:
        return {}
    basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    return {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
        "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {basic}",
    }


@dataclass
class GitHubSource:
    """A GitHub repository, mirrored as a bare clone under ``workdir/clones``."""

    owner: str
    name: str
    repo: RepoInfo
    token: str | None = None

    @classmethod
    def from_slug(cls, slug: str, repo: RepoInfo | None = None, token: str | None = None) -> GitHubSource:
        match = _SLUG_RE.match(slug) or _GITHUB_URL_RE.match(slug)
        if not match:
            raise ValueError(f"not a GitHub repository: {slug!r}")
        owner, name = match["owner"], match["name"]
        repo = repo or RepoInfo(slug=f"{owner}/{name}", url=f"https://github.com/{owner}/{name}")
        return cls(owner=owner, name=name, repo=repo, token=token)

    @property
    def clone_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.name}.git"

    def materialize(self, workdir: Path) -> Checkout:
        clone = workdir / "clones" / self.owner / f"{self.name}.git"
        env = _auth_env(self.token if self.token is not None else github_token())
        refspecs = ["+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*"]
        if (clone / "HEAD").exists():
            git("fetch", "--prune", "--quiet", self.clone_url, *refspecs, git_dir=clone, env=env)
        else:
            clone.parent.mkdir(parents=True, exist_ok=True)
            tmp = clone.with_name(clone.name + ".partial")
            shutil.rmtree(tmp, ignore_errors=True)
            try:
                git("clone", "--bare", "--quiet", self.clone_url, tmp, env=env)
            except CommandError:
                shutil.rmtree(tmp, ignore_errors=True)
                raise
            tmp.rename(clone)
        if self.repo.default_branch:
            # Keep HEAD pointing at the default branch even if it changed upstream.
            git("symbolic-ref", "HEAD", f"refs/heads/{self.repo.default_branch}", git_dir=clone, check=False)
        return Checkout(repo=self.repo, git_dir=clone, worktree=None, head=_resolve_head(clone))


def resolve_target(target: str) -> Source:
    path = Path(target).expanduser()
    if path.exists():
        return LocalSource.from_path(path)
    if _SLUG_RE.match(target) or _GITHUB_URL_RE.match(target):
        return GitHubSource.from_slug(target)
    raise ValueError(f"target {target!r} is neither an existing directory nor a GitHub owner/repo")
