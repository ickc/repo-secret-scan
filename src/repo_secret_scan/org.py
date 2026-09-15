"""Run the single-repository pipeline across every repository of an owner.

Scratch directory layout::

    <scratch>/
      work/clones/<owner>/<repo>.git   bare mirrors (sensitive: private code)
      work/tmp/                         scanner scratch space
      results/<owner>/<repo>/           per-repo result.json, findings.jsonl, report.md, results.sarif
      report/                           org-level report.md, dashboard.html, data/*.csv
"""

from __future__ import annotations

import fnmatch
import json
import logging
import time
import urllib.parse
import urllib.request
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .config import Config, OrgOptions
from .dataset import Dataset
from .models import RepoInfo, RepoScanResult, RunStatus
from .pipeline import (
    build_scanners, has_transient_errors, load_result, private_dir, reprocess, result_fingerprint, scan_repo, scanner_versions,
)
from .reporters import ORG_REPORTERS
from .sources import FullHistory, GitHubSource, github_token

log = logging.getLogger(__name__)

_RESCAN_STATUSES = {RunStatus.FAILED, RunStatus.TIMEOUT}


def _api_get(url: str, token: str | None) -> tuple[object, str | None]:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "repo-secret-scan", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as response:
        body = json.load(response)
        next_url = None
        for part in (response.headers.get("Link") or "").split(","):
            if 'rel="next"' in part:
                next_url = part[part.index("<") + 1 : part.index(">")]
        return body, next_url


def list_repos(owner: str, token: str | None) -> list[RepoInfo]:
    account, _ = _api_get(f"https://api.github.com/users/{urllib.parse.quote(owner)}", token)
    kind = "orgs" if isinstance(account, dict) and account.get("type") == "Organization" else "users"
    url: str | None = f"https://api.github.com/{kind}/{urllib.parse.quote(owner)}/repos?type=all&per_page=100"
    repos = []
    while url:
        page, url = _api_get(url, token)
        for r in page:  # type: ignore[union-attr]
            repos.append(
                RepoInfo(
                    slug=r["full_name"],
                    url=r["html_url"],
                    visibility=r.get("visibility") or ("private" if r.get("private") else "public"),
                    default_branch=r.get("default_branch"),
                    fork=r.get("fork"),
                    archived=r.get("archived"),
                    pushed_at=r.get("pushed_at"),
                    size_kb=r.get("size"),
                )
            )
    return sorted(repos, key=lambda r: r.slug.lower())


def select_repos(repos: list[RepoInfo], options: OrgOptions) -> list[RepoInfo]:
    def keep(r: RepoInfo) -> bool:
        name = r.slug.split("/", 1)[-1]
        return all([
            options.include_forks or not r.fork,
            options.include_archived or not r.archived,
            options.include_empty or (r.size_kb or 0) > 0,
            options.visibility == "all" or r.visibility == options.visibility,
            any(fnmatch.fnmatch(name, p) or fnmatch.fnmatch(r.slug, p) for p in options.include),
            not any(fnmatch.fnmatch(name, p) or fnmatch.fnmatch(r.slug, p) for p in options.exclude),
        ])

    return [r for r in repos if keep(r)]


def _is_fresh(cached: RepoScanResult | None, repo: RepoInfo, fingerprint: str) -> bool:
    return (
        cached is not None
        and cached.status not in _RESCAN_STATUSES
        and not has_transient_errors([*cached.errors, *(e for s in cached.scanner_runs for e in s.errors)])
        and cached.config_fingerprint == fingerprint
        and cached.repo.pushed_at == repo.pushed_at
    )


def scan_owner(
    owner: str,
    scratch: Path,
    config: Config,
    *,
    force: bool = False,
    limit: int | None = None,
    on_progress: Callable[[str], None] = print,
) -> tuple[Dataset, Path]:
    scratch = private_dir(scratch)
    workdir, results_root, report_dir = scratch / "work", scratch / "results", scratch / "report"
    token = github_token()

    repos = select_repos(list_repos(owner, token), config.org)
    if limit is not None:
        repos = repos[:limit]
    scanners = build_scanners(config)
    versions = scanner_versions(scanners)
    fingerprint = result_fingerprint(config, versions)
    on_progress(f"{len(repos)} repositories selected; scanners: {versions}")

    results: dict[str, RepoScanResult] = {}
    todo = []
    for repo in repos:
        cached = load_result(results_root / repo.slug)
        if not force and _is_fresh(cached, repo, fingerprint):
            results[repo.slug] = cached  # type: ignore[assignment]
        else:
            todo.append(repo)
    on_progress(f"{len(results)} up to date, {len(todo)} to scan")

    def work(repo: RepoInfo) -> tuple[RepoScanResult, float]:
        start = time.monotonic()
        source = GitHubSource.from_slug(repo.slug, repo=repo, token=token)
        result = scan_repo(
            source, FullHistory(), config, workdir=workdir, out_dir=results_root / repo.slug,
            scanners=scanners, versions=versions,
        )
        return result, time.monotonic() - start

    # Largest repositories first so the long poles start early.
    todo.sort(key=lambda r: -(r.size_kb or 0))
    with ThreadPoolExecutor(max_workers=max(1, config.org.jobs)) as pool:
        futures = {pool.submit(work, repo): repo for repo in todo}
        for done, future in enumerate(as_completed(futures), start=1):
            repo = futures[future]
            try:
                result, elapsed = future.result()
            except Exception as exc:  # noqa: BLE001
                on_progress(f"[{done}/{len(todo)}] {repo.slug}: crashed: {exc}")
                continue
            results[repo.slug] = result
            detail = "; ".join(result.errors + [e for s in result.scanner_runs for e in s.errors])[:200]
            on_progress(
                f"[{done}/{len(todo)}] {repo.slug}: {result.status.value}, "
                f"{len(result.findings)} findings, {elapsed:.0f}s" + (f" — {detail}" if detail else "")
            )

    dataset = Dataset.from_results(reprocess(r, config) for r in results.values())
    write_org_reports(dataset, report_dir, config, title=f"Secret scan: {owner}", on_progress=on_progress)
    return dataset, report_dir


def write_org_reports(dataset: Dataset, report_dir: Path, config: Config, *, title: str, on_progress: Callable[[str], None] = print) -> None:
    private_dir(report_dir)
    for name in config.report_formats:
        try:
            ORG_REPORTERS.create(name, config.component_options("org_reporter", name)).write(dataset, report_dir, title)
        except Exception as exc:  # noqa: BLE001
            on_progress(f"report {name} failed: {exc}")


def load_results(results_root: Path) -> list[RepoScanResult]:
    return [r for p in sorted(results_root.glob("*/*/result.json")) if (r := load_result(p.parent))]
