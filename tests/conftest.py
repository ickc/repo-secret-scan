from __future__ import annotations

import secrets
import string
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from repo_secret_scan import tools


def _rand(alphabet: str, n: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def fake_github_pat() -> str:
    # Assembled at runtime so no token-shaped literal lives in the repository.
    return "ghp" + "_" + _rand(string.ascii_letters + string.digits, 36)


def fake_aws_key_id() -> str:
    return "AK" + "IA" + _rand(string.ascii_uppercase + "234567", 16)


def fake_slack_bot_token() -> str:
    return "xox" + "b-" + _rand(string.digits, 12) + "-" + _rand(string.digits, 13) + "-" + _rand(string.ascii_letters + string.digits, 24)


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


@dataclass
class FixtureRepo:
    path: Path
    removed_token: str  # committed then deleted: history only
    live_key_id: str  # still in HEAD
    branch_token: str  # only on a side branch
    base_commit: str  # commit before the AWS key was added


@pytest.fixture
def fixture_repo(tmp_path: Path) -> FixtureRepo:
    repo = tmp_path / "fixture"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.email", "dev@example.com")
    git(repo, "config", "user.name", "Dev")
    git(repo, "config", "commit.gpgsign", "false")

    (repo / "README.md").write_text("# fixture\n")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "init")

    removed = fake_github_pat()
    (repo / "config.py").write_text(f'TOKEN = "{removed}"\n')
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "add token")
    git(repo, "rm", "-q", "config.py")
    git(repo, "commit", "-qm", "remove token")
    base = git(repo, "rev-parse", "HEAD")

    key_id = fake_aws_key_id()
    secret_key = _rand(string.ascii_letters + string.digits + "/+", 40)
    (repo / "creds.ini").write_text(f"aws_access_key_id = {key_id}\naws_secret_access_key = {secret_key}\n")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "add creds")

    git(repo, "checkout", "-qb", "feature")
    branch_token = fake_slack_bot_token()
    (repo / "notify.py").write_text(f'SLACK = "{branch_token}"\n')
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "slack")
    git(repo, "checkout", "-q", "main")
    return FixtureRepo(repo, removed, key_id, branch_token, base)


def _tools_available() -> bool:
    try:
        for spec in tools.TOOLS.values():
            tools.resolve(spec, install=False)
    except tools.ToolUnavailableError:
        return False
    return True


requires_scanners = pytest.mark.skipif(
    not _tools_available(), reason="scanner binaries not installed (run `repo-secret-scan tools install`)"
)
