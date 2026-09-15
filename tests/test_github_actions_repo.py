from __future__ import annotations

import json
from pathlib import Path

import pytest

from repo_secret_scan.sources import LocalSource, github_actions_repo


@pytest.fixture
def actions_env(tmp_path: Path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    event = tmp_path / "event.json"
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "octo-org/some-repo")
    monkeypatch.setenv("GITHUB_WORKSPACE", str(workspace))
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    return workspace, event


def test_visibility_and_identity_from_event(actions_env):
    workspace, event = actions_env
    event.write_text(json.dumps({"repository": {"visibility": "public", "default_branch": "main", "fork": False}}))
    repo = LocalSource.from_path(workspace).repo
    assert (repo.slug, repo.visibility, repo.default_branch) == ("octo-org/some-repo", "public", "main")
    assert repo.html_url == "https://github.com/octo-org/some-repo"


def test_private_flag_fallback(actions_env):
    workspace, event = actions_env
    event.write_text(json.dumps({"repository": {"private": True}}))
    assert github_actions_repo(workspace.resolve()).visibility == "private"


def test_schedule_event_without_repository_or_token_is_unknown(actions_env):
    workspace, event = actions_env
    event.write_text(json.dumps({"schedule": "17 5 * * 1"}))
    assert github_actions_repo(workspace.resolve()).visibility == "unknown"


def test_ignored_outside_actions_or_outside_workspace(actions_env, tmp_path: Path, monkeypatch):
    workspace, event = actions_env
    event.write_text(json.dumps({"repository": {"visibility": "public"}}))
    assert github_actions_repo(tmp_path.resolve()) is None  # not the workspace
    monkeypatch.setenv("GITHUB_ACTIONS", "false")
    assert LocalSource.from_path(workspace).repo.visibility == "local"
