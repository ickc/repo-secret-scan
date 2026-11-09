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


def _mock_client(handler):
    import httpx2

    from ghinsight.client import GitHubClient

    def factory(token, **kwargs):
        return GitHubClient(token, base_url="https://api.example.test", transport=httpx2.MockTransport(handler), **kwargs)

    return factory


def test_schedule_event_looks_up_visibility_with_token(actions_env, monkeypatch):
    import httpx2

    from repo_secret_scan import sources

    workspace, event = actions_env
    event.write_text(json.dumps({"schedule": "17 5 * * 1"}))
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    seen = []

    def handler(request):
        seen.append((request.url.path, request.headers["authorization"]))
        return httpx2.Response(200, json={"full_name": "octo-org/some-repo", "private": False, "visibility": "internal"})

    monkeypatch.setattr(sources, "GitHubClient", _mock_client(handler))
    assert github_actions_repo(workspace.resolve()).visibility == "internal"
    assert seen == [("/repos/octo-org/some-repo", "Bearer test-token")]


def test_visibility_lookup_failure_is_unknown_and_fast(actions_env, monkeypatch):
    import httpx2

    from repo_secret_scan import sources

    workspace, event = actions_env
    event.write_text(json.dumps({"schedule": "17 5 * * 1"}))
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    calls = []

    def handler(request):
        calls.append(request)
        return httpx2.Response(403, headers={"x-ratelimit-remaining": "0"})

    monkeypatch.setattr(sources, "GitHubClient", _mock_client(handler))
    assert github_actions_repo(workspace.resolve()).visibility == "unknown"
    assert len(calls) == 1  # no rate-limit wait inside a CI step


def test_org_list_repos_returns_mutable_repo_info(monkeypatch):
    import httpx2

    from repo_secret_scan import org
    from repo_secret_scan.models import RepoInfo

    def handler(request):
        assert request.url.path == "/orgs/octo-org/repos"
        return httpx2.Response(
            200,
            json=[
                {"full_name": "octo-org/b", "html_url": "https://github.com/octo-org/b", "private": True, "size": 3},
                {"full_name": "octo-org/A", "html_url": "https://github.com/octo-org/A", "visibility": "public", "fork": True},
            ],
        )

    monkeypatch.setattr(org, "GitHubClient", _mock_client(handler))
    repos = org.list_repos("octo-org", "test-token")
    assert repos == [
        RepoInfo("octo-org/A", url="https://github.com/octo-org/A", visibility="public", fork=True),
        RepoInfo("octo-org/b", url="https://github.com/octo-org/b", visibility="private", size_kb=3),
    ]
    repos[0].visibility = "private"  # scan code updates RepoInfo in place
