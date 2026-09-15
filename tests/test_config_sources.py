from __future__ import annotations

from pathlib import Path

import pytest

from repo_secret_scan.config import OrgOptions, load_config
from repo_secret_scan.models import RepoInfo
from repo_secret_scan.org import select_repos
from repo_secret_scan.processors import PROCESSORS
from repo_secret_scan.registry import UnknownComponentError
from repo_secret_scan.scanners import SCANNERS
from repo_secret_scan.sources import GitHubSource, LocalSource, resolve_target


def test_config_options_reach_components(tmp_path: Path):
    path = tmp_path / "c.toml"
    path.write_text(
        '[scan]\nscanners = ["trufflehog"]\n[scanner.trufflehog]\nconcurrency = 3\nverify = true\n'
        '[org]\ninclude_forks = false\njobs = 2\n'
    )
    config = load_config(path)
    scanner = SCANNERS.create("trufflehog", config.component_options("scanner", "trufflehog"))
    assert (scanner.concurrency, scanner.verify) == (3, True)
    assert (config.org.include_forks, config.org.jobs) == (False, 2)


def test_fingerprint_tracks_result_affecting_settings(tmp_path: Path):
    a = load_config(None)
    b = load_config(None)
    b.options["scanner"] = {"trufflehog": {"verify": True}}
    assert a.fingerprint() != b.fingerprint()
    c = load_config(None)
    c.report_formats = ["csv"]
    c.options["scanner"] = {"trufflehog": {"concurrency": 2, "timeout": 5}}
    assert a.fingerprint() == c.fingerprint()


def test_offline_processor_options_do_not_invalidate_cache():
    from repo_secret_scan.pipeline import result_fingerprint

    a = load_config(None)
    b = load_config(None)
    b.options["processor"] = {"triage": {"high_confidence_score": 5}}
    assert result_fingerprint(a, {}) == result_fingerprint(b, {})
    b.options["processor"]["in-head"] = {"batch_size": 1}
    assert result_fingerprint(a, {}) != result_fingerprint(b, {})


def test_reprocess_applies_current_policy_but_keeps_scan_facts():
    from repo_secret_scan.config import Config
    from repo_secret_scan.models import Finding, Location, RepoScanResult, RunStatus, Severity
    from repo_secret_scan.pipeline import reprocess

    from .conftest import fake_aws_key_id

    finding = Finding.create(
        scanner="gitleaks", rule="aws-access-token", secret=fake_aws_key_id(),
        location=Location(path="notebooks/x.ipynb"), in_head=True, suppressed=True, tags={"stale-tag"},
    )
    finding.secret = None
    result = RepoScanResult(
        repo=RepoInfo("o/r", visibility="private"), scope="history", head="abc", started_at="", finished_at="",
        status=RunStatus.OK, config_fingerprint="", findings=[finding],
    )
    config = Config()
    config.options["processor"] = {"triage": {"tag_weights": {}}}
    (after,) = reprocess(result, config).findings
    assert after.tags == {"notebook"}
    assert after.in_head is True and after.suppressed is True
    assert after.severity is Severity.CRITICAL  # 4 high-confidence + 1 in HEAD, notebook weight disabled


def test_transient_error_detection():
    from repo_secret_scan._proc import is_transient, summarise_stderr

    crash = (
        "runtime: failed to create new OS thread (have 12 already; errno=11)\n"
        "fatal error: newosproc\n\ngoroutine 1 [running]:\n\t/src/semgroup.go:64 +0x88\n"
    )
    assert is_transient(crash)
    assert "fatal error: newosproc" in summarise_stderr(crash)
    assert "goroutine" not in summarise_stderr(crash)
    assert not is_transient("fatal: repository not found")


def test_registry_errors():
    with pytest.raises(UnknownComponentError, match="available"):
        PROCESSORS.create("nope")
    with pytest.raises(ValueError, match="invalid options"):
        SCANNERS.create("gitleaks", {"bogus": 1})


def test_resolve_target(tmp_path: Path):
    assert isinstance(resolve_target(str(tmp_path)), LocalSource)
    for target in ("octo-org/repo", "https://github.com/octo-org/repo.git", "git@github.com:octo-org/repo.git"):
        source = resolve_target(target)
        assert isinstance(source, GitHubSource)
        assert source.repo.slug == "octo-org/repo"
    with pytest.raises(ValueError):
        resolve_target("definitely not a target")


def test_select_repos_filters():
    repos = [
        RepoInfo("o/app", visibility="public", fork=False, archived=False, size_kb=10),
        RepoInfo("o/fork", visibility="public", fork=True, archived=False, size_kb=10),
        RepoInfo("o/old", visibility="private", fork=False, archived=True, size_kb=10),
        RepoInfo("o/empty", visibility="private", fork=False, archived=False, size_kb=0),
    ]
    slugs = lambda opts: [r.slug for r in select_repos(repos, opts)]  # noqa: E731
    assert slugs(OrgOptions()) == ["o/app", "o/fork", "o/old", "o/empty"]
    assert slugs(OrgOptions(include_forks=False, include_archived=False, include_empty=False)) == ["o/app"]
    assert slugs(OrgOptions(visibility="private", exclude=["emp*"])) == ["o/old"]
