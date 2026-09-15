"""End-to-end tests running the real scanner binaries on a synthetic repository."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from repo_secret_scan.config import Config
from repo_secret_scan.dataset import Dataset
from repo_secret_scan.models import RunStatus, mask_secret
from repo_secret_scan.org import load_results, write_org_reports
from repo_secret_scan.pipeline import load_result, scan_repo
from repo_secret_scan.sources import CommitRange, FullHistory, LocalSource, WorkingTree

from .conftest import FixtureRepo, git, requires_scanners

pytestmark = requires_scanners


def _all_output_text(root: Path) -> str:
    return "\n".join(p.read_text(errors="replace") for p in root.rglob("*") if p.is_file())


def _by_hash_and_scanner(result):
    return {(f.secret_hash, f.scanner): f for f in result.findings}


def test_full_history_scan(fixture_repo: FixtureRepo, tmp_path: Path):
    out = tmp_path / "out"
    result = scan_repo(LocalSource.from_path(fixture_repo.path), FullHistory(), Config(), workdir=tmp_path / "work", out_dir=out)

    assert result.status is RunStatus.OK, result.scanner_runs
    assert {r.scanner for r in result.scanner_runs} == {"gitleaks", "trufflehog"}
    groups: dict[str, set[str]] = {}
    for f in result.findings:
        groups.setdefault(f.preview, set()).add(f.scanner)
    in_head = {f.preview: f.in_head for f in result.findings}

    removed, live, branch = fixture_repo.removed_token, fixture_repo.live_key_id, fixture_repo.branch_token

    # trufflehog drops some random-looking tokens as likely false positives, so
    # only require agreement on the AWS key, which it reliably reports.
    assert "gitleaks" in groups[mask_secret(removed)]
    assert groups[mask_secret(live)] == {"gitleaks", "trufflehog"}
    assert "gitleaks" in groups[mask_secret(branch)], "side branches must be scanned"
    assert in_head[mask_secret(removed)] is False
    assert in_head[mask_secret(live)] is True
    assert in_head[mask_secret(branch)] is False

    # Plaintext secrets must never reach disk.
    text = _all_output_text(out)
    for secret in (removed, live, branch):
        assert secret not in text

    reloaded = load_result(out)
    assert _by_hash_and_scanner(reloaded).keys() == _by_hash_and_scanner(result).keys()
    sarif = json.loads((out / "results.sarif").read_text())
    assert len(sarif["runs"][0]["results"]) == len(result.findings)


def test_commit_range_scope_only_sees_new_commits(fixture_repo: FixtureRepo, tmp_path: Path):
    result = scan_repo(
        LocalSource.from_path(fixture_repo.path), CommitRange(base=fixture_repo.base_commit, head="main"), Config(),
        workdir=tmp_path / "work", out_dir=tmp_path / "out",
    )
    previews = {f.preview for f in result.findings}
    assert mask_secret(fixture_repo.live_key_id) in previews
    assert mask_secret(fixture_repo.removed_token) not in previews


def test_working_tree_scope(fixture_repo: FixtureRepo, tmp_path: Path):
    result = scan_repo(
        LocalSource.from_path(fixture_repo.path), WorkingTree(), Config(), workdir=tmp_path / "work", out_dir=tmp_path / "out",
    )
    assert result.findings
    assert {f.location.path for f in result.findings} == {"creds.ini"}
    assert all(f.in_head for f in result.findings)


def test_bare_clone_and_org_reports(fixture_repo: FixtureRepo, tmp_path: Path):
    bare = tmp_path / "fixture.git"
    git(tmp_path, "clone", "-q", "--bare", str(fixture_repo.path), str(bare))
    results_root = tmp_path / "scratch" / "results"
    result = scan_repo(LocalSource.from_path(bare), FullHistory(), Config(), workdir=tmp_path / "work", out_dir=results_root / "o" / "fixture")
    assert result.status is RunStatus.OK
    assert len({f.secret_hash for f in result.findings}) >= 3

    dataset = Dataset.from_results(load_results(results_root))
    config = Config(report_formats=["csv", "markdown"] + (["dashboard"] if _has_plotly() else []))
    report_dir = tmp_path / "scratch" / "report"
    write_org_reports(dataset, report_dir, config, title="test", on_progress=pytest.fail)
    assert (report_dir / "report.md").read_text().count("| ") > 5
    round_trip = Dataset.from_csv(report_dir / "data")
    assert round_trip.secrets == dataset.secrets
    assert fixture_repo.live_key_id not in _all_output_text(tmp_path / "scratch")


def _has_plotly() -> bool:
    try:
        import plotly  # noqa: F401
    except ImportError:
        return False
    return True
