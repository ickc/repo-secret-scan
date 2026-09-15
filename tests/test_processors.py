from __future__ import annotations

from pathlib import Path

from repo_secret_scan.models import Finding, Location, RepoInfo, Severity, Verification
from repo_secret_scan.processors import CrossScanner, IgnoreFile, InHead, PathTags, ProcessContext, Triage
from repo_secret_scan.sources import Checkout, FullHistory, LocalSource, WorkingTree

from .conftest import fake_aws_key_id, fake_github_pat, git


def _finding(secret: str, path: str = "app.py", scanner: str = "gitleaks", rule: str = "github-pat", **kw) -> Finding:
    return Finding.create(scanner=scanner, rule=rule, secret=secret, location=Location(path=path, line=1), **kw)


def _ctx(visibility: str = "private", scope=FullHistory()) -> ProcessContext:
    return ProcessContext(Checkout(RepoInfo("o/r", visibility=visibility), None, None, None), scope)


def test_in_head_distinguishes_history_from_current(fixture_repo, tmp_path: Path):
    checkout = LocalSource.from_path(fixture_repo.path).materialize(tmp_path)
    findings = [_finding(fixture_repo.removed_token), _finding(fixture_repo.live_key_id, rule="aws")]
    InHead().process(findings, ProcessContext(checkout, FullHistory()))
    assert [f.in_head for f in findings] == [False, True]


def test_in_head_is_true_for_working_tree_scope():
    findings = InHead().process([_finding(fake_github_pat())], _ctx(scope=WorkingTree()))
    assert findings[0].in_head is True


def test_path_tags():
    token = fake_github_pat()
    paths = {
        "tests/test_api.py": {"test"},
        "docs/setup.md": {"docs"},
        ".env.example": {"example"},
        "web/package-lock.json": {"lockfile"},
        "environment.yml": {"lockfile"},
        "static/app.min.js": {"vendored"},
        "app/__pycache__/cfg.cpython-311.pyc": {"generated", "binary"},
        "vendor/qhull.tgz.md5sum": {"vendored", "checksum"},
        "config/appsettings.json": set(),
        "src/app.py": set(),
    }
    findings = PathTags().process([_finding(token, path=p) for p in paths], _ctx())
    assert {f.location.path: f.tags for f in findings} == paths


def test_cross_scanner_marks_agreement():
    token, other = fake_github_pat(), fake_github_pat()
    findings = CrossScanner().process(
        [_finding(token), _finding(token, scanner="trufflehog"), _finding(other)], _ctx()
    )
    assert [("multi-scanner" in f.tags) for f in findings] == [True, True, False]
    assert findings[0].extra["found_by"] == ["gitleaks", "trufflehog"]


def test_ignore_file_from_repository_head(fixture_repo, tmp_path: Path):
    token = fake_github_pat()
    target = _finding(token)
    (fixture_repo.path / ".secret-scan-ignore.toml").write_text(
        f'[[ignore]]\nsecret_hash = "{target.secret_hash}"\nreason = "fixture"\n\n'
        '[[ignore]]\npath = "tests/*"\nrule = "generic-*"\nreason = "synthetic"\n'
    )
    git(fixture_repo.path, "add", ".")
    git(fixture_repo.path, "commit", "-qm", "ignore")
    bare = tmp_path / "bare.git"
    git(tmp_path, "clone", "-q", "--bare", str(fixture_repo.path), str(bare))
    checkout = LocalSource.from_path(bare).materialize(tmp_path)
    assert checkout.is_bare

    findings = [
        target,
        _finding(fake_github_pat(), path="tests/data.py", rule="generic-api-key"),
        _finding(fake_github_pat(), path="src/data.py", rule="generic-api-key"),
    ]
    IgnoreFile().process(findings, ProcessContext(checkout, FullHistory()))
    assert [f.suppressed for f in findings] == [True, True, False]
    assert findings[0].suppression_reason == "fixture"


def test_triage_scores():
    triage = Triage()
    specific_head = _finding(fake_aws_key_id(), rule="aws-access-token", in_head=True)
    specific_history = _finding(fake_aws_key_id(), rule="aws-access-token", in_head=False)
    generic_test = _finding(fake_github_pat(), rule="generic-api-key", in_head=False, tags={"test"})
    live = _finding(fake_github_pat(), rule="generic-api-key", verification=Verification.LIVE)
    weak_notebook = _finding(fake_github_pat(), rule="Box", scanner="trufflehog", in_head=True, tags={"notebook"})
    other_detector = _finding(fake_github_pat(), rule="CloudflareApiToken", scanner="trufflehog", in_head=True)
    triage.process([specific_head, specific_history, generic_test, live, weak_notebook, other_detector], _ctx("private"))
    assert specific_head.severity is Severity.CRITICAL
    assert specific_history.severity is Severity.HIGH, "a real key only in history still needs rotating"
    assert generic_test.severity is Severity.INFO
    assert live.severity is Severity.CRITICAL
    assert weak_notebook.severity is Severity.INFO
    assert other_detector.severity is Severity.MEDIUM
    assert specific_head.extra["severity_reasons"][:2] == ["high-confidence detector", "still in default branch"]

    public = _finding(fake_aws_key_id(), rule="aws-access-token", in_head=True)
    triage.process([public], _ctx("public"))
    assert public.severity is Severity.CRITICAL
