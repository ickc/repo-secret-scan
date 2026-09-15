from __future__ import annotations

from pathlib import Path

from repo_secret_scan.models import Finding, Location, RepoInfo, RepoScanResult, RunStatus, Severity
from repo_secret_scan.reporters.annotations import GitHubAnnotationsReporter, annotation_lines

from .conftest import fake_aws_key_id, fake_github_pat


def _finding(secret: str, severity: Severity, path: str = "app/config.py", line: int | None = 3, **kw) -> Finding:
    f = Finding.create(
        scanner="gitleaks", rule="github-pat", secret=secret,
        location=Location(path=path, line=line, commit="0123456789abcdef"), severity=severity, **kw,
    )
    f.secret = None
    return f


def _result(findings: list[Finding]) -> RepoScanResult:
    return RepoScanResult(
        repo=RepoInfo("o/r"), scope="history", head="abc", started_at="", finished_at="",
        status=RunStatus.OK, config_fingerprint="", findings=findings,
    )


def test_levels_filtering_and_dedup():
    token = fake_github_pat()
    findings = [
        _finding(fake_aws_key_id(), Severity.MEDIUM, in_head=True),
        _finding(token, Severity.CRITICAL, in_head=True, line=10),
        _finding(token, Severity.CRITICAL, in_head=False, line=2),  # same secret, same file: one annotation
        _finding(fake_github_pat(), Severity.LOW),
        _finding(fake_github_pat(), Severity.HIGH, suppressed=True),
    ]
    lines = annotation_lines(_result(findings), Severity.MEDIUM, 50)
    assert [line.split(" ", 1)[0] for line in lines] == ["::error", "::warning"]
    assert "line=10" in lines[0] and "still present on the default branch" in lines[0]
    assert token not in "\n".join(lines)
    assert findings[1].secret_hash in lines[0]


def test_workflow_command_escaping():
    f = _finding(fake_github_pat(), Severity.HIGH, path="dir,with:odd%chars/a.py")
    (line,) = annotation_lines(_result([f]), Severity.LOW, 50)
    props, message = line[len("::error ") :].split("::", 1)
    assert "file=dir%2Cwith%3Aodd%25chars/a.py" in props
    assert "\n" not in message


def test_cap_adds_overflow_notice():
    findings = [_finding(fake_github_pat(), Severity.HIGH, path=f"f{i}.py") for i in range(7)]
    lines = annotation_lines(_result(findings), Severity.LOW, 5)
    assert len(lines) == 5
    assert "3 more findings" in lines[-1]


def test_reporter_writes_file_and_emits_only_in_actions(tmp_path: Path, monkeypatch, capsys):
    result = _result([_finding(fake_github_pat(), Severity.HIGH)])
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    GitHubAnnotationsReporter().write(result, tmp_path)
    assert (tmp_path / "annotations.txt").read_text().startswith("::error ")
    assert capsys.readouterr().out == ""

    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    GitHubAnnotationsReporter().write(result, tmp_path)
    assert capsys.readouterr().out.startswith("::error ")
