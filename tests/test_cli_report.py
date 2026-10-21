from __future__ import annotations

import csv
import secrets
import string

from typer.testing import CliRunner

from repo_secret_scan import publish
from repo_secret_scan.cli import app
from repo_secret_scan.dataset import Dataset
from repo_secret_scan.models import (
    Finding,
    Location,
    RepoInfo,
    RepoScanResult,
    RunStatus,
    Severity,
    mask_in_text,
)

runner = CliRunner()


def _password() -> str:
    return "Pw" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(38))


def _dataset(secret: str) -> Dataset:
    finding = Finding.create(
        scanner="gitleaks",
        rule="generic-api-key",
        secret=secret,
        location=Location(path="src/config.py", line=7, commit="a" * 40, commit_date="2020-01-01T00:00:00Z"),
        context=mask_in_text(f'KEY = "{secret}"', secret),
        entropy=4.5,
        severity=Severity.CRITICAL,
    )
    result = RepoScanResult(
        repo=RepoInfo(slug="my-org/some-repo", url="https://github.com/my-org/some-repo", visibility="public"),
        scope="history",
        head="0" * 40,
        started_at="2020-01-01T00:00:00Z",
        finished_at="2020-01-01T00:01:00Z",
        status=RunStatus.OK,
        config_fingerprint="abc123",
        findings=[finding],
    )
    return Dataset.from_results([result])


def _csv_source(tmp_path, secret: str):
    """A report directory as a previous run left it: pages plus ``data/``."""
    data_dir = tmp_path / "report" / "data"
    _dataset(secret).write_csv(data_dir)
    return data_dir


def _config(tmp_path, formats: str) -> str:
    path = tmp_path / "cfg.toml"
    path.write_text(f"[report]\nformats = {formats}\n")
    return str(path)


def test_redacting_csvs_in_place_is_refused(tmp_path):
    source = _csv_source(tmp_path, _password())
    result = runner.invoke(app, ["report", str(source), "--redact"])
    assert result.exit_code != 0
    assert "--out" in result.output
    # The originals are untouched.
    assert "secret_hash" in (source / "secrets.csv").read_text()
    assert not list(source.glob("secret-labels.json"))


def test_a_shared_directory_never_receives_the_label_index(tmp_path):
    source = _csv_source(tmp_path, _password())
    share = tmp_path / "share"
    result = runner.invoke(app, ["report", str(source), "--redact", "--out", str(share), "--label-index", str(share / "idx.json")])
    assert result.exit_code != 0
    assert "--label-index" in result.output
    assert not (share / "idx.json").exists()


def test_redacting_to_a_separate_directory_writes_redacted_csvs(tmp_path):
    password = _password()
    source = _csv_source(tmp_path, password)
    share = tmp_path / "share"
    index = tmp_path / publish.INDEX_FILENAME

    # Configured formats omit csv; redaction adds it, or the shared directory would
    # hold redacted pages and no data while the unredacted CSVs stayed behind.
    result = runner.invoke(app, [
        "report", str(source), "--redact", "--out", str(share),
        "--label-index", str(index), "--config", _config(tmp_path, '["markdown"]'),
    ])
    assert result.exit_code == 0, result.output

    rows = list(csv.DictReader((share / "data" / "secrets.csv").open()))
    assert rows and all(r["secret_hash"].startswith(publish.ID_PREFIX) for r in rows)
    blob = (share / "data" / "secrets.csv").read_text() + (share / "report.md").read_text()
    assert password not in blob
    assert password[:4] not in blob
    assert f"({len(password)} chars)" not in blob
    assert index.exists()
    assert not (share / publish.INDEX_FILENAME).exists()


def test_without_redact_a_csv_source_still_renders_in_place(tmp_path):
    source = _csv_source(tmp_path, _password())
    before = (source / "secrets.csv").read_text()
    result = runner.invoke(app, ["report", str(source)])
    assert result.exit_code == 0, result.output
    assert (source / "secrets.csv").read_text() == before
    assert (tmp_path / "report" / "report.md").exists()


def test_reports_say_where_a_moved_secret_is_now():
    from repo_secret_scan.reporters.markdown import render

    unmoved = _dataset(_password())
    assert unmoved.secrets[0]["head_location"] == ""
    assert "; now" not in render(unmoved, "t")

    secret = _password()
    finding = Finding.create(
        scanner="gitleaks", rule="generic-api-key", secret=secret,
        location=Location(path="src/config.py", line=7, commit="a" * 40), severity=Severity.CRITICAL,
    )
    finding.extra["head_location"] = {"path": "src/config.py", "line": 12}
    result = RepoScanResult(
        repo=RepoInfo(slug="my-org/some-repo", url="https://github.com/my-org/some-repo", visibility="public"),
        scope="history", head="0" * 40, started_at="", finished_at="", status=RunStatus.OK,
        config_fingerprint="", findings=[finding],
    )
    (row,) = Dataset.from_results([result]).secrets
    assert row["head_location"] == "src/config.py:12"
    assert row["head_link"] == "https://github.com/my-org/some-repo/blob/" + "0" * 40 + "/src/config.py#L12"
    text = render(Dataset.from_results([result]), "t")
    assert "now [`src/config.py:12`](" + row["head_link"] + ")" in text
