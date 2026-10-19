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


def test_a_shared_directory_never_receives_the_label_index(tmp_path):
    source = _csv_source(tmp_path, _password())
    share = tmp_path / "share"
    result = runner.invoke(app, ["report", str(source), "--redact", "--out", str(share), "--label-index", str(share / "idx.json")])
    assert result.exit_code != 0
    assert "--label-index" in result.output
    assert not (share / "idx.json").exists()
