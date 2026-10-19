from __future__ import annotations

import secrets
import stat
import string

import pytest

from repo_secret_scan import publish
from repo_secret_scan.dataset import Dataset
from repo_secret_scan.models import (
    Finding,
    Location,
    RepoInfo,
    RepoScanResult,
    RunStatus,
    Severity,
    mask_in_text,
    mask_secret,
)
from repo_secret_scan.reporters import markdown

from .conftest import fake_aws_key_id, fake_github_pat


def fake_password() -> str:
    # Human-shaped rather than token-shaped: no vendor prefix to recognise.
    return "Pw" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(38))


def _result(findings: list[Finding]) -> RepoScanResult:
    return RepoScanResult(
        repo=RepoInfo(slug="my-org/some-repo", url="https://github.com/my-org/some-repo", visibility="public"),
        scope="history",
        head="0" * 40,
        started_at="2020-01-01T00:00:00Z",
        finished_at="2020-01-01T00:01:00Z",
        status=RunStatus.OK,
        config_fingerprint="abc123",
        findings=findings,
    )


def _finding(secret: str, **kwargs) -> Finding:
    return Finding.create(
        scanner="gitleaks",
        rule="generic-api-key",
        secret=secret,
        location=Location(path="src/config.py", line=7, commit="a" * 40, commit_date="2020-01-01T00:00:00Z"),
        context=mask_in_text(f'KEY = "{secret}"', secret),
        entropy=4.5,
        severity=Severity.CRITICAL,
        **kwargs,
    )


def test_bucket_length_reports_a_range_not_an_exact_value():
    assert publish.bucket_length(5) == "0-15"
    assert publish.bucket_length(16) == "16-23"
    assert publish.bucket_length(32) == "32-39"
    assert publish.bucket_length(40) == "40-47"
    assert publish.bucket_length(5000) == "1024+"


def test_preview_drops_every_prefix_whatever_it_looks_like():
    # A vendor marker and a password opening are indistinguishable in four
    # characters, and the detector name already gives the credential type.
    token = fake_github_pat()
    assert publish.redact_preview(mask_secret(token)) == "…(40-47 chars)"
    assert "ghp" not in publish.redact_preview(mask_secret(token))

    key_id = fake_aws_key_id()
    assert "AKIA" not in publish.redact_preview(mask_secret(key_id))

    password = fake_password()
    redacted = publish.redact_preview(mask_secret(password))
    assert redacted == "…(40-47 chars)"
    assert password[:4] not in redacted


def test_preview_drops_a_prefix_that_collides_with_a_uri_scheme():
    # "post" is the start of postgres:// and also of plenty of passwords.
    secret = "post" + "gresqlpassword0123456789abcdef"
    assert publish.redact_preview(mask_secret(secret)) == "…(32-39 chars)"


def test_preview_keeps_a_pem_header_and_rejects_unknown_shapes():
    assert publish.redact_preview("-----BEGIN RSA PRIVATE KEY-----") == "-----BEGIN RSA PRIVATE KEY-----"
    assert publish.redact_preview("whatever this is") == "…(redacted)"
    assert publish.redact_preview("") == ""


def test_labels_are_stable_unrelated_to_the_hash_and_persist(tmp_path):
    index = publish.LabelIndex()
    first = index.label_for("deadbeef" * 3)
    assert index.label_for("deadbeef" * 3) == first
    assert index.label_for("cafebabe" * 3) != first
    assert "deadbeef" not in first
    assert first.startswith(publish.ID_PREFIX)
    assert index.label_for("") == ""

    path = index.save(tmp_path / publish.INDEX_FILENAME)
    reloaded = publish.LabelIndex.load(path)
    assert reloaded.label_for("deadbeef" * 3) == first
    assert not reloaded.dirty


def test_label_index_is_owner_only(tmp_path):
    index = publish.LabelIndex()
    index.label_for("deadbeef" * 3)
    path = index.save(tmp_path / publish.INDEX_FILENAME)
    assert not stat.S_IMODE(path.stat().st_mode) & 0o077


def test_label_index_rejects_an_unknown_version(tmp_path):
    path = tmp_path / publish.INDEX_FILENAME
    path.write_text('{"version": 999, "labels": {}}')
    with pytest.raises(ValueError, match="version"):
        publish.LabelIndex.load(path)


def test_missing_index_starts_empty(tmp_path):
    index = publish.LabelIndex.load(tmp_path / "nope.json")
    assert index.labels == {}


def test_redacted_dataset_carries_nothing_derived_from_the_secret(tmp_path):
    password, token = fake_password(), fake_github_pat()
    findings = [_finding(password), _finding(token)]
    hashes = {f.secret_hash for f in findings}
    dataset = Dataset.from_results([_result(findings)])
    assert dataset.redacted is False

    index = publish.LabelIndex()
    redacted = publish.redact(dataset, index)
    assert redacted.redacted is True
    # The original dataset is untouched, so an operator can still render both.
    assert {s["secret_hash"] for s in dataset.secrets} == hashes

    redacted.write_csv(tmp_path)
    blob = "".join((tmp_path / f"{name}.csv").read_text() for name in ("repos", "secrets", "findings"))
    for secret in (password, token):
        assert secret not in blob
        assert secret[4:] not in blob
    for secret_hash in hashes:
        assert secret_hash not in blob
    assert f"({len(password)} chars)" not in blob
    assert "4.5" not in blob

    for row in [*redacted.secrets, *redacted.findings]:
        assert row["secret_hash"] in index.labels.values()
    assert all(f["entropy"] == "" for f in redacted.findings)
    # Context keeps the surrounding code but inherits the trimmed preview.
    contexts = [f["context"] for f in redacted.findings]
    assert all(c.startswith("KEY = ") for c in contexts)
    assert any("40-47 chars" in c for c in contexts)


def test_redaction_is_idempotent_across_runs(tmp_path):
    findings = [_finding(fake_password())]
    dataset = Dataset.from_results([_result(findings)])
    path = tmp_path / publish.INDEX_FILENAME

    index = publish.LabelIndex.load(path)
    first = publish.redact(dataset, index).secrets[0]["secret_hash"]
    index.save(path)

    index = publish.LabelIndex.load(path)
    assert publish.redact(dataset, index).secrets[0]["secret_hash"] == first


def test_markdown_labels_the_column_and_explains_the_ids():
    dataset = Dataset.from_results([_result([_finding(fake_password())])])
    plain = markdown.render(dataset, "Plain")
    assert "| Hash |" in plain
    assert "opaque id" not in plain

    redacted = markdown.render(publish.redact(dataset, publish.LabelIndex()), "Redacted")
    assert "| ID |" in redacted
    assert "opaque id" in redacted
    assert "cannot be used in `secret_hash`" in redacted


@pytest.mark.parametrize("padding", [148, 150, 155])
def test_context_is_withheld_when_a_truncated_preview_survives(padding):
    password = fake_password()
    preview = mask_secret(password)
    # mask_in_text truncates after masking, so a preview near the cutoff is cut
    # short. How much of it survives depends on where the line is cut, and a
    # substitution of the whole preview misses every one of these.
    truncated = mask_in_text("x" * padding + f'KEY = "{password}"', password)
    assert preview not in truncated
    assert truncated.endswith("…")

    safe = publish.redact_context(truncated, preview, publish.redact_preview(preview))
    assert safe == publish.CONTEXT_WITHHELD
    assert password[:2] not in safe


def test_context_without_the_secret_is_left_alone():
    password = fake_password()
    context = "ssh_key = load(path) # nothing sensitive on this line"
    assert publish.redact_context(context, mask_secret(password), "…") == context
    assert publish.redact_context("", mask_secret(password), "…") == ""


def test_redacted_findings_never_keep_a_truncated_preview(tmp_path):
    password = fake_password()
    finding = _finding(password)
    finding.context = mask_in_text("y" * 150 + f'KEY = "{password}"', password)
    dataset = Dataset.from_results([_result([finding])])

    redacted = publish.redact(dataset, publish.LabelIndex())
    redacted.write_csv(tmp_path)
    blob = (tmp_path / "findings.csv").read_text()
    assert password[:4] not in blob
    assert publish.CONTEXT_WITHHELD in blob
