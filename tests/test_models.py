from __future__ import annotations

from repo_secret_scan.models import (
    HASH_KEY_ENV,
    Finding,
    Location,
    Severity,
    hash_secret,
    mask_in_text,
    mask_secret,
)

from .conftest import fake_github_pat


def test_hash_is_stable_whitespace_insensitive_and_keyed(monkeypatch):
    token = fake_github_pat()
    assert hash_secret(token) == hash_secret(f"  {token}\n")
    default = hash_secret(token)
    monkeypatch.setenv(HASH_KEY_ENV, "another-key")
    assert hash_secret(token) != default


def test_mask_never_reveals_more_than_prefix():
    token = fake_github_pat()
    masked = mask_secret(token)
    assert masked.startswith(token[:4])
    assert token[4:] not in masked
    assert mask_secret("short") == "…(5 chars)"
    assert mask_secret("-----BEGIN RSA PRIVATE KEY-----\nabc\n") == "-----BEGIN RSA PRIVATE KEY-----"


def test_mask_in_text_removes_secret_from_context():
    token = fake_github_pat()
    context = mask_in_text(f'TOKEN = "{token}"', token)
    assert token not in context
    assert context.startswith("TOKEN = ")


def test_record_round_trip_drops_plaintext():
    token = fake_github_pat()
    finding = Finding.create(
        scanner="gitleaks", rule="github-pat", secret=token,
        location=Location(path="a.py", line=3, commit="abc"), tags={"test"},
    )
    record = finding.to_record()
    assert "secret" not in record
    assert token not in repr(finding)
    assert token not in str(record)
    restored = Finding.from_record(record)
    assert restored.secret is None
    assert restored.location == finding.location
    assert restored.tags == {"test"}
    assert restored.severity is Severity.MEDIUM


def test_severity_threshold():
    assert Severity.at_least(Severity.HIGH) == {Severity.CRITICAL, Severity.HIGH}
