from __future__ import annotations

import json
from pathlib import Path

from repo_secret_scan.models import Verification
from repo_secret_scan.scanners.gitleaks import parse_report
from repo_secret_scan.scanners.trufflehog import parse_log_errors, parse_output

from .conftest import fake_aws_key_id, fake_github_pat


def test_gitleaks_report_is_normalised():
    token = fake_github_pat()
    records = [
        {
            "RuleID": "github-pat", "Description": "GitHub PAT", "StartLine": 2, "Match": f'token = "{token}"',
            "Secret": token, "File": "/repo/src/config.py", "Commit": "c0ffee", "Entropy": 5.1,
            "Email": "dev@example.com", "Date": "2024-01-02T03:04:05Z", "Fingerprint": "c0ffee:src/config.py:github-pat:2",
        },
        {"RuleID": "empty", "Secret": "", "Match": "", "File": "x"},
    ]
    (finding,) = parse_report(records, root=Path("/repo"))
    assert finding.rule == "github-pat"
    assert finding.location.path == "src/config.py"
    assert finding.location.line == 2
    assert finding.location.commit == "c0ffee"
    assert token not in finding.context
    assert finding.secret == token


def _trufflehog_line(raw: str, **overrides) -> str:
    record = {
        "SourceMetadata": {"Data": {"Git": {
            "commit": "deadbeef", "file": "creds.ini", "email": "Dev <dev@example.com>",
            "timestamp": "2024-01-02 03:04:05 +0000", "line": 1,
        }}},
        "DetectorName": "AWS", "DetectorType": 2, "DecoderName": "PLAIN", "Verified": False,
        "Raw": raw, "RawV2": raw + ":secretpart", "ExtraData": {"account": "123"},
        "SecretParts": {"secret_access_key": "should-never-be-kept"},
    }
    record.update(overrides)
    return json.dumps(record)


def test_trufflehog_output_is_normalised():
    key_id = fake_aws_key_id()
    stdout = "\n".join([_trufflehog_line(key_id), "not json", ""])
    (finding,) = parse_output(stdout)
    assert finding.rule == "AWS"
    assert finding.location.author_email == "dev@example.com"
    assert finding.location.commit_date == "2024-01-02T03:04:05+00:00"
    assert finding.verification is Verification.UNKNOWN
    assert finding.extra["detector_account"] == "123"
    assert "should-never-be-kept" not in json.dumps(finding.to_record())


def test_trufflehog_verification_mapping():
    key_id = fake_aws_key_id()
    live = parse_output(_trufflehog_line(key_id, Verified=True), verify=True)[0]
    invalid = parse_output(_trufflehog_line(key_id), verify=True)[0]
    errored = parse_output(_trufflehog_line(key_id, VerificationError="timeout"), verify=True)[0]
    assert (live.verification, invalid.verification, errored.verification) == (
        Verification.LIVE, Verification.INVALID, Verification.ERROR,
    )


def test_trufflehog_filesystem_paths_are_relative():
    key_id = fake_aws_key_id()
    line = _trufflehog_line(key_id, SourceMetadata={"Data": {"Filesystem": {"file": "/work/tree/a/b.env", "line": 4}}})
    (finding,) = parse_output(line, root=Path("/work/tree"))
    assert finding.location.path == "a/b.env"
    assert finding.location.commit is None


def test_trufflehog_log_errors():
    stderr = "\n".join([
        json.dumps({"level": "info-0", "msg": "running"}),
        json.dumps({"level": "error", "msg": "error scanning", "error": "bad object"}),
    ])
    assert parse_log_errors(stderr) == ["error scanning: bad object"]
