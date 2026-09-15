"""SARIF 2.1.0 output, suitable for ``github/codeql-action/upload-sarif``."""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from ..models import RepoScanResult, Severity
from .base import REPORTERS

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
# GitHub code scanning orders alerts by this numeric "security-severity".
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def _tool_version() -> str:
    try:
        return version("repo-secret-scan")
    except PackageNotFoundError:
        return "0"


def to_sarif(result: RepoScanResult) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for f in result.findings:
        rule_id = f"{f.scanner}/{f.rule}"
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": f.rule,
                "shortDescription": {"text": f"{f.rule} ({f.scanner})"},
                "fullDescription": {"text": f.description or f.rule},
                "properties": {"tags": ["security", "secret"]},
            },
        )
        region = {"startLine": f.location.line} if f.location.line else {}
        where = f"commit {f.location.commit[:12]}" if f.location.commit else "working tree"
        entry: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _LEVEL[f.severity],
            "message": {
                "text": f"Possible {f.rule} secret `{f.preview}` in {where}"
                + ("" if f.in_head is False else " (still present)")
            },
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.location.path}, **({"region": region} if region else {})}}],
            "partialFingerprints": {"secretHash/v1": f.secret_hash},
            "properties": {
                "security-severity": _SECURITY_SEVERITY[f.severity],
                "severity": f.severity.value,
                "commit": f.location.commit,
                "inHead": f.in_head,
                "tags": sorted(f.tags),
            },
        }
        if f.suppressed:
            entry["suppressions"] = [{"kind": "external", "justification": f.suppression_reason}]
        results.append(entry)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "repo-secret-scan", "version": _tool_version(), "rules": list(rules.values())}},
                "results": results,
            }
        ],
    }


@REPORTERS.register("sarif")
@dataclass
class SarifReporter:
    filename: str = "results.sarif"

    def write(self, result: RepoScanResult, out_dir: Path) -> None:
        (out_dir / self.filename).write_text(json.dumps(to_sarif(result), indent=2) + "\n")
