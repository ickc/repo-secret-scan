"""TOML configuration.

Example::

    [scan]
    scanners = ["gitleaks", "trufflehog"]
    processors = ["in-head", "path-tags", "cross-scanner", "ignore-file", "triage"]
    reporters = ["markdown", "sarif"]  # findings.jsonl + result.json are always written

    [scanner.trufflehog]
    concurrency = 4

    [org]
    include_forks = true
    include_archived = true
    visibility = "all"
    jobs = 8

    [report]
    formats = ["csv", "markdown", "dashboard"]

Every ``[scanner.<name>]``, ``[processor.<name>]``, ``[reporter.<name>]`` and
``[org_reporter.<name>]`` table is passed as keyword arguments to that
component's constructor.
"""

from __future__ import annotations

import hashlib
import json
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_SCANNERS = ["gitleaks", "trufflehog"]
DEFAULT_PROCESSORS = ["in-head", "path-tags", "cross-scanner", "ignore-file", "triage"]
DEFAULT_REPORTERS = ["markdown", "sarif"]
DEFAULT_ORG_REPORTS = ["csv", "markdown", "dashboard"]
# Scanner options that affect speed or resource use but not findings.
OPERATIONAL_OPTIONS = {"timeout", "concurrency", "max_procs", "install"}


@dataclass
class OrgOptions:
    include_forks: bool = True
    include_archived: bool = True
    include_empty: bool = True
    visibility: str = "all"  # all | public | private | internal
    include: list[str] = field(default_factory=lambda: ["*"])
    exclude: list[str] = field(default_factory=list)
    jobs: int = 8


@dataclass
class Config:
    scanners: list[str] = field(default_factory=lambda: list(DEFAULT_SCANNERS))
    processors: list[str] = field(default_factory=lambda: list(DEFAULT_PROCESSORS))
    reporters: list[str] = field(default_factory=lambda: list(DEFAULT_REPORTERS))
    report_formats: list[str] = field(default_factory=lambda: list(DEFAULT_ORG_REPORTS))
    options: dict[str, dict[str, dict[str, Any]]] = field(default_factory=dict)
    org: OrgOptions = field(default_factory=OrgOptions)
    # Retries for failures caused by a busy host (fork/thread exhaustion).
    retries: int = 2
    retry_delay: float = 30.0

    def component_options(self, kind: str, name: str) -> dict[str, Any]:
        return dict(self.options.get(kind, {}).get(name, {}))

    def fingerprint(self, exclude_processors: frozenset[str] = frozenset()) -> str:
        """Identifies settings that change stored scan results, for cache invalidation.

        ``exclude_processors`` names processors re-applied at report time,
        whose settings therefore never invalidate a cached scan.
        """
        processors = [p for p in self.processors if p not in exclude_processors]
        relevant = {
            "scanners": self.scanners,
            "processors": processors,
            "scanner": {
                n: {k: v for k, v in self.component_options("scanner", n).items() if k not in OPERATIONAL_OPTIONS}
                for n in self.scanners
            },
            "processor": {n: self.component_options("processor", n) for n in processors},
        }
        return hashlib.sha256(json.dumps(relevant, sort_keys=True).encode()).hexdigest()[:16]


def load_config(path: Path | None) -> Config:
    if path is None:
        return Config()
    data = tomllib.loads(Path(path).read_text())
    scan = data.get("scan", {})
    config = Config(
        scanners=scan.get("scanners", list(DEFAULT_SCANNERS)),
        processors=scan.get("processors", list(DEFAULT_PROCESSORS)),
        reporters=scan.get("reporters", list(DEFAULT_REPORTERS)),
        report_formats=data.get("report", {}).get("formats", list(DEFAULT_ORG_REPORTS)),
        options={kind: data.get(kind, {}) for kind in ("scanner", "processor", "reporter", "org_reporter")},
        org=OrgOptions(**data.get("org", {})),
        retries=scan.get("retries", 2),
        retry_delay=scan.get("retry_delay", 30.0),
    )
    return config
