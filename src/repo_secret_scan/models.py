"""Scanner-agnostic data model shared by every pipeline stage.

The raw secret value only ever lives in memory (``Finding.secret``); it is
never serialised. Persisted records carry a keyed hash, used to correlate the
same secret across scanners, commits, repositories and runs, plus a short
masked preview for humans.
"""

from __future__ import annotations

import enum
import hashlib
import hmac
import os
from dataclasses import dataclass, field, fields
from typing import Any

HASH_KEY_ENV = "REPO_SECRET_SCAN_HASH_KEY"
_DEFAULT_HASH_KEY = "repo-secret-scan"


class Verification(str, enum.Enum):
    """Whether a secret is known to be live. Only verifier stages set this."""

    UNKNOWN = "unknown"
    LIVE = "live"
    INVALID = "invalid"
    ERROR = "error"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)

    @classmethod
    def at_least(cls, threshold: Severity) -> set[Severity]:
        return {s for s in cls if s.rank <= threshold.rank}


def normalise_secret(secret: str) -> str:
    return secret.strip()


def hash_secret(secret: str) -> str:
    """Keyed hash of a secret; stable across runs for a given key."""
    key = os.environ.get(HASH_KEY_ENV, _DEFAULT_HASH_KEY).encode()
    digest = hmac.new(key, normalise_secret(secret).encode(), hashlib.sha256)
    return digest.hexdigest()[:24]


def mask_secret(secret: str) -> str:
    """Human hint that reveals the token family but not the secret itself."""
    secret = normalise_secret(secret)
    first_line = secret.splitlines()[0] if secret else ""
    if first_line.startswith("-----BEGIN"):
        return first_line
    if len(secret) >= 16:
        return f"{secret[:4]}…({len(secret)} chars)"
    return f"…({len(secret)} chars)"


def mask_in_text(text: str, secret: str, limit: int = 160) -> str:
    """Replace the secret inside surrounding context, flattened to one line."""
    secret = normalise_secret(secret)
    if secret:
        text = text.replace(secret, mask_secret(secret))
        # Multi-line secrets may be only partially present in the match.
        for line in secret.splitlines():
            if len(line) >= 8:
                text = text.replace(line, "…")
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


@dataclass(frozen=True)
class Location:
    path: str
    line: int | None = None
    commit: str | None = None
    commit_date: str | None = None
    author_email: str | None = None


@dataclass
class Finding:
    scanner: str
    rule: str
    location: Location
    secret_hash: str
    preview: str
    description: str = ""
    context: str = ""
    entropy: float | None = None
    verification: Verification = Verification.UNKNOWN
    severity: Severity = Severity.MEDIUM
    in_head: bool | None = None
    suppressed: bool = False
    suppression_reason: str = ""
    tags: set[str] = field(default_factory=set)
    extra: dict[str, Any] = field(default_factory=dict)
    # In-memory only: never serialised, never shown in repr.
    secret: str | None = field(default=None, repr=False, compare=False)

    @classmethod
    def create(cls, *, scanner: str, rule: str, secret: str, location: Location, **kwargs: Any) -> Finding:
        return cls(
            scanner=scanner,
            rule=rule,
            location=location,
            secret_hash=hash_secret(secret),
            preview=mask_secret(secret),
            secret=secret,
            **kwargs,
        )

    def to_record(self) -> dict[str, Any]:
        record: dict[str, Any] = {}
        for f in fields(self):
            if f.name == "secret":
                continue
            value = getattr(self, f.name)
            if isinstance(value, Location):
                value = {lf.name: getattr(value, lf.name) for lf in fields(Location)}
            elif isinstance(value, enum.Enum):
                value = value.value
            elif isinstance(value, set):
                value = sorted(value)
            record[f.name] = value
        return record

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> Finding:
        data = dict(record)
        data["location"] = Location(**data["location"])
        data["verification"] = Verification(data.get("verification", "unknown"))
        data["severity"] = Severity(data.get("severity", "medium"))
        data["tags"] = set(data.get("tags", []))
        data.pop("secret", None)
        return cls(**data)


@dataclass
class RepoInfo:
    """Identity and metadata of the repository being scanned."""

    slug: str
    url: str | None = None
    visibility: str = "unknown"  # public | private | internal | local | unknown
    default_branch: str | None = None
    fork: bool | None = None
    archived: bool | None = None
    pushed_at: str | None = None
    size_kb: int | None = None

    @property
    def html_url(self) -> str | None:
        if self.url and self.url.startswith("https://github.com/"):
            return self.url.removesuffix(".git")
        return None


class RunStatus(str, enum.Enum):
    OK = "ok"
    EMPTY = "empty"
    PARTIAL = "partial"
    FAILED = "failed"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"


@dataclass
class ScannerRun:
    scanner: str
    version: str | None
    status: RunStatus
    duration_s: float
    findings: int = 0
    errors: list[str] = field(default_factory=list)


@dataclass
class RepoScanResult:
    repo: RepoInfo
    scope: str
    head: str | None
    started_at: str
    finished_at: str
    status: RunStatus
    config_fingerprint: str
    scanner_runs: list[ScannerRun] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def summary_record(self) -> dict[str, Any]:
        """Everything except the findings themselves (they go to JSONL)."""
        return {
            "repo": {f.name: getattr(self.repo, f.name) for f in fields(RepoInfo)},
            "scope": self.scope,
            "head": self.head,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "status": self.status.value,
            "config_fingerprint": self.config_fingerprint,
            "scanner_runs": [
                {
                    "scanner": r.scanner,
                    "version": r.version,
                    "status": r.status.value,
                    "duration_s": round(r.duration_s, 3),
                    "findings": r.findings,
                    "errors": r.errors,
                }
                for r in self.scanner_runs
            ],
            "errors": self.errors,
            "finding_count": len(self.findings),
        }

    @classmethod
    def from_summary_record(cls, record: dict[str, Any], findings: list[Finding] | None = None) -> RepoScanResult:
        runs = [
            ScannerRun(
                scanner=r["scanner"],
                version=r.get("version"),
                status=RunStatus(r["status"]),
                duration_s=r.get("duration_s", 0.0),
                findings=r.get("findings", 0),
                errors=r.get("errors", []),
            )
            for r in record.get("scanner_runs", [])
        ]
        return cls(
            repo=RepoInfo(**record["repo"]),
            scope=record["scope"],
            head=record.get("head"),
            started_at=record["started_at"],
            finished_at=record["finished_at"],
            status=RunStatus(record["status"]),
            config_fingerprint=record.get("config_fingerprint", ""),
            scanner_runs=runs,
            findings=findings or [],
            errors=record.get("errors", []),
        )
