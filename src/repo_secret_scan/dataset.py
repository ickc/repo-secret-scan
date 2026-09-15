"""Tabular view of scan results: the CSV files every report is built from.

Three tables:

``repos.csv``     one row per repository scanned (status, counts, errors)
``secrets.csv``   one row per distinct secret per repository — the triage list
``findings.csv``  one row per individual scanner hit (commit/file/line)
"""

from __future__ import annotations

import csv
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Finding, RepoInfo, RepoScanResult, Severity, Verification

LIST_SEP = ";"

REPO_COLUMNS = [
    "repo", "visibility", "fork", "archived", "size_kb", "pushed_at", "status", "scope", "head",
    "finished_at", "scanners", "duration_s", "findings", "secrets", "open_secrets",
    "critical", "high", "medium", "low", "info", "errors",
]
SECRET_COLUMNS = [
    "severity", "repo", "visibility", "secret_hash", "preview", "rules", "scanners", "in_head",
    "suppressed", "suppression_reason", "verification", "occurrences", "commits", "location", "paths", "path_count",
    "first_seen", "last_seen", "authors", "tags", "severity_reasons", "shared_with_repos", "link",
]
FINDING_COLUMNS = [
    "severity", "repo", "visibility", "secret_hash", "scanner", "rule", "preview", "in_head", "suppressed",
    "verification", "path", "line", "commit", "commit_date", "author_email", "entropy", "tags", "context", "link",
]

_VERIFICATION_ORDER = [Verification.LIVE, Verification.ERROR, Verification.UNKNOWN, Verification.INVALID]


def blob_link(repo: RepoInfo, finding: Finding, fallback_ref: str | None) -> str:
    base = repo.html_url
    ref = finding.location.commit or fallback_ref
    if not base or not ref or not finding.location.path:
        return ""
    anchor = f"#L{finding.location.line}" if finding.location.line else ""
    return f"{base}/blob/{ref}/{finding.location.path}{anchor}"


def _join(values: Iterable[Any], limit: int | None = None) -> str:
    items = [str(v) for v in values if v not in (None, "")]
    if limit is not None and len(items) > limit:
        items = items[:limit] + [f"(+{len(items) - limit} more)"]
    return LIST_SEP.join(items)


@dataclass
class SecretGroup:
    """All findings of one secret within one repository."""

    repo: RepoInfo
    head: str | None
    findings: list[Finding] = field(default_factory=list)

    @property
    def lead(self) -> Finding:
        # Most severe, then still in HEAD; ties go to the newest occurrence.
        newest_first = sorted(self.findings, key=lambda f: f.location.commit_date or "", reverse=True)
        return min(newest_first, key=lambda f: (f.severity.rank, not f.in_head))

    def row(self, shared_with: int) -> dict[str, Any]:
        fs = self.findings
        lead = self.lead
        dates = sorted(d for f in fs if (d := f.location.commit_date))
        verification = min((f.verification for f in fs), key=_VERIFICATION_ORDER.index)
        return {
            "severity": lead.severity.value,
            "repo": self.repo.slug,
            "visibility": self.repo.visibility,
            "secret_hash": lead.secret_hash,
            "preview": lead.preview,
            "rules": _join(sorted({f"{f.scanner}:{f.rule}" for f in fs})),
            "scanners": _join(sorted({f.scanner for f in fs})),
            "in_head": any(f.in_head for f in fs),
            "suppressed": all(f.suppressed for f in fs),
            "suppression_reason": lead.suppression_reason,
            "verification": verification.value,
            "occurrences": len(fs),
            "commits": len({f.location.commit for f in fs if f.location.commit}),
            # The representative occurrence, matching ``link``.
            "location": f"{lead.location.path}:{lead.location.line}" if lead.location.line else lead.location.path,
            "paths": _join(sorted({f.location.path for f in fs}), limit=5),
            "path_count": len({f.location.path for f in fs}),
            "first_seen": dates[0] if dates else "",
            "last_seen": dates[-1] if dates else "",
            "authors": _join(sorted({f.location.author_email for f in fs if f.location.author_email}), limit=5),
            "tags": _join(sorted(set().union(*(f.tags for f in fs)))),
            "severity_reasons": _join(lead.extra.get("severity_reasons", [])),
            "shared_with_repos": shared_with,
            "link": blob_link(self.repo, lead, self.head),
        }


def group_secrets(result: RepoScanResult) -> list[SecretGroup]:
    groups: dict[str, SecretGroup] = {}
    for f in result.findings:
        groups.setdefault(f.secret_hash, SecretGroup(result.repo, result.head)).findings.append(f)
    return sorted(groups.values(), key=lambda g: (g.lead.severity.rank, g.repo.slug, g.lead.secret_hash))


def _repo_row(result: RepoScanResult, groups: list[SecretGroup]) -> dict[str, Any]:
    open_groups = [g for g in groups if not all(f.suppressed for f in g.findings)]
    severities = Counter(g.lead.severity.value for g in open_groups)
    r = result.repo
    return {
        "repo": r.slug, "visibility": r.visibility, "fork": r.fork, "archived": r.archived,
        "size_kb": r.size_kb, "pushed_at": r.pushed_at, "status": result.status.value, "scope": result.scope,
        "head": result.head, "finished_at": result.finished_at,
        "scanners": _join(f"{s.scanner}={s.status.value}" for s in result.scanner_runs),
        "duration_s": round(sum(s.duration_s for s in result.scanner_runs), 1),
        "findings": len(result.findings), "secrets": len(groups), "open_secrets": len(open_groups),
        **{s.value: severities.get(s.value, 0) for s in Severity},
        "errors": " ".join(_join([*result.errors, *(e for s in result.scanner_runs for e in s.errors)], limit=3).split())[:500],
    }


@dataclass
class Dataset:
    repos: list[dict[str, Any]]
    secrets: list[dict[str, Any]]
    findings: list[dict[str, Any]]

    @classmethod
    def from_results(cls, results: Iterable[RepoScanResult]) -> Dataset:
        results = sorted(results, key=lambda r: r.repo.slug.lower())
        per_repo = [(r, group_secrets(r)) for r in results]
        repos_by_hash: dict[str, set[str]] = defaultdict(set)
        for r, groups in per_repo:
            for g in groups:
                repos_by_hash[g.lead.secret_hash].add(r.repo.slug)

        repos, secrets, findings = [], [], []
        for r, groups in per_repo:
            repos.append(_repo_row(r, groups))
            for g in groups:
                secrets.append(g.row(len(repos_by_hash[g.lead.secret_hash]) - 1))
                for f in g.findings:
                    findings.append({
                        "severity": f.severity.value, "repo": r.repo.slug, "visibility": r.repo.visibility,
                        "secret_hash": f.secret_hash, "scanner": f.scanner, "rule": f.rule, "preview": f.preview,
                        "in_head": f.in_head, "suppressed": f.suppressed, "verification": f.verification.value,
                        "path": f.location.path, "line": f.location.line, "commit": f.location.commit,
                        "commit_date": f.location.commit_date, "author_email": f.location.author_email,
                        "entropy": f.entropy, "tags": _join(sorted(f.tags)), "context": f.context,
                        "link": blob_link(r.repo, f, r.head),
                    })
        rank = {s.value: s.rank for s in Severity}
        secrets.sort(key=lambda s: (s["suppressed"], rank[s["severity"]], not s["in_head"], s["repo"].lower()))
        return cls(repos=repos, secrets=secrets, findings=findings)

    def write_csv(self, data_dir: Path) -> None:
        data_dir.mkdir(parents=True, exist_ok=True)
        for name, columns, rows in self._tables():
            with (data_dir / f"{name}.csv").open("w", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(rows)

    @classmethod
    def from_csv(cls, data_dir: Path) -> Dataset:
        def read(name: str) -> list[dict[str, Any]]:
            with (data_dir / f"{name}.csv").open(newline="") as fh:
                return [_coerce(row) for row in csv.DictReader(fh)]

        return cls(repos=read("repos"), secrets=read("secrets"), findings=read("findings"))

    def _tables(self):
        return [
            ("repos", REPO_COLUMNS, self.repos),
            ("secrets", SECRET_COLUMNS, self.secrets),
            ("findings", FINDING_COLUMNS, self.findings),
        ]


_INT_COLUMNS = {
    "size_kb", "findings", "secrets", "open_secrets", "critical", "high", "medium", "low", "info",
    "occurrences", "commits", "path_count", "shared_with_repos", "line",
}


def _coerce(row: dict[str, str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in row.items():
        if value in ("True", "False"):
            out[key] = value == "True"
        elif key in _INT_COLUMNS and value not in ("", None):
            out[key] = int(value)
        elif key == "duration_s" and value:
            out[key] = float(value)
        else:
            out[key] = value
    return out
