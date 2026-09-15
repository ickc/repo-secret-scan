from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..dataset import Dataset
from ..models import RepoScanResult, Severity
from .base import ORG_REPORTERS, REPORTERS

ACTIONABLE = [Severity.CRITICAL.value, Severity.HIGH.value, Severity.MEDIUM.value]


def _cell(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ")


def _table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(_cell(c) for c in row) + " |" for row in rows]
    return lines


def _location(secret: dict[str, Any]) -> str:
    label = f"`{_cell(secret['location'])}`"
    if secret["path_count"] > 1:
        label += f" (+{secret['path_count'] - 1})"
    return f"[{label}]({secret['link']})" if secret["link"] else label


def render(dataset: Dataset, title: str, max_rows: int = 300) -> str:
    repos, secrets = dataset.repos, dataset.secrets
    open_secrets = [s for s in secrets if not s["suppressed"]]
    by_severity = Counter(s["severity"] for s in open_secrets)
    statuses = Counter(r["status"] for r in repos)
    in_head = sum(1 for s in open_secrets if s["in_head"])
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    out = [f"# {title}", "", f"Generated {now}. **Confidential** — this report locates live credentials; do not publish it.", ""]
    out += ["## Summary", ""]
    out += _table(
        ["Metric", "Value"],
        [
            ["Repositories scanned", len(repos)],
            ["Scan status", ", ".join(f"{k}: {v}" for k, v in sorted(statuses.items()))],
            ["Distinct open secrets", len(open_secrets)],
            ["…still present on default branch", in_head],
            ["…by severity", ", ".join(f"{s.value}: {by_severity.get(s.value, 0)}" for s in Severity)],
            ["Suppressed via ignore files", len(secrets) - len(open_secrets)],
            ["Scanner hits (all occurrences)", len(dataset.findings)],
        ],
    )

    agreement = Counter(s["scanners"] for s in open_secrets)
    if agreement:
        out += ["", "### Scanner agreement (distinct open secrets)", ""]
        out += _table(["Found by", "Secrets"], [[k.replace(";", " + "), v] for k, v in agreement.most_common()])

    actionable = [s for s in open_secrets if s["severity"] in ACTIONABLE]
    out += ["", f"## Action list ({len(actionable)} secrets rated medium or above)", ""]
    if actionable:
        out += [
            "Rotate or revoke each credential first — removing it from git does not undo the exposure. "
            "Then delete it from the code, and rewrite history if the repository is or will be public.",
            "",
        ]
        rows = [
            [
                s["severity"], s["repo"], s["rules"].replace(";", ", "), f"`{s['preview']}`",
                "yes" if s["in_head"] else "history", s["occurrences"], _location(s),
                s["severity_reasons"].replace(";", "; "), f"`{s['secret_hash']}`",
            ]
            for s in actionable[:max_rows]
        ]
        out += _table(["Severity", "Repo", "Detector", "Preview", "In HEAD", "Hits", "Where", "Why", "Hash"], rows)
        if len(actionable) > max_rows:
            out += ["", f"_{len(actionable) - max_rows} more rows in `data/secrets.csv`._"]
    else:
        out += ["Nothing rated medium or above."]

    low = [s for s in open_secrets if s["severity"] not in ACTIONABLE]
    if low:
        rules = Counter(r for s in low for r in s["rules"].split(";"))
        out += ["", f"## Low-confidence findings ({len(low)})", "", "Mostly generic patterns or test/doc/data files; see `data/secrets.csv`. Most common detectors:", ""]
        out += _table(["Detector", "Secrets"], [[k, v] for k, v in rules.most_common(15)])

    shared = [s for s in open_secrets if s["shared_with_repos"]]
    if shared:
        # Group by the set of repositories sharing secrets: usually copies or forks of one project.
        repos_by_hash: dict[str, set[str]] = {}
        worst: dict[str, int] = {}
        rank = {s.value: s.rank for s in Severity}
        for s in shared:
            repos_by_hash.setdefault(s["secret_hash"], set()).add(s["repo"])
            worst[s["secret_hash"]] = min(worst.get(s["secret_hash"], 99), rank[s["severity"]])
        clusters: dict[tuple[str, ...], list[str]] = {}
        for h, rs in repos_by_hash.items():
            clusters.setdefault(tuple(sorted(rs)), []).append(h)
        rows = [
            [", ".join(rs), len(hashes), list(Severity)[min(worst[h] for h in hashes)].value]
            for rs, hashes in sorted(clusters.items(), key=lambda kv: (min(worst[h] for h in kv[1]), -len(kv[1])))
        ]
        out += ["", "## Secrets reused across repositories", "", "Rotating one of these fixes every listed repository.", ""]
        out += _table(["Repositories", "Shared secrets", "Worst severity"], rows)

    problems = [r for r in repos if r["status"] not in ("ok", "empty")]
    if problems:
        out += ["", "## Scan problems", ""]
        out += _table(["Repo", "Status", "Scanners", "Errors"], [[r["repo"], r["status"], r["scanners"], r["errors"]] for r in problems])

    out += [
        "", "## Suppressing reviewed findings", "",
        "Add a `.secret-scan-ignore.toml` to the repository root (or a central file via `[processor.ignore-file] path`):", "",
        "```toml", "[[ignore]]", 'secret_hash = "<hash from this report>"', 'reason = "test fixture, not a real key"', "",
        "[[ignore]]", 'path = "tests/fixtures/*"', 'rule = "generic-api-key"', 'reason = "synthetic data"', "```", "",
    ]
    return "\n".join(out)


@REPORTERS.register("markdown")
@dataclass
class RepoMarkdownReporter:
    filename: str = "report.md"

    def write(self, result: RepoScanResult, out_dir: Path) -> None:
        dataset = Dataset.from_results([result])
        title = f"Secret scan: {result.repo.slug} ({result.scope})"
        (out_dir / self.filename).write_text(render(dataset, title))


@ORG_REPORTERS.register("markdown")
@dataclass
class OrgMarkdownReporter:
    filename: str = "report.md"
    max_rows: int = 300

    def write(self, dataset: Dataset, out_dir: Path, title: str) -> None:
        (out_dir / self.filename).write_text(render(dataset, title, self.max_rows))
