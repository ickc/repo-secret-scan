"""GitHub Actions workflow-command annotations.

Lines such as ``::error file=app/config.py,line=12,title=…::…`` printed by a
workflow step become annotations on the run and, for files in the diff, on the
pull request's "Files changed" view. Unlike SARIF upload this needs no GitHub
Code Security licence, so it also works for private repositories.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

from ..models import Finding, RepoScanResult, Severity
from .base import REPORTERS

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "notice",
    Severity.INFO: "notice",
}


def _escape_data(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(value: str) -> str:
    return _escape_data(value).replace(":", "%3A").replace(",", "%2C")


def _message(f: Finding) -> str:
    where = "still present on the default branch" if f.in_head else "in git history"
    if f.in_head is None:
        where = "location in scanned content"
    commit = f" (commit {f.location.commit[:12]})" if f.location.commit else ""
    found_by = ", ".join(f.extra.get("found_by", [f.scanner]))
    return (
        f"{f.severity.value}: possible {f.rule} secret `{f.preview}` {where}{commit}. "
        f"Found by {found_by}. Rotate it, then remove it. secret_hash={f.secret_hash}"
    )


def annotation_lines(result: RepoScanResult, min_severity: Severity, max_annotations: int) -> list[str]:
    """One annotation per secret per file, most severe first, capped."""
    wanted = Severity.at_least(min_severity)
    seen: set[tuple[str, str]] = set()
    lines = []
    candidates = sorted(
        (f for f in result.findings if not f.suppressed and f.severity in wanted),
        key=lambda f: (f.severity.rank, not f.in_head, f.location.path, f.location.line or 0),
    )
    for f in candidates:
        key = (f.secret_hash, f.location.path)
        if key in seen:
            continue
        seen.add(key)
        props = [f"file={_escape_property(f.location.path)}"]
        if f.location.line:
            props.append(f"line={f.location.line}")
        props.append(f"title={_escape_property(f'Possible secret: {f.rule}')}")
        lines.append(f"::{_LEVEL[f.severity]} {','.join(props)}::{_escape_data(_message(f))}")
    if len(lines) > max_annotations:
        # GitHub displays only a limited number of annotations per step; say what was cut.
        hidden = len(lines) - (max_annotations - 1)
        lines = lines[: max_annotations - 1] + [
            f"::warning title=More secret-scan findings::{hidden} more findings not annotated; see the job summary or report."
        ]
    return lines


@REPORTERS.register("github-annotations")
@dataclass
class GitHubAnnotationsReporter:
    """Write annotations to a file and, inside GitHub Actions, print them.

    ``emit``: ``"auto"`` prints only when ``GITHUB_ACTIONS=true``; ``"always"``
    or ``"never"`` force it.
    """

    filename: str = "annotations.txt"
    min_severity: str = "medium"
    max_annotations: int = 50
    emit: str = "auto"

    def write(self, result: RepoScanResult, out_dir: Path) -> None:
        lines = annotation_lines(result, Severity(self.min_severity), self.max_annotations)
        (out_dir / self.filename).write_text("".join(f"{line}\n" for line in lines))
        in_actions = os.environ.get("GITHUB_ACTIONS") == "true"
        if self.emit == "always" or (self.emit == "auto" and in_actions):
            for line in lines:
                print(line, file=sys.stdout)
            sys.stdout.flush()
