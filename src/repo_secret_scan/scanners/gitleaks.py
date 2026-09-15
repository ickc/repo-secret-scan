from __future__ import annotations

import json
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .._proc import CommandError
from ..models import Finding, Location, mask_in_text
from ..sources import Checkout, CommitRange, FullHistory, Scope, WorkingTree
from ..tools import GITLEAKS
from .base import SCANNERS, ExternalToolScanner, ScanOutput, UnsupportedScopeError

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def parse_report(records: list[dict[str, Any]], scanner: str = "gitleaks", root: Path | None = None) -> list[Finding]:
    findings = []
    prefix = f"{root}/" if root else None
    for rec in records:
        secret = rec.get("Secret") or rec.get("Match") or ""
        if not secret.strip():
            continue
        findings.append(
            Finding.create(
                scanner=scanner,
                rule=rec.get("RuleID", "unknown"),
                secret=secret,
                description=rec.get("Description", ""),
                context=mask_in_text(rec.get("Match", ""), secret),
                entropy=rec.get("Entropy"),
                location=Location(
                    path=_relative(rec.get("File", ""), prefix),
                    line=rec.get("StartLine"),
                    commit=rec.get("Commit") or None,
                    commit_date=rec.get("Date") or None,
                    author_email=rec.get("Email") or None,
                ),
                extra={"native_fingerprint": rec.get("Fingerprint"), "native_tags": rec.get("Tags") or []},
            )
        )
    return findings


def _relative(path: str, prefix: str | None) -> str:
    return path.removeprefix(prefix) if prefix else path


@SCANNERS.register("gitleaks")
@dataclass
class GitleaksScanner(ExternalToolScanner):
    tool = GITLEAKS
    name = "gitleaks"

    config: str | None = None
    max_target_megabytes: int | None = None

    def version_args(self) -> list[str]:
        return ["version"]

    def _args(self, checkout: Checkout, scope: Scope) -> tuple[list[str], Path | None]:
        if isinstance(scope, WorkingTree):
            if checkout.worktree is None:
                raise UnsupportedScopeError("gitleaks: working-tree scope needs a checked-out worktree")
            return ["dir", str(checkout.worktree)], checkout.worktree
        if checkout.git_dir is None:
            raise UnsupportedScopeError("gitleaks: history scopes need a git repository")
        args = ["git", str(checkout.worktree or checkout.git_dir)]
        if isinstance(scope, CommitRange):
            args += ["--log-opts", f"{scope.base}..{scope.head}"]
        elif not isinstance(scope, FullHistory):
            raise UnsupportedScopeError(f"gitleaks: unsupported scope {scope!r}")
        return args, None

    def scan(self, checkout: Checkout, scope: Scope, tmpdir: Path) -> ScanOutput:
        args, root = self._args(checkout, scope)
        common = ["--report-format", "json", "--no-banner", "--no-color", "--exit-code", "0", "--log-level", "error"]
        if self.config:
            common += ["--config", self.config]
        if self.max_target_megabytes:
            common += ["--max-target-megabytes", str(self.max_target_megabytes)]
        # The raw report contains plaintext secrets: keep it private and short-lived.
        with tempfile.TemporaryDirectory(dir=tmpdir, prefix="gitleaks-") as private:
            report = Path(private) / "report.json"
            stdout, stderr, code = self._run([*args, *common, "--report-path", str(report)])
            if code != 0:
                raise CommandError([self.name, *args], code, stderr or stdout)
            records = json.loads(report.read_text() or "[]") if report.exists() else []
        warnings = [_ANSI_RE.sub("", line) for line in stderr.splitlines() if line.strip()]
        return ScanOutput(findings=parse_report(records, self.name, root), warnings=warnings)
