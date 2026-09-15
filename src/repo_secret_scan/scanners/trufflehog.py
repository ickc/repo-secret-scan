from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .._proc import CommandError
from ..models import Finding, Location, Verification
from ..sources import Checkout, CommitRange, FullHistory, Scope, WorkingTree
from ..tools import TRUFFLEHOG
from .base import SCANNERS, ExternalToolScanner, ScanOutput, UnsupportedScopeError


def _iso(timestamp: str | None) -> str | None:
    if not timestamp:
        return None
    try:
        return datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S %z").isoformat()
    except ValueError:
        return timestamp


def _short(value: Any, limit: int = 200) -> Any:
    if isinstance(value, str) and len(value) > limit:
        return value[: limit - 1] + "…"
    return value


def parse_line(record: dict[str, Any], *, scanner: str, verify: bool, root: Path | None) -> Finding | None:
    secret = record.get("Raw") or record.get("RawV2") or ""
    if not secret.strip():
        return None
    data = (record.get("SourceMetadata") or {}).get("Data") or {}
    meta = data.get("Git") or data.get("Filesystem") or next(iter(data.values()), {}) or {}
    path = meta.get("file", "")
    if root is not None:
        path = path.removeprefix(f"{root}/")
    email = meta.get("email") or ""
    if "<" in email and email.endswith(">"):
        email = email.rsplit("<", 1)[1][:-1]

    if record.get("Verified"):
        verification = Verification.LIVE
    elif record.get("VerificationError"):
        verification = Verification.ERROR
    elif verify:
        verification = Verification.INVALID
    else:
        verification = Verification.UNKNOWN

    extra = {
        "detector_type": record.get("DetectorType"),
        "decoder": record.get("DecoderName"),
        **{f"detector_{k}": _short(v) for k, v in (record.get("ExtraData") or {}).items()},
    }
    if record.get("VerificationError"):
        extra["verification_error"] = _short(record["VerificationError"])
    return Finding.create(
        scanner=scanner,
        rule=record.get("DetectorName", "unknown"),
        secret=secret,
        description=record.get("DetectorDescription", ""),
        verification=verification,
        location=Location(
            path=path,
            line=meta.get("line"),
            commit=meta.get("commit") or None,
            commit_date=_iso(meta.get("timestamp")),
            author_email=email or None,
        ),
        extra=extra,
    )


def parse_output(stdout: str, *, scanner: str = "trufflehog", verify: bool = False, root: Path | None = None) -> list[Finding]:
    findings = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        finding = parse_line(json.loads(line), scanner=scanner, verify=verify, root=root)
        if finding is not None:
            findings.append(finding)
    return findings


def parse_log_errors(stderr: str) -> list[str]:
    errors = []
    for line in stderr.splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            if line.strip():
                errors.append(line.strip())
            continue
        if entry.get("level") in {"error", "fatal", "panic"}:
            detail = entry.get("error") or ""
            errors.append(f"{entry.get('msg', '')}: {detail}".strip(": "))
    return errors


@SCANNERS.register("trufflehog")
@dataclass
class TrufflehogScanner(ExternalToolScanner):
    tool = TRUFFLEHOG
    name = "trufflehog"

    # Verification sends candidate secrets to third-party APIs; opt in explicitly.
    verify: bool = False
    concurrency: int | None = None

    def _args(self, checkout: Checkout, scope: Scope) -> tuple[list[str], Path | None]:
        if isinstance(scope, WorkingTree):
            if checkout.worktree is None:
                raise UnsupportedScopeError("trufflehog: working-tree scope needs a checked-out worktree")
            return ["filesystem", str(checkout.worktree)], checkout.worktree
        if checkout.git_dir is None:
            raise UnsupportedScopeError("trufflehog: history scopes need a git repository")
        if checkout.is_bare:
            args = ["git", f"file://{checkout.git_dir}", "--bare"]
        else:
            args = ["git", f"file://{checkout.worktree}"]
        if isinstance(scope, CommitRange):
            args += ["--since-commit", scope.base, "--branch", scope.head]
        elif not isinstance(scope, FullHistory):
            raise UnsupportedScopeError(f"trufflehog: unsupported scope {scope!r}")
        return args, None

    def scan(self, checkout: Checkout, scope: Scope, tmpdir: Path) -> ScanOutput:
        args, root = self._args(checkout, scope)
        args += ["--json", "--no-update", "--no-color"]
        if root is not None:
            # filesystem mode would otherwise decode every object under .git/.
            excludes = tmpdir / "trufflehog-exclude.txt"
            excludes.write_text(r"(^|/)\.git/" + "\n")
            args += ["--exclude-paths", str(excludes)]
        if not self.verify:
            args.append("--no-verification")
        if self.concurrency:
            args += ["--concurrency", str(self.concurrency)]
        # trufflehog copies repositories into TMPDIR; keep that inside the workdir.
        stdout, stderr, code = self._run(args, env={"TMPDIR": str(tmpdir)})
        errors = parse_log_errors(stderr)
        if code != 0:
            raise CommandError([self.name, *args], code, "\n".join(errors) or stderr)
        return ScanOutput(
            findings=parse_output(stdout, scanner=self.name, verify=self.verify, root=root),
            warnings=errors,
        )
