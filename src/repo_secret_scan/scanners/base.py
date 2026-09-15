from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar, Protocol

from .._proc import run
from ..models import Finding
from ..registry import Registry
from ..sources import Checkout, Scope
from ..tools import ToolSpec, resolve


class UnsupportedScopeError(ValueError):
    pass


class ScanTimeoutError(RuntimeError):
    pass


@dataclass
class ScanOutput:
    findings: list[Finding]
    # Non-fatal problems reported by the tool (e.g. an unreadable blob).
    warnings: list[str] = field(default_factory=list)


class Scanner(Protocol):
    name: str

    def version(self) -> str | None: ...

    def scan(self, checkout: Checkout, scope: Scope, tmpdir: Path) -> ScanOutput: ...


SCANNERS: Registry[Scanner] = Registry("scanner")


@dataclass
class ExternalToolScanner:
    """Base for scanners that shell out to a pinned third-party binary."""

    tool: ClassVar[ToolSpec]
    name: ClassVar[str]

    timeout: float = 3600.0
    extra_args: list[str] = field(default_factory=list)
    install: bool = True
    # Both tools are Go programs that otherwise size their thread pools to every
    # CPU; on many-core shared hosts parallel scans then exhaust the user's
    # process limit ("fork/exec: resource temporarily unavailable").
    max_procs: int | None = 4

    def binary(self) -> Path:
        return resolve(self.tool, install=self.install)

    def version(self) -> str | None:
        try:
            out = run([self.binary(), *self.version_args()], check=False, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            return None
        text = (out.stdout or out.stderr).strip()
        return text.split()[-1] if text else None

    def version_args(self) -> list[str]:
        return ["--version"]

    def _run(self, args: list[str], *, env: dict[str, str] | None = None) -> tuple[str, str, int]:
        env = dict(env or {})
        if self.max_procs:
            env.setdefault("GOMAXPROCS", str(self.max_procs))
        try:
            out = run([self.binary(), *args, *self.extra_args], env=env, timeout=self.timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise ScanTimeoutError(f"{self.name} exceeded {self.timeout:.0f}s") from exc
        return out.stdout, out.stderr, out.returncode
