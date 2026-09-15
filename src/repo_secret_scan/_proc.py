"""Small subprocess helpers shared by sources, scanners and processors."""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

# Failures caused by a busy host rather than by the repository; worth retrying.
TRANSIENT_ERROR_RE = re.compile(
    r"resource temporarily unavailable|cannot fork|unable to fork|unable to create thread|"
    r"failed to create new os thread|can't start new thread|errno 11\b|cannot create async thread",
    re.IGNORECASE,
)
# Lines that explain a crash, as opposed to the goroutine dump that follows them.
_HEADLINE_RE = re.compile(r"^\s*(fatal error|panic|runtime: |fatal:|error:|\S*\s*(FTL|ERR)\b)", re.IGNORECASE)


def is_transient(message: str) -> bool:
    return bool(TRANSIENT_ERROR_RE.search(message))


def summarise_stderr(stderr: str, limit: int = 3) -> str:
    lines = [line.strip() for line in stderr.strip().splitlines() if line.strip()]
    headlines = [line for line in lines if _HEADLINE_RE.match(line)]
    return " | ".join((headlines or lines[-limit:])[:limit])


class CommandError(RuntimeError):
    def __init__(self, args: Sequence[str], returncode: int, stderr: str) -> None:
        self.returncode = returncode
        self.stderr = stderr
        super().__init__(f"{' '.join(map(str, args[:3]))} … exited {returncode}: {summarise_stderr(stderr)}")


@dataclass
class Completed:
    returncode: int
    stdout: str
    stderr: str


def run(
    args: Sequence[str | os.PathLike[str]],
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    input: str | None = None,
    timeout: float | None = None,
    check: bool = True,
) -> Completed:
    """Run a command, capturing text output. Raises ``subprocess.TimeoutExpired``."""
    merged_env = {**os.environ, **env} if env else None
    proc = subprocess.run(
        [str(a) for a in args],
        cwd=cwd,
        env=merged_env,
        input=input,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout,
        # Scanners must never block waiting on a terminal prompt.
        stdin=None if input is not None else subprocess.DEVNULL,
    )
    if check and proc.returncode != 0:
        raise CommandError([str(a) for a in args], proc.returncode, proc.stderr)
    return Completed(proc.returncode, proc.stdout, proc.stderr)


def git(*args: str | os.PathLike[str], git_dir: Path | None = None, **kwargs) -> Completed:
    prefix: list[str | os.PathLike[str]] = ["git"]
    if git_dir is not None:
        prefix += ["--git-dir", git_dir]
    env = {"GIT_TERMINAL_PROMPT": "0", **kwargs.pop("env", {})}
    return run([*prefix, *args], env=env, **kwargs)
