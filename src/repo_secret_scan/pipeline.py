"""Single-repository pipeline: source -> scanners -> processors -> reporters."""

from __future__ import annotations

import json
import logging
import shutil
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from ._proc import is_transient
from .config import Config
from .models import Finding, RepoScanResult, RunStatus, ScannerRun
from .processors import PROCESSORS, ProcessContext
from .reporters import REPORTERS
from .scanners import SCANNERS, Scanner, ScanTimeoutError
from .sources import Checkout, Scope, Source

log = logging.getLogger(__name__)

RESULT_FILE = "result.json"
FINDINGS_FILE = "findings.jsonl"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def private_dir(path: Path) -> Path:
    """Create a directory (and missing parents) readable only by the current user.

    Existing directories are left alone.
    """
    missing = []
    probe = path
    while not probe.exists():
        missing.append(probe)
        probe = probe.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700, exist_ok=True)
        directory.chmod(0o700)  # mkdir's mode is filtered by the umask
    return path


def build_scanners(config: Config) -> list[Scanner]:
    return [SCANNERS.create(n, config.component_options("scanner", n)) for n in config.scanners]


def scanner_versions(scanners: list[Scanner]) -> dict[str, str | None]:
    return {s.name: s.version() for s in scanners}


def _run_scanner_once(scanner: Scanner, version: str | None, checkout: Checkout, scope: Scope, tmpdir: Path) -> tuple[ScannerRun, list[Finding]]:
    start = time.monotonic()
    try:
        output = scanner.scan(checkout, scope, tmpdir)
    except ScanTimeoutError as exc:
        return ScannerRun(scanner.name, version, RunStatus.TIMEOUT, time.monotonic() - start, errors=[str(exc)]), []
    except Exception as exc:  # noqa: BLE001 - one scanner failing must not sink the others
        return ScannerRun(scanner.name, version, RunStatus.FAILED, time.monotonic() - start, errors=[str(exc)]), []
    # Tool log errors on individual blobs (e.g. undecodable chunks) are kept as
    # warnings; only resource failures mean content may have been skipped.
    status = RunStatus.PARTIAL if has_transient_errors(output.warnings) else RunStatus.OK
    run = ScannerRun(scanner.name, version, status, time.monotonic() - start, len(output.findings), output.warnings[:50])
    return run, output.findings


def has_transient_errors(errors: list[str]) -> bool:
    return any(is_transient(e) for e in errors)


def _run_scanner(
    scanner: Scanner, version: str | None, checkout: Checkout, scope: Scope, tmpdir: Path, retries: int, retry_delay: float
) -> tuple[ScannerRun, list[Finding]]:
    for attempt in range(retries + 1):
        run, findings = _run_scanner_once(scanner, version, checkout, scope, tmpdir)
        if run.status in (RunStatus.OK, RunStatus.TIMEOUT) or not has_transient_errors(run.errors) or attempt == retries:
            break
        log.info("%s on %s hit a transient error, retrying: %s", scanner.name, checkout.repo.slug, run.errors[0][:200])
        time.sleep(retry_delay * (attempt + 1))
    if run.status is RunStatus.FAILED:
        log.warning("%s failed on %s: %s", scanner.name, checkout.repo.slug, run.errors[0][:300])
    return run, findings


def _overall_status(runs: list[ScannerRun]) -> RunStatus:
    statuses = {r.status for r in runs}
    if not runs or statuses == {RunStatus.OK}:
        return RunStatus.OK
    if statuses <= {RunStatus.FAILED, RunStatus.TIMEOUT}:
        return RunStatus.FAILED
    return RunStatus.PARTIAL


def scan_repo(
    source: Source,
    scope: Scope,
    config: Config,
    *,
    workdir: Path,
    out_dir: Path,
    scanners: list[Scanner] | None = None,
    versions: dict[str, str | None] | None = None,
) -> RepoScanResult:
    started = _now()
    private_dir(workdir)
    scanners = scanners if scanners is not None else build_scanners(config)
    versions = versions if versions is not None else scanner_versions(scanners)
    fingerprint = result_fingerprint(config, versions)

    def finish(status: RunStatus, head: str | None, runs=(), findings=(), errors=()) -> RepoScanResult:
        result = RepoScanResult(
            repo=source.repo, scope=scope.describe(), head=head, started_at=started, finished_at=_now(),
            status=status, config_fingerprint=fingerprint, scanner_runs=list(runs),
            findings=list(findings), errors=list(errors),
        )
        write_result(result, out_dir, config)
        return result

    for attempt in range(config.retries + 1):
        try:
            checkout = source.materialize(workdir)
            break
        except Exception as exc:  # noqa: BLE001
            if attempt == config.retries or not is_transient(str(exc)):
                log.warning("could not fetch %s: %s", source.repo.slug, exc)
                return finish(RunStatus.FAILED, None, errors=[f"materialize: {exc}"])
            time.sleep(config.retry_delay * (attempt + 1))

    if checkout.git_dir is not None and not checkout.has_commits:
        return finish(RunStatus.EMPTY, None)

    tmpdir = private_dir(workdir / "tmp" / source.repo.slug.replace("/", "__"))
    try:
        with ThreadPoolExecutor(max_workers=max(1, len(scanners))) as pool:
            outcomes = list(pool.map(
                lambda s: _run_scanner(s, versions.get(s.name), checkout, scope, tmpdir, config.retries, config.retry_delay),
                scanners,
            ))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    runs = [run for run, _ in outcomes]
    findings = [f for _, fs in outcomes for f in fs]

    findings, errors = _apply_processors(findings, ProcessContext(checkout=checkout, scope=scope), config)
    for f in findings:
        f.secret = None  # drop plaintext as soon as processing is done
    status = _overall_status(runs)
    if errors and status is RunStatus.OK:
        status = RunStatus.PARTIAL
    return finish(status, checkout.head, runs, findings, errors)


def _apply_processors(
    findings: list[Finding], ctx: ProcessContext, config: Config, *, offline_only: bool = False
) -> tuple[list[Finding], list[str]]:
    errors: list[str] = []
    for name in config.processors:
        processor = PROCESSORS.create(name, config.component_options("processor", name))
        if offline_only and not processor.offline:
            continue
        try:
            findings = processor.process(findings, ctx)
        except Exception as exc:  # noqa: BLE001
            log.warning("processor %s failed on %s: %s", name, ctx.checkout.repo.slug, exc)
            errors.append(f"processor {name}: {exc}")
    findings.sort(key=lambda f: (f.severity.rank, f.secret_hash, f.location.path, f.location.line or 0))
    return findings, errors


def offline_processors(config: Config) -> frozenset[str]:
    return frozenset(
        n for n in config.processors if PROCESSORS.create(n, config.component_options("processor", n)).offline
    )


def result_fingerprint(config: Config, versions: dict[str, str | None]) -> str:
    return f"{config.fingerprint(offline_processors(config))}:{json.dumps(versions, sort_keys=True)}"


def reprocess(result: RepoScanResult, config: Config) -> RepoScanResult:
    """Re-apply offline processors (tags, triage, …) to stored findings.

    Facts that needed the repository or the plaintext secret (``in_head``,
    suppression) are kept from the original scan.
    """
    for f in result.findings:
        f.tags.clear()
    ctx = ProcessContext(checkout=Checkout(result.repo, None, None, result.head), scope=None)
    result.findings, _ = _apply_processors(result.findings, ctx, config, offline_only=True)
    return result


def write_result(result: RepoScanResult, out_dir: Path, config: Config) -> None:
    private_dir(out_dir)
    # Canonical machine-readable output; every other format is derived from it.
    with (out_dir / FINDINGS_FILE).open("w") as fh:
        for f in result.findings:
            fh.write(json.dumps(f.to_record(), sort_keys=True) + "\n")
    for name in config.reporters:
        REPORTERS.create(name, config.component_options("reporter", name)).write(result, out_dir)
    # Written last: its presence marks a complete result for caching.
    (out_dir / RESULT_FILE).write_text(json.dumps(result.summary_record(), indent=2) + "\n")


def load_result(out_dir: Path) -> RepoScanResult | None:
    summary = out_dir / RESULT_FILE
    if not summary.is_file():
        return None
    record = json.loads(summary.read_text())
    findings_path = out_dir / FINDINGS_FILE
    findings = []
    if findings_path.is_file():
        findings = [Finding.from_record(json.loads(line)) for line in findings_path.read_text().splitlines() if line]
    return RepoScanResult.from_summary_record(record, findings)
