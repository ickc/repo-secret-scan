from __future__ import annotations

import logging
import os
import sys
from enum import Enum
from pathlib import Path
from typing import Annotated, Optional

import typer

from . import tools as tools_mod
from .config import load_config
from .dataset import Dataset
from .models import Severity
from .org import load_results, scan_owner, write_org_reports
from .pipeline import is_shared, lock_down, reprocess, scan_repo
from .reporters import REPORTERS
from .sources import CommitRange, FullHistory, WorkingTree, resolve_target

app = typer.Typer(no_args_is_help=True, help="Find leaked secrets in a git repository or a whole GitHub organisation.")
tools_app = typer.Typer(no_args_is_help=True, help="Manage the pinned scanner binaries.")
app.add_typer(tools_app, name="tools")

ConfigOpt = Annotated[Optional[Path], typer.Option("--config", "-c", help="TOML configuration file.", exists=True, dir_okay=False)]


class ScopeChoice(str, Enum):
    history = "history"
    range = "range"
    tree = "tree"


class VisibilityChoice(str, Enum):
    public = "public"
    private = "private"
    internal = "internal"


def _err(message: str) -> None:
    typer.echo(message, err=True)


@app.callback()
def main(verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False) -> None:
    # Everything this tool writes (clones, results, reports) is sensitive.
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO if verbose else logging.WARNING, format="%(levelname)s %(name)s: %(message)s")


@app.command()
def scan(
    target: Annotated[str, typer.Argument(help="Local directory, OWNER/REPO, or GitHub URL.")],
    out: Annotated[Path, typer.Option("--out", "-o", help="Directory for this repository's results.")] = Path("secret-scan-results"),
    workdir: Annotated[Optional[Path], typer.Option(help="Where clones and scanner temp files go (default: <out>/.work).")] = None,
    scope: Annotated[ScopeChoice, typer.Option(help="history: all commits; range: --base..--head; tree: files on disk.")] = ScopeChoice.history,
    base: Annotated[Optional[str], typer.Option(help="Base commit for --scope range.")] = None,
    head: Annotated[str, typer.Option(help="Head commit for --scope range.")] = "HEAD",
    scanner: Annotated[Optional[list[str]], typer.Option("--scanner", "-s", help="Override configured scanners.")] = None,
    fail_on: Annotated[Optional[Severity], typer.Option(help="Exit 1 if an unsuppressed finding is at least this severe.")] = None,
    report_format: Annotated[Optional[list[str]], typer.Option("--format", "-f", help="Add a report format, e.g. github-annotations (repeatable).")] = None,
    visibility: Annotated[Optional[VisibilityChoice], typer.Option(help="Repository visibility used by triage (public raises severity). Auto-detected inside GitHub Actions.")] = None,
    config_path: ConfigOpt = None,
) -> None:
    """Scan one repository."""
    config = load_config(config_path)
    if scanner:
        config.scanners = scanner
    for name in report_format or []:
        if name not in REPORTERS:
            raise typer.BadParameter(f"unknown format {name!r}; available: {', '.join(REPORTERS.names())}")
        if name not in config.reporters:
            config.reporters.append(name)
    if scope is ScopeChoice.range:
        if not base:
            raise typer.BadParameter("--scope range needs --base")
        scope_obj = CommitRange(base=base, head=head)
    else:
        scope_obj = WorkingTree() if scope is ScopeChoice.tree else FullHistory()

    source = resolve_target(target)
    if visibility is not None:
        source.repo.visibility = visibility.value
    if out.is_dir() and is_shared(out):
        # --out may be any existing directory (even "."), so warn rather than chmod it.
        _err(f"warning: {out} is accessible to other users; scan results locate credentials (chmod 700 it)")
    result = scan_repo(source, scope_obj, config, workdir=workdir or out / ".work", out_dir=out)
    open_findings = [f for f in result.findings if not f.suppressed]
    typer.echo(f"{result.repo.slug}: {result.status.value}, {len(result.findings)} findings ({len(open_findings)} unsuppressed) -> {out}")
    for run in result.scanner_runs:
        typer.echo(f"  {run.scanner} {run.version}: {run.status.value}, {run.findings} findings, {run.duration_s:.1f}s")
        for error in run.errors[:5]:
            typer.echo(f"    ! {error}")
    if result.status.value == "failed":
        raise typer.Exit(2)
    if fail_on is not None and any(f.severity in Severity.at_least(fail_on) for f in open_findings):
        raise typer.Exit(1)


@app.command()
def org(
    owner: Annotated[str, typer.Argument(help="GitHub organisation or user.")],
    scratch: Annotated[Path, typer.Option("--scratch", help="Scratch directory for clones, results and reports.")],
    config_path: ConfigOpt = None,
    jobs: Annotated[Optional[int], typer.Option("--jobs", "-j", help="Repositories scanned in parallel.")] = None,
    forks: Annotated[Optional[bool], typer.Option("--forks/--no-forks", help="Include forks.")] = None,
    archived: Annotated[Optional[bool], typer.Option("--archived/--no-archived", help="Include archived repositories.")] = None,
    visibility: Annotated[Optional[str], typer.Option(help="all, public, private or internal.")] = None,
    include: Annotated[Optional[list[str]], typer.Option("--include", help="Repository name glob to include (repeatable).")] = None,
    exclude: Annotated[Optional[list[str]], typer.Option("--exclude", help="Repository name glob to exclude (repeatable).")] = None,
    limit: Annotated[Optional[int], typer.Option(help="Only scan the first N selected repositories.")] = None,
    force: Annotated[bool, typer.Option(help="Rescan even when cached results are up to date.")] = False,
) -> None:
    """Scan every repository of a GitHub organisation or user."""
    config = load_config(config_path)
    overrides = {"jobs": jobs, "include_forks": forks, "include_archived": archived, "visibility": visibility, "include": include, "exclude": exclude}
    for key, value in overrides.items():
        if value is not None:
            setattr(config.org, key, value)
    _, report_dir = scan_owner(owner, scratch, config, force=force, limit=limit, on_progress=lambda m: typer.echo(m, err=True))
    typer.echo(f"reports written to {report_dir}")


@app.command()
def report(
    source: Annotated[Path, typer.Argument(help="An org scratch dir (with results/) or a report data/ dir of CSVs.", exists=True, file_okay=False)],
    out: Annotated[Optional[Path], typer.Option("--out", "-o", help="Report directory (default: <scratch>/report).")] = None,
    title: Annotated[str, typer.Option(help="Report title.")] = "Secret scan",
    config_path: ConfigOpt = None,
) -> None:
    """Rebuild reports from saved results or CSV data without rescanning."""
    config = load_config(config_path)
    if (source / "results").is_dir():
        if lock_down(source):
            _err(f"{source} was accessible to other users; restricted it to owner only")
        dataset = Dataset.from_results(reprocess(r, config) for r in load_results(source / "results"))
        out = out or source / "report"
    elif (source / "secrets.csv").is_file():
        dataset = Dataset.from_csv(source)
        config.report_formats = [f for f in config.report_formats if f != "csv"]
        out = out or source.parent
    else:
        _err(f"{source} contains neither results/ nor secrets.csv")
        raise typer.Exit(2)
    write_org_reports(dataset, out, config, title=title, on_progress=_err)
    typer.echo(f"reports written to {out}")


@tools_app.command("install")
def tools_install() -> None:
    """Download and verify the pinned scanner releases into the tool cache."""
    for spec in tools_mod.TOOLS.values():
        path = tools_mod.install_tool(spec)
        typer.echo(f"{spec.name} {spec.version}: {path}")


@tools_app.command("list")
def tools_list() -> None:
    """Show which binary each scanner would use."""
    failed = False
    for spec in tools_mod.TOOLS.values():
        try:
            typer.echo(f"{spec.name} (pinned {spec.version}): {tools_mod.resolve(spec, install=False)}")
        except tools_mod.ToolUnavailableError as exc:
            failed = True
            typer.echo(f"{spec.name} (pinned {spec.version}): {exc}")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    app()
