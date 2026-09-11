from __future__ import annotations

import json
import shutil
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from sureshot.domain.enums import Coverage, Domain, StepStatus
from sureshot.domain.scan import ScanProvenance, ScanState, StepResult
from sureshot.engine.context.snippet import extract_snippets
from sureshot.engine.ingest.profiler import EXCLUDED_DIRS, profile_repository
from sureshot.engine.ingest.unpack import unpack
from sureshot.engine.ingest.workdir import Workdir
from sureshot.engine.normalize.fingerprint import apply_fingerprints
from sureshot.engine.scanners.base import ScanRequest, ScannerUnavailable
from sureshot.engine.scanners.semgrep.scanner import SemgrepScanner

app = typer.Typer(add_completion=False)
console = Console()

_COLOR = {"critical": "bold red", "high": "red", "medium": "yellow",
          "low": "cyan", "info": "dim"}


def _stage(source: Path, dest: Path) -> None:
    if source.is_dir():
        shutil.copytree(source, dest, dirs_exist_ok=True, symlinks=False,
                        ignore=shutil.ignore_patterns(*EXCLUDED_DIRS))
    else:
        unpack(source, dest)


@app.command()
def scan(
    target: Path = typer.Argument(..., exists=True),
    json_out: Path | None = typer.Option(None, "--json", help="write findings to a file"),
    timeout: int = typer.Option(900, "--timeout"),
    keep: bool = typer.Option(False, "--keep", help="preserve the workdir"),
) -> None:
    scan_id = uuid.uuid4().hex[:12]
    state = ScanState(
        scan_id=scan_id, org_id="local", project_id=target.name,
        workdir="", started_at=datetime.now(UTC),
        provenance=ScanProvenance(engine_version="0.1.0"),
    )

    with Workdir(scan_id=scan_id, base=Path(tempfile.gettempdir()), keep=keep) as wd:
        with console.status("staging repository"):
            _stage(target.resolve(), wd.source)

        profile = profile_repository(wd.source)
        state = state.record(StepResult(step="profile", status=StepStatus.OK, duration_ms=0))

        console.print(
            f"[dim]{profile.scanned_files} files · "
            f"{profile.primary_language or 'unknown'} · "
            f"{profile.skipped_files} skipped[/dim]\n"
        )

        try:
            with console.status("running semgrep"):
                outcome = SemgrepScanner(profile=profile).scan(
                    ScanRequest(source=wd.source.resolve(), output=wd.output.resolve(),
                                timeout_seconds=timeout)
                )
        except ScannerUnavailable as exc:
            console.print(f"[red]scanner failed:[/red] {exc}")
            raise typer.Exit(2)

        state = state.record(StepResult(
            step="semgrep",
            status=StepStatus.DEGRADED if outcome.degraded else StepStatus.OK,
            detail=outcome.partial_reason or "",
            duration_ms=outcome.duration_ms,
        ))

        snippets = extract_snippets(wd.source, outcome.findings)
        findings = apply_fingerprints(outcome.findings, snippets)

        if json_out:
            json_out.write_text(json.dumps(
                {"scan_id": scan_id,
                 "provenance": state.provenance.model_dump(mode="json"),
                 "coverage": [c.model_dump(mode="json") for c in profile.coverage],
                 "findings": [f.model_dump(mode="json") for f in findings]},
                indent=2,
            ))

    _render(findings, profile, state)
    raise typer.Exit(1 if findings else 0)


def _render(findings, profile, state: ScanState) -> None:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

    if not findings:
        console.print("[green]no findings[/green]")
    else:
        table = Table(show_header=True, header_style="dim")
        table.add_column("severity")
        table.add_column("rule")
        table.add_column("location")
        for f in sorted(findings, key=lambda f: -f.severity.rank)[:40]:
            table.add_row(
                f"[{_COLOR[f.severity.value]}]{f.severity.value}[/]",
                f.title,
                f"{f.location.file_path}:{f.location.line_start}",
            )
        console.print(table)
        console.print("  ".join(
            f"[{_COLOR[s]}]{s} {counts[s]}[/]"
            for s in ("critical", "high", "medium", "low", "info") if s in counts
        ))

    for note in profile.coverage:
        if note.coverage is not Coverage.FULL:
            console.print(f"[yellow]coverage[/yellow] {note.domain.value}: {note.reason}")
    for step in state.steps:
        if step.status is not StepStatus.OK:
            console.print(f"[yellow]degraded[/yellow] {step.step}: {step.detail}")
