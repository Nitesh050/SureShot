from __future__ import annotations

import dataclasses
import json
import shutil
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from sureshot.domain.enums import Coverage, StepStatus
from sureshot.domain.scan import ScanProvenance, ScanState
from sureshot.engine.ingest.profiler import EXCLUDED_DIRS, profile_repository
from sureshot.engine.ingest.unpack import unpack
from sureshot.engine.ingest.workdir import Workdir
from sureshot.engine.intelligence.llm.cache import TriageCache
from sureshot.engine.intelligence.llm.client import AnthropicClient, LLMError, OllamaClient
from sureshot.engine.intelligence.llm.triage import TriageEngine
from sureshot.engine.pipeline.steps import PipelineContext, run_pipeline
from sureshot.engine.scanners.registry import build_scanner, default_scanners
from sureshot.reporting.builder import build_report
from sureshot.reporting.writers import sarif as sarif_writer

app = typer.Typer(add_completion=False)
console = Console()

_COLOR = {"critical": "bold red", "high": "red", "medium": "yellow",
          "low": "cyan", "info": "dim"}


# A no-op callback keeps `scan` an explicit subcommand; Typer collapses a
# single @app.command() into the app itself otherwise (no "scan" keyword).
@app.callback()
def _main() -> None:
    pass


def _stage(source: Path, dest: Path) -> None:
    if source.is_dir():
        shutil.copytree(source, dest, dirs_exist_ok=True, symlinks=False,
                        ignore=shutil.ignore_patterns(*EXCLUDED_DIRS))
    else:
        unpack(source, dest)


def _build_client(backend: str, model: str | None):
    if backend == "ollama":
        return OllamaClient(model_id=model) if model else OllamaClient()
    return AnthropicClient(model_id=model) if model else AnthropicClient()


def _select_scanners(names: str | None, profile):
    if not names:
        return default_scanners(profile)
    selected = []
    for name in (n.strip() for n in names.split(",") if n.strip()):
        if name in ("semgrep", "codeql"):
            selected.append(build_scanner(name, profile=profile))
        else:
            selected.append(build_scanner(name))
    return tuple(selected)


@app.command()
def scan(
    target: Path = typer.Argument(..., exists=True),
    json_out: Path | None = typer.Option(None, "--json"),
    sarif_out: Path | None = typer.Option(None, "--sarif", help="write a SARIF report to a file"),
    triage: bool = typer.Option(True, "--triage/--no-triage"),
    min_score: float = typer.Option(0.0, "--min-score"),
    llm: str = typer.Option("anthropic", "--llm", help="anthropic or ollama"),
    llm_model: str | None = typer.Option(None, "--llm-model"),
    scanners: str | None = typer.Option(
        None, "--scanners", help="comma-separated scanner names (default: auto-detected)"
    ),
    timeout: int = typer.Option(900, "--timeout"),
    keep: bool = typer.Option(False, "--keep"),
) -> None:
    scan_id = uuid.uuid4().hex[:12]

    engine = None
    if triage:
        try:
            engine = TriageEngine(client=_build_client(llm, llm_model), cache=TriageCache())
        except LLMError as exc:
            console.print(f"[yellow]triage disabled:[/yellow] {exc}")

    with Workdir(scan_id=scan_id, base=Path(tempfile.gettempdir()), keep=keep) as wd:
        with console.status("staging"):
            _stage(target.resolve(), wd.source)

        profile = profile_repository(wd.source)

        state = ScanState(
            scan_id=scan_id, org_id="local", project_id=target.name,
            workdir=str(wd.root), started_at=datetime.now(UTC),
            provenance=ScanProvenance(engine_version="0.1.0"),
        )
        ctx = PipelineContext(
            source=wd.source.resolve(), output=wd.output.resolve(),
            scanners=_select_scanners(scanners, profile), triage=engine, timeout_seconds=timeout,
        )

        with console.status("scanning"):
            result = run_pipeline(state, ctx)

        shown = tuple(t for t in result.triaged if t.score >= min_score)

        if json_out:
            json_out.write_text(json.dumps({
                "scan_id": scan_id,
                "provenance": result.state.provenance.model_dump(mode="json"),
                "coverage": [c.model_dump(mode="json") for c in result.profile.coverage],
                "findings": [t.model_dump(mode="json") for t in shown],
            }, indent=2))

        if sarif_out:
            report = build_report(result)
            report = dataclasses.replace(
                report,
                issues=tuple(i for i in report.issues if i.primary.score >= min_score),
            )
            sarif_out.write_text(sarif_writer.write(report))

    _render(shown, result.profile, result.state)
    raise typer.Exit(1 if any(t.actionable for t in shown) else 0)


def _render(triaged, profile, state) -> None:
    console.print(
        f"[dim]{profile.scanned_files} files · "
        f"{profile.primary_language or 'unknown'}[/dim]\n"
    )

    if not triaged:
        console.print("[green]no findings[/green]")
    else:
        table = Table(show_header=True, header_style="dim")
        for col in ("score", "sev", "verdict", "rule", "location"):
            table.add_column(col)
        for t in triaged[:40]:
            f = t.finding
            mark = "!" if t.holds else ""
            table.add_row(
                f"{t.score:.0f}{mark}",
                f"[{_COLOR[f.severity.value]}]{f.severity.value}[/]",
                t.verdict.value.replace("_", " "),
                f.title,
                f"{f.location.file_path}:{f.location.line_start}",
            )
        console.print(table)

        dismissed = sum(1 for t in triaged if not t.actionable)
        console.print(
            f"\n{len(triaged)} findings · {len(triaged) - dismissed} actionable · "
            f"{dismissed} dismissed"
        )

    for note in profile.coverage:
        if note.coverage is not Coverage.FULL:
            console.print(f"[yellow]coverage[/yellow] {note.domain.value}: {note.reason}")
    for step in state.steps:
        if step.status is not StepStatus.OK:
            console.print(f"[yellow]degraded[/yellow] {step.step}: {step.detail}")
