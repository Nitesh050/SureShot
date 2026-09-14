from __future__ import annotations

import json
import shutil
import tempfile
import uuid
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from sureshot.domain.enums import StepStatus
from sureshot.engine.ingest.profiler import EXCLUDED_DIRS
from sureshot.engine.ingest.unpack import unpack
from sureshot.engine.ingest.workdir import Workdir
from sureshot.engine.intelligence.llm.client import AnthropicClient, LLMError, OllamaClient
from sureshot.engine.pipeline.run import PipelineConfig, run_pipeline

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


@app.command()
def scan(
    target: Path = typer.Argument(..., exists=True),
    json_out: Path | None = typer.Option(None, "--json"),
    timeout: int = typer.Option(900, "--timeout"),
    no_triage: bool = typer.Option(False, "--no-triage"),
    max_triage: int | None = typer.Option(None, "--max-triage"),
    llm: str = typer.Option("anthropic", "--llm", help="anthropic or ollama"),
    llm_model: str | None = typer.Option(None, "--llm-model"),
    keep: bool = typer.Option(False, "--keep"),
) -> None:
    client = None
    if not no_triage:
        try:
            client = _build_client(llm, llm_model)
        except LLMError as exc:
            console.print(f"[yellow]triage disabled:[/yellow] {exc}")

    scan_id = uuid.uuid4().hex[:12]
    with Workdir(scan_id=scan_id, base=Path(tempfile.gettempdir()), keep=keep) as wd:
        with console.status("staging"):
            _stage(target.resolve(), wd.source)
        with console.status("scanning"):
            result = run_pipeline(
                wd.source,
                PipelineConfig(client=client, timeout_seconds=timeout, max_triage=max_triage),
            )
        if json_out:
            json_out.write_text(json.dumps({
                "scan_id": result.state.scan_id,
                "provenance": result.state.provenance.model_dump(mode="json"),
                "coverage": [c.model_dump(mode="json") for c in result.profile.coverage],
                "findings": [{
                    "finding": s.finding.model_dump(mode="json"),
                    "analysis": s.analysis.model_dump(mode="json") if s.analysis else None,
                    "risk": s.risk.model_dump(mode="json"),
                } for s in result.findings],
            }, indent=2))

    _render(result)
    raise typer.Exit(1 if result.findings else 0)


def _render(result) -> None:
    if not result.findings:
        console.print("[green]no findings[/green]")
    else:
        table = Table(show_header=True, header_style="dim")
        table.add_column("risk", justify="right")
        table.add_column("sev")
        table.add_column("verdict")
        table.add_column("rule")
        table.add_column("location")
        for s in result.findings[:40]:
            verdict = s.analysis.verdict.value if s.analysis else "—"
            held = s.analysis and s.analysis.guard_holds
            table.add_row(
                f"{s.risk.score:.0f}",
                f"[{_COLOR[s.finding.severity.value]}]{s.finding.severity.value}[/]",
                f"[yellow]{verdict}[/]" if held else verdict,
                s.finding.title,
                f"{s.finding.location.file_path}:{s.finding.location.line_start}",
            )
        console.print(table)

    for s in result.findings:
        for hold in (s.analysis.guard_holds if s.analysis else ()):
            console.print(
                f"[yellow]held[/yellow] {s.finding.location.file_path}"
                f":{s.finding.location.line_start} — {hold.value}: {s.analysis.rationale}"
            )

    for note in result.profile.coverage:
        if note.coverage.value != "full":
            console.print(f"[yellow]coverage[/yellow] {note.domain.value}: {note.reason}")
    for step in result.state.steps:
        if step.status is not StepStatus.OK:
            console.print(f"[yellow]{step.status.value}[/yellow] {step.step}: {step.detail}")
