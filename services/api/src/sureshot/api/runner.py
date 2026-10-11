from __future__ import annotations

import json
import logging
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

from sureshot.domain.enums import Severity, Verdict
from sureshot.domain.scan import ScanProvenance, ScanState
from sureshot.engine.context.snippet import Snippet, extract_snippets, snippet_key
from sureshot.engine.guards.redaction import redact_snippets
from sureshot.engine.ingest.fetch import FetchError, clone, parse_repo_url
from sureshot.engine.ingest.profiler import profile_repository
from sureshot.engine.ingest.safety import UnsafeArchiveError
from sureshot.engine.ingest.unpack import unpack
from sureshot.engine.ingest.workdir import Workdir
from sureshot.engine.intelligence.llm.cache import TriageCache
from sureshot.engine.intelligence.llm.client import AnthropicClient, LLMError, OllamaClient
from sureshot.engine.intelligence.llm.triage import TriageEngine
from sureshot.engine.pipeline.steps import PipelineContext, run_pipeline
from sureshot.engine.scanners.registry import build_scanner, default_scanners
from sureshot.reporting.builder import ReportData, build_report
from sureshot.reporting.writers import html as html_writer
from sureshot.reporting.writers import json as json_writer
from sureshot.reporting.writers import pdf as pdf_writer
from sureshot.reporting.writers import sarif as sarif_writer

from sureshot.api.store import REPORT_FILES, ScanRecord, ScanStatus, ScanStore, ScanSummary, StepRecord, now

log = logging.getLogger(__name__)

UPLOAD_NAME = "upload.bin"


class _ProgressTriage:
    """Wraps a TriageEngine so the API can report per-finding progress.

    Triage is by far the slowest step (one LLM call per finding), so without
    this the UI would sit on "AI triage" for minutes with no signal.
    """

    def __init__(self, engine: TriageEngine, report: Callable[[int, int], None]) -> None:
        self._engine = engine
        self._report = report

    def triage_batch(self, findings, snippets):
        total = len(findings)
        out = []
        last = 0.0
        for done, finding in enumerate(findings, start=1):
            out.append(self._engine.triage(finding, snippets.get(finding.instance_id, Snippet("", "", 1))))
            if time.monotonic() - last > 1.0 or done == total:
                self._report(done, total)
                last = time.monotonic()
        return tuple(out)


class ScanRunner:
    """Runs scans on a small thread pool inside the API process.

    The worker service will take this over once there is a queue; until then
    two concurrent scans keep a laptop responsive while scanners run.
    """

    def __init__(self, store: ScanStore, max_workers: int = 2, timeout_seconds: int = 900) -> None:
        self.store = store
        self.timeout_seconds = timeout_seconds
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="scan")

    def submit(self, scan_id: str) -> None:
        self._pool.submit(self._run_safely, scan_id)

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)

    def _run_safely(self, scan_id: str) -> None:
        try:
            self._run(scan_id)
        except (FetchError, UnsafeArchiveError) as exc:
            self._fail(scan_id, str(exc))
        except Exception as exc:  # the thread must never die silently
            log.exception("scan %s crashed", scan_id)
            self._fail(scan_id, f"internal error: {exc}"[:300])
        finally:
            upload = self.store.data_dir / scan_id / UPLOAD_NAME
            upload.unlink(missing_ok=True)

    def _fail(self, scan_id: str, message: str) -> None:
        record = self.store.get(scan_id)
        steps = list(record.steps) if record else []
        if record and record.current_step:
            steps.append(StepRecord(step=record.current_step, status="failed", detail=message))
        self.store.update(scan_id, status=ScanStatus.FAILED, error=message,
                          current_step=None, progress=None, steps=steps, finished_at=now())

    def _run(self, scan_id: str) -> None:
        record = self.store.get(scan_id)
        assert record is not None
        self.store.update(scan_id, status=ScanStatus.RUNNING, started_at=now(), current_step="fetch")
        steps: list[StepRecord] = []
        notes: list[str] = []

        with Workdir(scan_id=scan_id, base=Path(tempfile.gettempdir()) / "sureshot") as wd:
            started = time.monotonic()
            source = record.source
            if source.kind == "url":
                repo = parse_repo_url(source.url or "", source.ref)
                commit = clone(repo, wd.source, timeout_seconds=300)
                source = source.model_copy(update={"commit": commit or None})
                detail = f"{repo.display}@{(commit or '')[:7]}"
            else:
                extracted = unpack(self.store.data_dir / scan_id / UPLOAD_NAME, wd.source)
                detail = f"{extracted.files} files extracted"
            steps.append(StepRecord(step="fetch", status="ok", detail=detail,
                                    duration_ms=int((time.monotonic() - started) * 1000)))
            self.store.update(scan_id, source=source, steps=steps, current_step="profile")

            profile = profile_repository(wd.source)
            self.store.update(scan_id, profile=profile.model_dump(mode="json"))

            engine = self._triage_engine(record, notes)
            triage = None
            if engine is not None:
                triage = _ProgressTriage(engine, lambda done, total: self.store.update(
                    scan_id, progress=f"{done}/{total} findings"))
            ctx = PipelineContext(
                source=wd.source.resolve(), output=wd.output.resolve(),
                scanners=self._scanners(record, profile), triage=triage,
                timeout_seconds=self.timeout_seconds,
            )
            state = ScanState(
                scan_id=scan_id, org_id="local", project_id=source.label,
                workdir=str(wd.root), started_at=now(),
                provenance=ScanProvenance(engine_version="0.1.0"),
            )

            def on_step(name: str, current: ScanState) -> None:
                self.store.update(scan_id, current_step=name, notes=notes, progress=None,
                                  steps=steps + [_step(s) for s in current.steps])

            result = run_pipeline(state, ctx, on_step=on_step)
            steps += [_step(s) for s in result.state.steps]

            self.store.update(scan_id, current_step="report", progress=None, steps=steps)
            started = time.monotonic()
            report = build_report(result)
            written = self._write_reports(scan_id, report, notes)
            self._write_snippets(scan_id, wd.source, report)
            steps.append(StepRecord(step="report", status="ok",
                                    detail=f"{len(report.issues)} issues after dedup",
                                    duration_ms=int((time.monotonic() - started) * 1000)))

        self.store.update(
            scan_id, status=ScanStatus.COMPLETED, finished_at=now(), current_step=None, progress=None,
            steps=steps, notes=notes, reports=written, summary=_summarize(report),
        )

    def _triage_engine(self, record: ScanRecord, notes: list[str]) -> TriageEngine | None:
        if not record.options.triage:
            notes.append("AI triage was turned off for this scan.")
            return None
        try:
            client = OllamaClient() if record.options.llm == "ollama" else AnthropicClient()
            return TriageEngine(client=client, cache=TriageCache())
        except LLMError as exc:
            notes.append(f"AI triage unavailable: {exc}")
            return None

    def _scanners(self, record: ScanRecord, profile):
        names = record.options.scanners
        if not names:
            return default_scanners(profile)
        return tuple(
            build_scanner(n, profile=profile) if n in ("semgrep", "codeql") else build_scanner(n)
            for n in names
        )

    def _write_reports(self, scan_id: str, report: ReportData, notes: list[str]) -> list[str]:
        writers = {"json": json_writer, "sarif": sarif_writer, "html": html_writer, "pdf": pdf_writer}
        out_dir = self.store.dir_for(scan_id)
        written = []
        for fmt, writer in writers.items():
            name, _ = REPORT_FILES[fmt]
            try:
                content = writer.write(report)
            except Exception as exc:
                log.exception("%s report failed for %s", fmt, scan_id)
                notes.append(f"{fmt.upper()} report could not be generated: {exc}"[:200])
                continue
            path = out_dir / name
            if isinstance(content, bytes):
                path.write_bytes(content)
            else:
                path.write_text(content)
            written.append(fmt)
        return written

    def _write_snippets(self, scan_id: str, source: Path, report: ReportData) -> None:
        """Save redacted code context for each issue's primary finding, so the
        UI can show the vulnerable lines after the workdir is gone."""
        findings = tuple(i.primary.finding for i in report.issues)
        try:
            snippets = redact_snippets(findings, extract_snippets(source, findings))
        except Exception:
            log.exception("snippet extraction failed for %s", scan_id)
            return
        out = {}
        for finding in findings:
            snip = snippets.get(snippet_key(finding.location))
            if snip and snip.context:
                out[finding.instance_id] = {
                    "context": snip.context,
                    "context_start": snip.context_start,
                    "truncated": snip.truncated,
                }
        (self.store.dir_for(scan_id) / "snippets.json").write_text(json.dumps(out))


def _step(s) -> StepRecord:
    return StepRecord(step=s.step, status=s.status.value, detail=s.detail, duration_ms=s.duration_ms)


def _summarize(report: ReportData) -> ScanSummary:
    issues = report.issues
    actionable = [i for i in issues if i.primary.actionable]
    by_severity = {s.value: 0 for s in Severity}
    for issue in actionable:
        by_severity[issue.primary.finding.severity.value] += 1
    return ScanSummary(
        raw_findings=sum(i.occurrences for i in issues),
        issues=len(issues),
        actionable=len(actionable),
        dismissed=len(issues) - len(actionable),
        needs_review=sum(1 for i in issues if i.primary.verdict is Verdict.NEEDS_HUMAN),
        multi_tool=sum(1 for i in issues if i.confirmed_by_multiple_tools),
        by_severity=by_severity,
    )

