from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from sureshot.domain.enums import StepStatus
from sureshot.domain.scan import ScanProvenance, ScanState, StepResult
from sureshot.engine.context.snippet import Snippet, extract_snippets, snippet_key
from sureshot.engine.ingest.profiler import profile_repository
from sureshot.engine.intelligence.llm.budget import TokenBudget
from sureshot.engine.intelligence.llm.cache import TriageCache
from sureshot.engine.intelligence.llm.client import LLMClient
from sureshot.engine.intelligence.llm.triage import TriageEngine
from sureshot.engine.normalize.fingerprint import apply_fingerprints
from sureshot.engine.pipeline.steps import PipelineResult, ScoredFinding
from sureshot.engine.risk.scoring import RiskPolicy, score_finding
from sureshot.engine.scanners.base import ScanRequest, ScannerUnavailable
from sureshot.engine.scanners.semgrep.scanner import SemgrepScanner

ENGINE_VERSION = "0.1.0"


@dataclass(frozen=True)
class PipelineConfig:
    client: LLMClient | None = None
    timeout_seconds: int = 900
    max_triage: int | None = None
    budget: TokenBudget | None = None
    org_id: str = "local"


class _Timer:
    def __enter__(self):
        self._start = time.monotonic()
        return self

    def __exit__(self, *_): ...

    @property
    def ms(self) -> int:
        return int((time.monotonic() - self._start) * 1000)


def run_pipeline(source: Path, config: PipelineConfig) -> PipelineResult:
    """Profile, scan, fingerprint, triage, and score a staged repository."""
    source = source.resolve()
    state = ScanState(
        scan_id=uuid.uuid4().hex[:12],
        org_id=config.org_id,
        project_id=source.name,
        workdir=str(source),
        started_at=datetime.now(UTC),
        provenance=ScanProvenance(engine_version=ENGINE_VERSION),
    )

    with _Timer() as t:
        profile = profile_repository(source)
    state = state.record(StepResult(step="profile", status=StepStatus.OK, duration_ms=t.ms))

    try:
        outcome = SemgrepScanner(profile=profile).scan(
            ScanRequest(source=source, output=source, timeout_seconds=config.timeout_seconds)
        )
    except ScannerUnavailable as exc:
        state = state.record(StepResult(
            step="scan", status=StepStatus.FAILED, detail=str(exc), duration_ms=0
        ))
        return PipelineResult(state=state, profile=profile, findings=())

    state = state.record(StepResult(
        step="scan",
        status=StepStatus.DEGRADED if outcome.degraded else StepStatus.OK,
        detail=outcome.partial_reason or "",
        duration_ms=outcome.duration_ms,
    ))
    state = state.model_copy(update={
        "provenance": state.provenance.with_tool(outcome.tool)
    })

    with _Timer() as t:
        snippets = extract_snippets(source, outcome.findings)
        findings = apply_fingerprints(outcome.findings, snippets)
    state = state.record(StepResult(step="fingerprint", status=StepStatus.OK, duration_ms=t.ms))

    analyses, state = _triage(findings, snippets, config, state)
    policy = RiskPolicy.default()

    with _Timer() as t:
        scored = tuple(
            ScoredFinding(
                finding=finding,
                analysis=analyses.get(finding.instance_id),
                risk=score_finding(finding, analyses.get(finding.instance_id), policy),
            )
            for finding in findings
        )
        scored = tuple(sorted(scored, key=lambda s: (-s.risk.score, s.finding.instance_id)))
    state = state.record(StepResult(step="risk", status=StepStatus.OK, duration_ms=t.ms))

    prompt_versions = tuple(sorted({a.prompt_version for a in analyses.values()}))
    state = state.model_copy(update={
        "provenance": state.provenance.model_copy(update={
            "risk_policy_hash": policy.hash,
            "model_id": config.client.model_id if config.client else None,
            "prompt_versions": prompt_versions,
        })
    })

    return PipelineResult(state=state, profile=profile, findings=scored)


def _triage(findings, snippets, config: PipelineConfig, state: ScanState):
    if config.client is None:
        return {}, state.record(
            StepResult(step="triage", status=StepStatus.OK,
                       detail="triage disabled", duration_ms=0)
        )

    engine = TriageEngine(
        client=config.client, cache=TriageCache(), budget=config.budget
    )
    selected = findings if config.max_triage is None else findings[: config.max_triage]

    analyses = {}
    with _Timer() as t:
        for finding in selected:
            snippet = snippets.get(snippet_key(finding.location), Snippet("", "", 1))
            analyses[finding.instance_id] = engine.triage(finding, snippet)

    skipped = len(findings) - len(selected)
    return analyses, state.record(StepResult(
        step="triage",
        status=StepStatus.DEGRADED if skipped else StepStatus.OK,
        detail=f"{skipped} finding(s) not triaged" if skipped else "",
        duration_ms=t.ms,
    ))
