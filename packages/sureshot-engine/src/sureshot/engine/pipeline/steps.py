from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Sequence

from sureshot.domain.enums import StepStatus
from sureshot.domain.finding import SecurityFinding
from sureshot.domain.repository import RepositoryProfile
from sureshot.domain.result import TriagedFinding
from sureshot.domain.scan import ScanState, StepResult
from sureshot.engine.context.snippet import Snippet, extract_snippets, snippet_key
from sureshot.engine.guards.redaction import redact_snippets
from sureshot.engine.ingest.profiler import profile_repository
from sureshot.engine.normalize.fingerprint import apply_fingerprints
from sureshot.engine.risk.scoring import RiskPolicy, score_finding
from sureshot.engine.scanners.base import ScanRequest, Scanner, ScannerUnavailable


class TriageProvider(Protocol):
    def triage_batch(self, findings, snippets): ...


@dataclass(frozen=True)
class PipelineContext:
    source: Path
    output: Path
    scanners: Sequence[Scanner]
    triage: TriageProvider | None = None
    policy: RiskPolicy | None = None
    timeout_seconds: int = 900


@dataclass(frozen=True)
class PipelineResult:
    state: ScanState
    profile: RepositoryProfile
    triaged: tuple[TriagedFinding, ...]


def _timed(fn):
    started = time.monotonic()
    value = fn()
    return value, int((time.monotonic() - started) * 1000)


def step_profile(
    state: ScanState, ctx: PipelineContext
) -> tuple[ScanState, RepositoryProfile]:
    profile, ms = _timed(lambda: profile_repository(ctx.source))
    return state.record(
        StepResult(step="profile", status=StepStatus.OK, duration_ms=ms)
    ), profile


def step_scan(
    state: ScanState, ctx: PipelineContext, profile: RepositoryProfile
) -> tuple[ScanState, tuple[SecurityFinding, ...]]:
    findings: list[SecurityFinding] = []
    provenance = state.provenance

    for scanner in ctx.scanners:
        request = ScanRequest(
            source=ctx.source, output=ctx.output, timeout_seconds=ctx.timeout_seconds
        )
        try:
            outcome = scanner.scan(request)
        except ScannerUnavailable as exc:
            state = state.record(StepResult(
                step=f"scan:{scanner.name}", status=StepStatus.DEGRADED,
                detail=str(exc)[:300], duration_ms=0,
            ))
            continue

        findings.extend(outcome.findings)
        provenance = provenance.with_tool(outcome.tool)
        state = state.record(StepResult(
            step=f"scan:{scanner.name}",
            status=StepStatus.DEGRADED if outcome.degraded else StepStatus.OK,
            detail=outcome.partial_reason or "",
            duration_ms=outcome.duration_ms,
        ))

    return state.model_copy(update={"provenance": provenance}), tuple(findings)


def step_fingerprint(
    state: ScanState, ctx: PipelineContext, findings: tuple[SecurityFinding, ...]
) -> tuple[ScanState, tuple[SecurityFinding, ...], dict]:
    def _work():
        snippets = extract_snippets(ctx.source, findings)
        return apply_fingerprints(findings, snippets), snippets

    (stamped, snippets), ms = _timed(_work)
    return state.record(
        StepResult(step="fingerprint", status=StepStatus.OK, duration_ms=ms)
    ), stamped, snippets


def step_redact(
    state: ScanState, ctx: PipelineContext,
    findings: tuple[SecurityFinding, ...], snippets: dict,
) -> tuple[ScanState, dict]:
    """Strip secret material out of every snippet before triage can see it.

    Runs after step_fingerprint (so fingerprint stability, computed from
    finding metadata rather than snippet text, is unaffected) and before
    step_triage (the only consumer of `snippets` that leaves this process,
    via the LLM prompt).
    """
    def _work():
        return redact_snippets(findings, snippets)

    redacted, ms = _timed(_work)
    return state.record(
        StepResult(step="redact", status=StepStatus.OK, duration_ms=ms)
    ), redacted


def step_triage(
    state: ScanState, ctx: PipelineContext,
    findings: tuple[SecurityFinding, ...], snippets: dict,
) -> tuple[ScanState, dict]:
    if ctx.triage is None or not findings:
        return state.record(
            StepResult(step="triage", status=StepStatus.OK,
                       detail="skipped", duration_ms=0)
        ), {}

    by_instance = {
        f.instance_id: snippets.get(snippet_key(f.location), Snippet("", "", 1))
        for f in findings
    }

    started = time.monotonic()
    try:
        analyses = ctx.triage.triage_batch(findings, by_instance)
    except Exception as exc:
        return state.record(StepResult(
            step="triage", status=StepStatus.DEGRADED,
            detail=f"triage unavailable: {str(exc)[:200]}",
            duration_ms=int((time.monotonic() - started) * 1000),
        )), {}

    ms = int((time.monotonic() - started) * 1000)
    if analyses:
        state = state.model_copy(update={
            "provenance": state.provenance.model_copy(update={
                "model_id": analyses[0].model_id,
                "prompt_versions": tuple(sorted({a.prompt_version for a in analyses})),
            })
        })

    return state.record(
        StepResult(step="triage", status=StepStatus.OK, duration_ms=ms)
    ), {a.instance_id: a for a in analyses}


def step_score(
    state: ScanState, ctx: PipelineContext,
    findings: tuple[SecurityFinding, ...], analyses: dict,
) -> tuple[ScanState, tuple[TriagedFinding, ...]]:
    policy = ctx.policy or RiskPolicy.default()

    def _work():
        out = []
        for finding in findings:
            analysis = analyses.get(finding.instance_id)
            result = score_finding(finding, analysis, policy)
            out.append(TriagedFinding(
                finding=finding, analysis=analysis, score=result.score,
                contributions=result.contributions, holds=result.holds,
            ))
        return tuple(sorted(out, key=lambda t: (-t.score, t.finding.location.file_path)))

    triaged, ms = _timed(_work)
    state = state.model_copy(update={
        "provenance": state.provenance.model_copy(
            update={"risk_policy_hash": policy.hash}
        )
    })
    return state.record(
        StepResult(step="score", status=StepStatus.OK, duration_ms=ms)
    ), triaged


def run_pipeline(state: ScanState, ctx: PipelineContext) -> PipelineResult:
    state, profile = step_profile(state, ctx)
    state, findings = step_scan(state, ctx, profile)
    state, findings, snippets = step_fingerprint(state, ctx, findings)
    state, snippets = step_redact(state, ctx, findings, snippets)
    state, analyses = step_triage(state, ctx, findings, snippets)
    state, triaged = step_score(state, ctx, findings, analyses)
    return PipelineResult(state=state, profile=profile, triaged=triaged)
