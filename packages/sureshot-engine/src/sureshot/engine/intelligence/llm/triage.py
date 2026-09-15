from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Mapping

from pydantic import ValidationError

from sureshot.domain.analysis import Evidence, SecurityAnalysis
from sureshot.domain.enums import GuardHold, Verdict
from sureshot.domain.finding import Location, SecurityFinding
from sureshot.engine.context.snippet import Snippet
from sureshot.engine.guards.evidence import enforce_evidence_window
from sureshot.engine.guards.injection import scan_for_directives
from sureshot.engine.intelligence.llm.budget import BudgetExceeded, TokenBudget
from sureshot.engine.intelligence.llm.cache import TriageCache
from sureshot.engine.intelligence.llm.client import LLMClient, LLMError
from sureshot.engine.intelligence.llm.schemas import TriageResponse, parse_triage_response
from sureshot.engine.intelligence.prompts.registry import load_prompt

CHARS_PER_TOKEN = 4


class TriageEngine:
    def __init__(
        self,
        client: LLMClient,
        prompt_name: str = "triage",
        prompt_version: str = "v3",
        cache: TriageCache | None = None,
        budget: TokenBudget | None = None,
        max_retries: int = 1,
    ) -> None:
        self._client = client
        self._prompt = load_prompt(prompt_name, prompt_version)
        self._cache = cache
        self._budget = budget
        self._max_retries = max_retries

    def triage(self, finding: SecurityFinding, snippet: Snippet) -> SecurityAnalysis:
        if not snippet.matched:
            return self._held(finding, GuardHold.EVIDENCE, "no source available")

        signals = scan_for_directives(
            snippet.context or snippet.matched, snippet.context_start
        )
        if signals:
            return self._held(
                finding,
                GuardHold.INJECTION,
                f"line {signals[0].line}: {signals[0].reason} — {signals[0].excerpt!r}",
            )

        key = (
            TriageCache.key(finding.instance_id, self._prompt.hash, self._client.model_id)
            if self._cache and finding.instance_id
            else None
        )
        if key and (hit := self._cache.get(key)) is not None:
            return hit

        prompt = self._render(finding, snippet)

        if self._budget is not None:
            try:
                self._budget.check(len(prompt) // CHARS_PER_TOKEN)
            except BudgetExceeded as exc:
                return self._held(finding, GuardHold.BUDGET, str(exc))

        response = self._ask(prompt)
        if response is None:
            return self._held(finding, GuardHold.EVIDENCE, "no usable model response")

        analysis = self._to_analysis(finding, response)
        analysis = enforce_evidence_window(analysis, snippet)

        if key:
            self._cache.put(key, analysis)
        return analysis

    def triage_batch(
        self,
        findings: tuple[SecurityFinding, ...],
        snippets: Mapping[str, Snippet],
    ) -> tuple[SecurityAnalysis, ...]:
        return tuple(
            self.triage(f, snippets.get(f.instance_id, Snippet("", "", 1)))
            for f in findings
        )

    def _render(self, finding: SecurityFinding, snippet: Snippet) -> str:
        return self._prompt.render(
            rule_id=finding.rule_id,
            message=finding.description or finding.title,
            cwe=", ".join(finding.cwe_ids) or "none reported",
            file_path=finding.location.file_path,
            line_start=finding.location.line_start,
            line_end=finding.location.line_end,
            context_start=snippet.context_start,
            code=snippet.context or snippet.matched,
        )

    def _ask(self, prompt: str) -> TriageResponse | None:
        for _ in range(self._max_retries + 1):
            try:
                reply = self._client.complete(prompt)
            except LLMError:
                return None

            if self._budget is not None:
                self._budget.record(reply.input_tokens, reply.output_tokens)

            try:
                return parse_triage_response(reply.text)
            except (ValueError, ValidationError):
                continue
        return None

    def _to_analysis(
        self, finding: SecurityFinding, response: TriageResponse
    ) -> SecurityAnalysis:
        evidence = tuple(
            Evidence(
                location=Location(
                    file_path=finding.location.file_path,
                    line_start=c.line_start,
                    line_end=c.line_end,
                ),
                note=c.note,
            )
            for c in response.citations
        )
        return SecurityAnalysis(
            analysis_id=f"an_{uuid.uuid4().hex[:12]}",
            instance_id=finding.instance_id or "",
            verdict=response.verdict,
            confidence=response.confidence,
            rationale=response.rationale,
            evidence=evidence,
            impact=response.impact,
            remediation=response.remediation,
            model_id=self._client.model_id,
            prompt_version=self._prompt.version,
            prompt_hash=self._prompt.hash,
            created_at=datetime.now(UTC),
        )

    def _held(
        self, finding: SecurityFinding, hold: GuardHold, reason: str
    ) -> SecurityAnalysis:
        return SecurityAnalysis(
            analysis_id=f"an_{uuid.uuid4().hex[:12]}",
            instance_id=finding.instance_id or "",
            verdict=Verdict.NEEDS_HUMAN,
            confidence=0.0,
            rationale=reason,
            guard_holds=(hold,),
            model_id=self._client.model_id,
            prompt_version=self._prompt.version,
            prompt_hash=self._prompt.hash,
            created_at=datetime.now(UTC),
        )
