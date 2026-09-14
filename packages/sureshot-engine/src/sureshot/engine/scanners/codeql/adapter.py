from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from sureshot.domain.enums import Domain, Severity
from sureshot.domain.finding import Location, SecurityFinding
from sureshot.domain.scan import ToolRecord

_CWE_TAG = re.compile(r"external/cwe/cwe-(\d+)", re.IGNORECASE)

_LEVEL_SEVERITY = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}


class AdapterError(Exception):
    """CodeQL SARIF output could not be converted into SecurityFindings."""


def _severity_from_score(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


def _map_severity(rule: dict) -> Severity:
    """security-severity (a CVSS-like score) is the most precise signal; fall
    back to the rule's SARIF level when a rule carries no score."""
    props = rule.get("properties") or {}
    score = props.get("security-severity")
    if score is not None:
        try:
            return _severity_from_score(float(score))
        except (TypeError, ValueError):
            pass
    level = (rule.get("defaultConfiguration") or {}).get("level")
    return _LEVEL_SEVERITY.get(str(level or "").lower(), Severity.MEDIUM)


def _extract_cwe_ids(rule: dict) -> tuple[str, ...]:
    tags = (rule.get("properties") or {}).get("tags") or []
    found = {
        f"CWE-{int(match.group(1))}"
        for tag in tags
        if isinstance(tag, str)
        for match in [_CWE_TAG.search(tag)]
        if match
    }
    return tuple(sorted(found, key=lambda c: int(c[4:])))


def _relative_path(uri: str) -> str:
    path = Path(str(uri).replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts:
        raise AdapterError(f"codeql reported a path outside the scan root: {uri}")
    return path.as_posix()


def _require(payload: dict, key: str, where: str) -> Any:
    if key not in payload:
        raise AdapterError(f"codeql {where} is missing required field {key!r}")
    return payload[key]


def _build_rule_index(rules: list[dict]) -> dict[str, dict]:
    return {rule["id"]: rule for rule in rules if "id" in rule}


def _adapt_result(result: dict, rules: dict[str, dict], tool: ToolRecord) -> SecurityFinding:
    rule_id = str(_require(result, "ruleId", "result"))
    rule = rules.get(rule_id, {})

    locations = result.get("locations") or []
    if not locations:
        raise AdapterError(f"result for {rule_id!r} has no location")
    physical = locations[0].get("physicalLocation") or {}
    uri = (physical.get("artifactLocation") or {}).get("uri")
    if not uri:
        raise AdapterError(f"result for {rule_id!r} has no artifact location")

    # SARIF omits endLine entirely when a region spans a single line.
    region = physical.get("region") or {}
    start = int(region.get("startLine", 1) or 1)
    end = int(region.get("endLine", start) or start)

    title = (rule.get("shortDescription") or {}).get("text") or rule_id
    message = (result.get("message") or {}).get("text") or ""

    return SecurityFinding(
        tool=tool.name,
        tool_version=tool.version,
        rule_id=rule_id,
        domain=Domain.SAST,
        title=str(title),
        description=str(message).strip(),
        severity=_map_severity(rule),
        cwe_ids=_extract_cwe_ids(rule),
        location=Location(
            file_path=_relative_path(uri),
            line_start=max(start, 1),
            line_end=max(end, start, 1),
        ),
        raw={
            "precision": (rule.get("properties") or {}).get("precision"),
            "security_severity": (rule.get("properties") or {}).get("security-severity"),
        },
    )


def adapt_results(payload: dict[str, Any], tool: ToolRecord) -> tuple[SecurityFinding, ...]:
    """Convert a parsed `codeql database analyze --format=sarif-latest` report."""
    runs = payload.get("runs") or []
    if not runs:
        return ()

    run = runs[0]
    rules = _build_rule_index(((run.get("tool") or {}).get("driver") or {}).get("rules") or [])
    findings: list[SecurityFinding] = []

    for index, result in enumerate(run.get("results") or []):
        try:
            findings.append(_adapt_result(result, rules, tool))
        except AdapterError as exc:
            raise AdapterError(f"result at index {index}: {exc}") from exc
        except Exception as exc:
            raise AdapterError(f"result at index {index}: {exc}") from exc

    return tuple(findings)
