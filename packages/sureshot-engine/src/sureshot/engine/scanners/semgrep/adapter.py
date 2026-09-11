from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable

from sureshot.domain.enums import Domain, Severity
from sureshot.domain.finding import Location, SecretRef, SecurityFinding
from sureshot.domain.scan import ToolRecord

_CWE_PATTERN = re.compile(r"\bCWE-(\d+)\b")

_SECRET_RULE_MARKERS = ("secrets", "detected-", "hardcoded", "hard-coded")

_SEVERITY_TABLE: dict[tuple[str, str], Severity] = {
    ("ERROR", "HIGH"): Severity.HIGH,
    ("ERROR", "MEDIUM"): Severity.HIGH,
    ("ERROR", "LOW"): Severity.MEDIUM,
    ("WARNING", "HIGH"): Severity.MEDIUM,
    ("WARNING", "MEDIUM"): Severity.MEDIUM,
    ("WARNING", "LOW"): Severity.LOW,
    ("INFO", "HIGH"): Severity.LOW,
    ("INFO", "MEDIUM"): Severity.LOW,
    ("INFO", "LOW"): Severity.INFO,
}


class AdapterError(Exception):
    """Scanner output could not be converted into a SecurityFinding."""


def extract_cwe_ids(raw: Any) -> tuple[str, ...]:
    """Pull bare CWE identifiers out of Semgrep's prose metadata strings."""
    if raw is None:
        return ()
    entries = [raw] if isinstance(raw, str) else list(raw)
    found = {
        f"CWE-{match.group(1)}"
        for entry in entries
        if isinstance(entry, str)
        for match in [_CWE_PATTERN.search(entry)]
        if match
    }
    return tuple(sorted(found, key=lambda c: int(c[4:])))


def map_severity(severity: Any, confidence: Any) -> Severity:
    key = (
        str(severity or "").upper(),
        str(confidence or "MEDIUM").upper(),
    )
    return _SEVERITY_TABLE.get(key, Severity.LOW)


def _is_secret_rule(check_id: str) -> bool:
    lowered = check_id.lower()
    return any(marker in lowered for marker in _SECRET_RULE_MARKERS)


def _title_from_rule(check_id: str) -> str:
    leaf = check_id.rsplit(".", 1)[-1]
    return leaf.replace("-", " ").replace("_", " ").strip().capitalize() or check_id


def _relative_path(raw_path: str, root: Path) -> str:
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        return candidate.as_posix()
    try:
        return candidate.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise AdapterError(
            f"scanner reported a path outside the scan root: {raw_path}"
        ) from exc


def _require(result: dict, key: str) -> Any:
    if key not in result:
        raise AdapterError(f"semgrep result is missing required field {key!r}")
    return result[key]


def _redact(matched: str) -> SecretRef:
    stripped = "".join(ch for ch in matched.strip() if not ch.isspace())
    return SecretRef(kind="semgrep-detected", last_four=stripped[-4:] if stripped else "")


def adapt_result(
    result: dict[str, Any],
    root: Path,
    tool: ToolRecord,
) -> SecurityFinding:
    check_id = str(_require(result, "check_id"))
    raw_path = str(_require(result, "path"))
    extra = result.get("extra") or {}
    metadata = extra.get("metadata") or {}

    start = int((result.get("start") or {}).get("line", 1) or 1)
    end = int((result.get("end") or {}).get("line", start) or start)
    start = max(start, 1)
    end = max(end, start)

    location = Location(
        file_path=_relative_path(raw_path, root),
        line_start=start,
        line_end=end,
    )

    is_secret = _is_secret_rule(check_id)
    severity = map_severity(extra.get("severity"), metadata.get("confidence"))
    if is_secret:
        severity = Severity.CRITICAL

    return SecurityFinding(
        tool=tool.name,
        tool_version=tool.version,
        rule_id=check_id,
        domain=Domain.SECRET if is_secret else Domain.SAST,
        title=_title_from_rule(check_id),
        description=str(extra.get("message") or "").strip(),
        severity=severity,
        cwe_ids=extract_cwe_ids(metadata.get("cwe")),
        location=location,
        secret=_redact(str(extra.get("lines") or "")) if is_secret else None,
        raw={} if is_secret else {
            "owasp": metadata.get("owasp"),
            "references": metadata.get("references"),
            "confidence": metadata.get("confidence"),
            "semgrep_severity": extra.get("severity"),
        },
    )


def adapt_results(
    results: Iterable[dict[str, Any]],
    root: Path,
    tool: ToolRecord,
) -> tuple[SecurityFinding, ...]:
    findings = []
    for index, result in enumerate(results):
        try:
            findings.append(adapt_result(result, root, tool))
        except AdapterError as exc:
            raise AdapterError(f"result at index {index}: {exc}") from exc
        except Exception as exc:
            raise AdapterError(f"result at index {index}: {exc}") from exc
    return tuple(findings)
