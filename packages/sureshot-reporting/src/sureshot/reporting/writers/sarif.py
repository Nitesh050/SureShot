from __future__ import annotations

import json

from sureshot.domain.enums import Severity
from sureshot.reporting.builder import ReportData

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


def write(report: ReportData) -> str:
    """Render SureShot's own deduplicated findings as SARIF 2.1.0.

    This is the reverse direction of scanners/codeql/adapter.py: there we
    read SARIF in, here we emit it, so other tools (GitHub code scanning,
    IDE integrations) can consume SureShot's combined, cross-tool-deduped
    output the same way they'd consume any single scanner's.
    """
    rules: dict[str, dict] = {}
    results = []

    for issue in report.issues:
        finding = issue.primary.finding
        if finding.rule_id not in rules:
            rules[finding.rule_id] = {
                "id": finding.rule_id,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description or finding.title},
                "properties": {
                    "tags": [f"external/cwe/{cwe.lower()}" for cwe in finding.cwe_ids],
                },
            }
        results.append({
            "ruleId": finding.rule_id,
            "level": _SARIF_LEVEL.get(finding.severity, "warning"),
            "message": {"text": finding.description or finding.title},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.location.file_path},
                    "region": {
                        "startLine": finding.location.line_start,
                        "endLine": finding.location.line_end,
                    },
                }
            }],
            "partialFingerprints": {"issueId": issue.issue_id},
        })

    sarif = {
        "$schema": SCHEMA_URI,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "SureShot",
                "version": report.state.provenance.engine_version,
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)
