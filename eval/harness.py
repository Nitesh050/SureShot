from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import yaml

from sureshot.domain.enums import Verdict
from sureshot.domain.finding import SecurityFinding
from sureshot.engine.context.snippet import extract_snippets
from sureshot.engine.ingest.profiler import profile_repository
from sureshot.engine.normalize.fingerprint import apply_fingerprints
from sureshot.engine.scanners.base import ScanRequest
from sureshot.engine.scanners.semgrep.scanner import SemgrepScanner

from eval.metrics import Confusion, report, score

ROOT = Path(__file__).parent
LINE_TOLERANCE = 3


@dataclass(frozen=True)
class Label:
    case: str
    file: str
    line: int
    cwe: str
    vulnerable: bool
    note: str = ""


def load_labels(path: Path) -> list[Label]:
    raw = yaml.safe_load(path.read_text())
    return [
        Label(case=case, **entry)
        for case, entries in raw["cases"].items()
        for entry in entries
    ]


def match_label(finding: SecurityFinding, labels: list[Label], case: str) -> Label | None:
    """Match on file, CWE, and an approximate line — never on instance_id."""
    for label in labels:
        if label.case != case or label.file != finding.location.file_path:
            continue
        if label.cwe not in finding.cwe_ids:
            continue
        if abs(label.line - finding.location.line_start) <= LINE_TOLERANCE:
            return label
    return None


def scan_case(case_dir: Path) -> tuple[SecurityFinding, ...]:
    profile = profile_repository(case_dir)
    outcome = SemgrepScanner(profile=profile).scan(
        ScanRequest(source=case_dir.resolve(), output=case_dir.resolve(), timeout_seconds=300)
    )
    snippets = extract_snippets(case_dir, outcome.findings)
    return apply_fingerprints(outcome.findings, snippets)


def run(
    dataset: Path,
    labels_path: Path,
    triage,
) -> tuple[Confusion, dict]:
    """Scan every case, triage the findings, and score against labels."""
    labels = load_labels(labels_path)
    predictions: dict[str, Verdict] = {}
    truth: dict[str, bool] = {}
    unmatched: list[str] = []

    for case_dir in sorted(p for p in dataset.iterdir() if p.is_dir()):
        for finding in scan_case(case_dir):
            label = match_label(finding, labels, case_dir.name)
            if label is None:
                unmatched.append(
                    f"{case_dir.name}/{finding.location.file_path}:"
                    f"{finding.location.line_start} {finding.rule_id}"
                )
                continue
            truth[finding.instance_id] = label.vulnerable
            predictions[finding.instance_id] = triage(finding)

    confusion = score(predictions, truth)
    detail = {
        "scored": len(truth),
        "unmatched_findings": unmatched,
        "labels_never_fired": [],
    }
    return confusion, detail


def keep_everything(_finding: SecurityFinding) -> Verdict:
    """Baseline: dismiss nothing. Perfect recall, zero noise reduction."""
    return Verdict.TRUE_POSITIVE


def save_run(name: str, confusion: Confusion, detail: dict) -> Path:
    ROOT.joinpath("runs").mkdir(exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
    path = ROOT / "runs" / f"{stamp}-{name}.json"
    path.write_text(json.dumps({
        "name": name,
        "at": stamp,
        "metrics": {
            "recall": confusion.recall,
            "precision": confusion.precision,
            "f1": confusion.f1,
            "mcc": confusion.mcc,
            "hold_rate": confusion.hold_rate,
            "noise_reduction": confusion.noise_reduction,
        },
        "confusion": {
            "tp": confusion.tp, "fp": confusion.fp,
            "tn": confusion.tn, "fn": confusion.fn, "held": confusion.held,
        },
        "detail": detail,
    }, indent=2))
    return path


if __name__ == "__main__":
    confusion, detail = run(
        ROOT / "datasets" / "internal",
        ROOT / "labels" / "internal.yaml",
        keep_everything,
    )
    print(report(confusion))
    if detail["unmatched_findings"]:
        print(f"\nunmatched ({len(detail['unmatched_findings'])}):")
        for item in detail["unmatched_findings"][:20]:
            print(f"  {item}")
    print(f"\nsaved → {save_run('baseline', confusion, detail)}")
