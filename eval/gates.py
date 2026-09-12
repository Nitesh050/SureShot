from __future__ import annotations

import json
import sys
from pathlib import Path

MIN_RECALL = 0.95
MAX_HOLD_RATE = 0.40
MIN_NOISE_REDUCTION = 0.15


def latest_run(runs: Path) -> dict:
    candidates = sorted(runs.glob("*.json"))
    if not candidates:
        raise SystemExit("no eval runs found")
    return json.loads(candidates[-1].read_text())


def main() -> int:
    metrics = latest_run(Path(__file__).parent / "runs")["metrics"]
    failures = []

    if metrics["recall"] < MIN_RECALL:
        failures.append(f"recall {metrics['recall']:.3f} < {MIN_RECALL}")
    if metrics["hold_rate"] > MAX_HOLD_RATE:
        failures.append(f"hold_rate {metrics['hold_rate']:.3f} > {MAX_HOLD_RATE}")
    if metrics["noise_reduction"] < MIN_NOISE_REDUCTION:
        failures.append(f"noise_reduction {metrics['noise_reduction']:.3f} < {MIN_NOISE_REDUCTION}")

    for failure in failures:
        print(f"GATE FAIL: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
