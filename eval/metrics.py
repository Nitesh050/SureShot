from __future__ import annotations

import math
from dataclasses import dataclass

from sureshot.domain.enums import Verdict


@dataclass(frozen=True)
class Confusion:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    held: int = 0

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn + self.held

    @property
    def recall(self) -> float:
        """Of real vulnerabilities, how many survived triage. Must not regress."""
        actual_positive = self.tp + self.fn + self._held_positive
        return self.tp / actual_positive if actual_positive else 0.0

    @property
    def precision(self) -> float:
        predicted_positive = self.tp + self.fp
        return self.tp / predicted_positive if predicted_positive else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def mcc(self) -> float:
        tp, fp, tn, fn = self.tp, self.fp, self.tn, self.fn
        denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
        return ((tp * tn) - (fp * fn)) / denom if denom else 0.0

    @property
    def hold_rate(self) -> float:
        return self.held / self.total if self.total else 0.0

    @property
    def noise_reduction(self) -> float:
        """Fraction of scanner output a human no longer has to read."""
        return self.tn / self.total if self.total else 0.0

    _held_positive: int = 0


def score(
    predictions: dict[str, Verdict],
    labels: dict[str, bool],
) -> Confusion:
    """Compare verdicts against ground truth. Held findings count as reviewed, not missed."""
    tp = fp = tn = fn = held = held_positive = 0

    for instance_id, is_vulnerable in labels.items():
        verdict = predictions.get(instance_id, Verdict.NEEDS_HUMAN)

        if verdict is Verdict.NEEDS_HUMAN:
            held += 1
            if is_vulnerable:
                held_positive += 1
            continue

        kept = verdict is Verdict.TRUE_POSITIVE
        if kept and is_vulnerable:
            tp += 1
        elif kept and not is_vulnerable:
            fp += 1
        elif not kept and is_vulnerable:
            fn += 1
        else:
            tn += 1

    return Confusion(tp=tp, fp=fp, tn=tn, fn=fn, held=held, _held_positive=held_positive)


def report(confusion: Confusion) -> str:
    c = confusion
    return (
        f"n={c.total}  tp={c.tp} fp={c.fp} tn={c.tn} fn={c.fn} held={c.held}\n"
        f"recall={c.recall:.3f}  precision={c.precision:.3f}  "
        f"f1={c.f1:.3f}  mcc={c.mcc:.3f}\n"
        f"hold_rate={c.hold_rate:.3f}  noise_reduction={c.noise_reduction:.3f}"
    )