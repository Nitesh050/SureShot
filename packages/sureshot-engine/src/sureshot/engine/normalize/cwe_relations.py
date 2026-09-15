from __future__ import annotations

# Ancestors for the CWEs scanners actually report. Not the full MITRE tree —
# just enough that two tools tagging the same bug at different taxonomy
# depths (e.g. Semgrep's CWE-704 vs CodeQL's CWE-89 for the same SQL
# injection, verified against live scanner output) are recognized as the
# same weakness, while genuinely unrelated CWEs nearby in a file are not.
_ANCESTORS: dict[str, frozenset[str]] = {
    "CWE-89": frozenset({"CWE-943", "CWE-74", "CWE-707", "CWE-20", "CWE-704"}),
    "CWE-79": frozenset({"CWE-74", "CWE-707", "CWE-20"}),
    "CWE-78": frozenset({"CWE-77", "CWE-74", "CWE-707", "CWE-20"}),
    "CWE-77": frozenset({"CWE-74", "CWE-707"}),
    "CWE-94": frozenset({"CWE-74", "CWE-707"}),
    "CWE-611": frozenset({"CWE-74", "CWE-707"}),
    "CWE-22": frozenset({"CWE-668", "CWE-706"}),
    "CWE-23": frozenset({"CWE-22", "CWE-668"}),
    "CWE-798": frozenset({"CWE-259", "CWE-344", "CWE-671"}),
    "CWE-259": frozenset({"CWE-798", "CWE-344"}),
    "CWE-327": frozenset({"CWE-693"}),
    "CWE-328": frozenset({"CWE-327", "CWE-693"}),
    "CWE-502": frozenset({"CWE-913", "CWE-20"}),
    "CWE-918": frozenset({"CWE-441"}),
    "CWE-352": frozenset({"CWE-345"}),
    "CWE-190": frozenset({"CWE-682"}),
    "CWE-125": frozenset({"CWE-119", "CWE-118"}),
    "CWE-787": frozenset({"CWE-119", "CWE-118"}),
    "CWE-476": frozenset({"CWE-710"}),
}


def _family(cwe: str) -> frozenset[str]:
    return _ANCESTORS.get(cwe, frozenset()) | {cwe}


def related(left: tuple[str, ...], right: tuple[str, ...]) -> bool:
    """True when two CWE sets plausibly describe the same weakness."""
    if not left or not right:
        return False
    for a in left:
        for b in right:
            if a == b or a in _family(b) or b in _family(a):
                return True
    return False
