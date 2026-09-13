from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

_EXCERPT_CHARS = 200

# Who the text addresses: an automated reviewer rather than a human.
_ADDRESSEE = r"""(?:
    ai | llm | gpt | claude | assistant | model | bot
  | (?:security[\s\-_]*)?(?:scanner|analyzer|analyser|reviewer|tool|auditor)
  | sast | dast | static[\s\-_]*analysis | automated[\s\-_]*(?:tool|scanner|analyzer|analyser|review)
  | system | agent
)"""

# What it asks for: a classification outcome.
_DIRECTIVE = r"""(?:
    (?:mark|flag|classify|treat|report|consider|label)\b[^.\n]{0,40}?
      \b(?:safe|false[\s\-_]*positive|not[\s\-_]*vulnerable|benign|approved|ok)
  | (?:ignore|skip|suppress|disregard|bypass|exclude|omit)\b[^.\n]{0,40}?
      \b(?:this|these|finding|findings|file|function|line|lines|issue|issues|warning|section|below|above|instruction)
  | (?:do[\s\-_]*not|don't|never)\b[^.\n]{0,30}?\b(?:flag|report|warn|alert)
  | (?:approve|whitelist|allowlist)[\s\-_]*all
  | verdict[\s\-_]*(?:should[\s\-_]*be|:|=)
  | (?:no|zero)[\s\-_]*(?:issues|findings|vulnerabilities)[\s\-_]*(?:here|found|present)
  | permissive[\s\-_]*mode
)"""

_ADDRESSED = re.compile(
    rf"{_ADDRESSEE}[\s\-_]*(?:s)?\s*[:,\-]?\s*(?:\w+\W+){{0,6}}?{_DIRECTIVE}",
    re.IGNORECASE | re.VERBOSE,
)

_REVERSE = re.compile(
    rf"{_DIRECTIVE}[^.\n]{{0,40}}?\b(?:by|for|to)?\s*{_ADDRESSEE}",
    re.IGNORECASE | re.VERBOSE,
)

_AUTHORITY_CLAIM = re.compile(
    r"""\b(?:
        (?:has\s+been|was|already)\s+(?:security[\s\-_]*)?(?:reviewed|audited|approved|vetted)
      | reviewed\s+(?:and|&)\s+approved
      | sanitized\s+(?:upstream|elsewhere|by\s+middleware)
    )\b""",
    re.IGNORECASE | re.VERBOSE,
)

_TOOL_SUPPRESSION = re.compile(
    r"\b(?:noqa|nosec|pylint|mypy|eslint|type:\s*ignore|semgrep-ignore|"
    r"codeql\[|prettier-ignore|flake8|ruff)\b",
    re.IGNORECASE,
)

# A classic jailbreak phrase that overrides instructions without naming any
# addressee at all ("ignore previous instructions" needs no "AI"/"scanner").
_BARE_JAILBREAK = re.compile(
    r"\bignore\b[^.\n]{0,40}?\b(?:previous|prior|above|earlier|all)\b"
    r"[^.\n]{0,20}?\binstructions?\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class InjectionSignal:
    line: int
    excerpt: str
    reason: str


def _fold(text: str) -> str:
    """Normalize unicode lookalikes and collapse runs of whitespace."""
    decomposed = unicodedata.normalize("NFKD", text)
    ascii_ish = "".join(
        ch for ch in decomposed if not unicodedata.combining(ch)
    )
    swapped = (
        ascii_ish
        .replace("\u0410", "A").replace("\u0430", "a")
        .replace("\u0415", "E").replace("\u0435", "e")
        .replace("\u041e", "O").replace("\u043e", "o")
        .replace("\u0421", "C").replace("\u0441", "c")
        .replace("\u0420", "P").replace("\u0440", "p")
        .replace("\u0406", "I").replace("\u0456", "i")
    )
    return re.sub(r"[ \t]+", " ", swapped)


def scan_for_directives(source: str, start_line: int = 1) -> tuple[InjectionSignal, ...]:
    """Find text in source that addresses an automated reviewer about a verdict."""
    signals: list[InjectionSignal] = []

    for offset, raw_line in enumerate(source.splitlines()):
        line = _fold(raw_line)

        if _TOOL_SUPPRESSION.search(line):
            continue

        reason = None
        if _ADDRESSED.search(line) or _REVERSE.search(line):
            reason = "text addressed to an automated reviewer requesting a verdict"
        elif _AUTHORITY_CLAIM.search(line) and re.search(
            _ADDRESSEE, line, re.IGNORECASE | re.VERBOSE
        ):
            reason = "text addressed to an automated reviewer asserting prior approval"
        elif _BARE_JAILBREAK.search(line):
            reason = "text attempts to override prior instructions"

        if reason:
            excerpt = raw_line.strip()[:_EXCERPT_CHARS]
            signals.append(
                InjectionSignal(line=start_line + offset, excerpt=excerpt, reason=reason)
            )

    return tuple(signals)


def is_suspicious(source: str) -> bool:
    return bool(scan_for_directives(source))