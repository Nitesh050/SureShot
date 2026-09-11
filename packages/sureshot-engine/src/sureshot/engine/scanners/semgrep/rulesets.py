from __future__ import annotations

from sureshot.domain.repository import RepositoryProfile

BASE_RULESETS = ("p/security-audit", "p/secrets")

LANGUAGE_RULESETS: dict[str, str] = {
    "Python": "p/python",
    "JavaScript": "p/javascript",
    "TypeScript": "p/typescript",
    "Java": "p/java",
    "Go": "p/golang",
    "Ruby": "p/ruby",
    "PHP": "p/php",
    "C": "p/c",
    "C++": "p/c",
    "C#": "p/csharp",
    "Kotlin": "p/kotlin",
    "Scala": "p/scala",
    "Rust": "p/rust",
    "Terraform": "p/terraform",
}


def select_rulesets(profile: RepositoryProfile | None) -> tuple[str, ...]:
    """Choose Semgrep rule packs for a repository, deterministically."""
    if profile is None:
        return BASE_RULESETS

    packs = {
        LANGUAGE_RULESETS[stat.name]
        for stat in profile.languages
        if stat.name in LANGUAGE_RULESETS
    }
    return BASE_RULESETS + tuple(sorted(packs))