from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

_DIR = Path(__file__).parent
_PLACEHOLDER = re.compile(r"\{(\w+)\}")


class PromptNotFound(Exception):
    """No prompt template exists for the requested name and version."""


@dataclass(frozen=True)
class Prompt:
    version: str
    hash: str
    template: str

    def render(self, **values: object) -> str:
        required = set(_PLACEHOLDER.findall(self.template))
        missing = required - set(values)
        if missing:
            raise KeyError(f"prompt {self.version} missing values: {sorted(missing)}")
        return self.template.format(**values)


@lru_cache(maxsize=32)
def load_prompt(name: str, version: str) -> Prompt:
    path = _DIR / f"{name}.{version}.md"
    if not path.is_file():
        raise PromptNotFound(f"no prompt at {path.name}")
    template = path.read_text(encoding="utf-8")
    digest = hashlib.sha256(template.encode("utf-8")).hexdigest()[:16]
    return Prompt(version=f"{name}.{version}", hash=digest, template=template)


def list_prompts() -> tuple[tuple[str, str], ...]:
    found = []
    for path in sorted(_DIR.glob("*.md")):
        name, version = path.stem.rsplit(".", 1)
        found.append((name, version))
    return tuple(found)