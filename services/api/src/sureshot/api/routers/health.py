from __future__ import annotations

import os
import shutil

from fastapi import APIRouter

from sureshot.engine.scanners.registry import available_scanners

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict:
    return {"status": "ok"}


@router.get("/capabilities")
def capabilities() -> dict:
    """Which scanners and LLM backends this server can actually use, so the
    UI can grey out the ones that would only degrade."""
    return {
        "scanners": [
            {"name": name, "installed": shutil.which(name) is not None}
            for name in available_scanners()
        ],
        "llm": {
            "anthropic": bool(os.environ.get("ANTHROPIC_API_KEY")),
            "ollama": True,
        },
    }
