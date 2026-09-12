from __future__ import annotations

import hashlib


class TriageCache:
    """In-memory cache keyed on what actually determines a verdict."""

    def __init__(self) -> None:
        self._store: dict[str, object] = {}

    @staticmethod
    def key(instance_id: str, prompt_hash: str, model_id: str) -> str:
        payload = f"{instance_id}\x1f{prompt_hash}\x1f{model_id}".encode()
        return hashlib.sha256(payload).hexdigest()[:32]

    def get(self, key: str):
        return self._store.get(key)

    def put(self, key: str, value) -> None:
        self._store[key] = value