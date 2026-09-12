from __future__ import annotations

import os
import random
import time
from dataclasses import dataclass
from typing import Protocol

DEFAULT_MODEL = "claude-sonnet-4-5-20250929"
_RETRYABLE = (429, 500, 502, 503, 529)


class LLMError(Exception):
    """The model could not be reached or returned an unusable response."""


@dataclass(frozen=True)
class ModelReply:
    text: str
    input_tokens: int
    output_tokens: int


class LLMClient(Protocol):
    model_id: str

    def complete(self, prompt: str, max_tokens: int = 1024) -> ModelReply: ...


class AnthropicClient:
    """Thin wrapper over the Messages API. Deterministic, retrying, no streaming."""

    def __init__(
        self,
        model_id: str = DEFAULT_MODEL,
        api_key: str | None = None,
        max_attempts: int = 4,
        timeout: float = 120.0,
    ) -> None:
        import anthropic

        key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise LLMError("ANTHROPIC_API_KEY is not set")

        self.model_id = model_id
        self._max_attempts = max_attempts
        self._client = anthropic.Anthropic(api_key=key, timeout=timeout, max_retries=0)

    def complete(self, prompt: str, max_tokens: int = 1024) -> ModelReply:
        import anthropic

        last: Exception | None = None
        for attempt in range(self._max_attempts):
            try:
                message = self._client.messages.create(
                    model=self.model_id,
                    max_tokens=max_tokens,
                    temperature=0,
                    messages=[{"role": "user", "content": prompt}],
                )
                text = "".join(
                    block.text for block in message.content if block.type == "text"
                )
                return ModelReply(
                    text=text,
                    input_tokens=message.usage.input_tokens,
                    output_tokens=message.usage.output_tokens,
                )
            except anthropic.APIStatusError as exc:
                last = exc
                if exc.status_code not in _RETRYABLE:
                    raise LLMError(f"model refused request: {exc}") from exc
            except anthropic.APIConnectionError as exc:
                last = exc

            time.sleep(min(2**attempt + random.random(), 30))

        raise LLMError(f"model unreachable after {self._max_attempts} attempts: {last}")