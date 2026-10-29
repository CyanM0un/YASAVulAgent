from __future__ import annotations

import json
import math
from typing import Any, Iterable


class TokenCounter:
    """Estimate tokens with tiktoken, falling back to a character heuristic."""

    def __init__(self, model: str = "", safety: float = 1.2) -> None:
        self.model = model
        self.safety = max(1.0, float(safety))
        self._encoding: Any | None = None
        self._encoding_failed = False

    def count_text(self, text: str) -> int:
        if not text:
            return 0
        raw = self._raw_count(text)
        return max(1, math.ceil(raw * self.safety))

    def count_json(self, value: Any) -> int:
        return self.count_text(json.dumps(value, ensure_ascii=False, separators=(",", ":")))

    def count_messages(self, messages: Iterable[Any]) -> int:
        total = 0
        for message in messages:
            total += self.count_text(_message_text(message)) + 4
            tool_calls = getattr(message, "tool_calls", None)
            if tool_calls:
                total += self.count_json(tool_calls)
        return total

    def _raw_count(self, text: str) -> int:
        if not self._encoding_failed:
            try:
                if self._encoding is None:
                    import tiktoken

                    self._encoding = tiktoken.get_encoding("cl100k_base")
                return len(self._encoding.encode(text, disallowed_special=()))
            except Exception:
                self._encoding_failed = True
        return max(1, len(text) // 4)

    def _encoding_name(self) -> str:
        return "cl100k_base" if not self._encoding_failed else "char/4"


def _message_text(message: Any) -> str:
    content = getattr(message, "content", message)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict):
                text = block.get("text")
                if isinstance(text, str):
                    parts.append(text)
                else:
                    parts.append(json.dumps(block, ensure_ascii=False))
            else:
                parts.append(str(block))
        return "\n".join(parts)
    return str(content)
