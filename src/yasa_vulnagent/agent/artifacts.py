from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .tokens import TokenCounter


class ToolResultStore:
    """Persist full tool results and expose bounded slices by reference."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def save(self, tool: str, arguments: dict[str, Any], result: Any) -> str:
        payload = {
            "tool": tool,
            "arguments": arguments,
            "result": result,
        }
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()[:24]
        path = self.root / f"{digest}.json"
        if not path.exists():
            atomic_write_bytes(path, encoded + b"\n")
        return f"tool-results/{digest}.json"

    def read(self, reference: str, offset: int = 0, limit: int = 4000) -> dict[str, Any]:
        path = self.resolve(reference)
        if path is None:
            return {"error": f"tool result is unavailable: {reference}"}
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return {"error": f"tool result cannot be read: {exc}"}
        text = json.dumps(payload.get("result", payload), ensure_ascii=False, indent=2)
        start = max(0, int(offset))
        end = min(len(text), start + max(1, int(limit)))
        return {
            "artifact_ref": reference,
            "text": text[start:end],
            "offset": start,
            "next_offset": end if end < len(text) else None,
            "total_chars": len(text),
            "truncated": end < len(text),
        }

    def resolve(self, reference: str) -> Path | None:
        candidate = Path(reference)
        if candidate.is_absolute() or ".." in candidate.parts:
            return None
        resolved = (self.root.parent / candidate).resolve()
        if self.root not in resolved.parents and resolved != self.root:
            return None
        return resolved if resolved.is_file() else None


def truncate_text(
    text: str,
    counter: TokenCounter,
    max_tokens: int,
    *,
    head_ratio: float = 0.6,
) -> tuple[str, bool]:
    if max_tokens <= 0 or counter.count_text(text) <= max_tokens:
        return text, False
    # Binary-search the longest prefix/suffix that fits; this keeps both ends.
    head_budget = max(1, int(max_tokens * head_ratio))
    tail_budget = max(1, max_tokens - head_budget)
    head = _take(text, head_budget, counter, from_end=False)
    tail = _take(text, tail_budget, counter, from_end=True)
    return head + "\n\n[...truncated...]\n\n" + tail, True


def _take(text: str, budget: int, counter: TokenCounter, *, from_end: bool) -> str:
    if not text:
        return ""
    low, high = 0, len(text)
    while low < high:
        middle = (low + high + 1) // 2
        candidate = text[-middle:] if from_end else text[:middle]
        if counter.count_text(candidate) <= budget:
            low = middle
        else:
            high = middle - 1
    return text[-low:] if from_end else text[:low]


def atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(tmp_path, path)
    except BaseException:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def atomic_write_json(path: Path, payload: Any, *, sort_keys: bool = False) -> None:
    encoded = (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=sort_keys) + "\n").encode(
        "utf-8"
    )
    atomic_write_bytes(path, encoded)
