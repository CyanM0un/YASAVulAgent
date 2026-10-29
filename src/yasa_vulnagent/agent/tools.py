from __future__ import annotations

import json
from typing import Any

from .artifacts import ToolResultStore, truncate_text
from .tokens import TokenCounter


def normalize_result(result: Any) -> Any:
    if isinstance(result, (dict, list, str, int, float, bool)) or result is None:
        return result
    return str(result)


def render_result(
    *,
    tool: str,
    arguments: dict[str, Any],
    result: Any,
    counter: TokenCounter,
    max_tokens: int,
    store: ToolResultStore | None,
) -> tuple[str, dict[str, Any]]:
    """Return model-facing content and a compact receipt."""
    payload = normalize_result(result)
    text = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False)
    receipt: dict[str, Any] = {"tool": tool, "status": "ok"}
    for key in ("path", "source", "range", "start_line", "end_line", "total_lines", "start_page", "end_page", "start_block", "end_block", "next_line", "next_page", "next_block", "next_cursor", "next_char"):
        if isinstance(payload, dict) and key in payload and payload[key] is not None:
            receipt[key] = payload[key]
    if isinstance(payload, dict):
        if payload.get("error"):
            receipt["status"] = "error"
        if payload.get("status"):
            receipt["status"] = str(payload["status"])
        inner = payload.get("text")
        if isinstance(inner, str):
            compact, truncated = truncate_text(inner, counter, max_tokens)
            payload = {**payload, "text": compact, "truncated": bool(payload.get("truncated") or truncated)}
            if truncated:
                receipt["truncated"] = True
            if truncated and store is not None:
                reference = store.save(tool, arguments, normalize_result(result))
                payload["artifact_ref"] = reference
                receipt["artifact_ref"] = reference
            receipt["chars"] = len(inner)
            text = json.dumps(payload, ensure_ascii=False)
            return text, receipt
    compact, truncated = truncate_text(text, counter, max_tokens)
    if truncated:
        receipt["truncated"] = True
        if store is not None:
            reference = store.save(tool, arguments, normalize_result(result))
            receipt["artifact_ref"] = reference
            text = json.dumps(
                {
                    "text": compact,
                    "truncated": True,
                    "artifact_ref": reference,
                    "original_chars": len(text),
                },
                ensure_ascii=False,
            )
        else:
            text = compact
    return text, receipt


def parse_arguments(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}
