from __future__ import annotations

from typing import Any, TypedDict


class DocumentsState(TypedDict, total=False):
    repository: str
    artifact_dir: str
    deadline: float
    inventory: list[dict[str, Any]]
    notes: list[dict[str, Any]]
    unknowns: list[str]
    document_index: int
    overview: str
    warnings: list[str]
    stop_reason: str
    documents: dict[str, Any]
    chunk_chars: int
    context_chars: int
    fetch_timeout: int
    summary_reserve: int


def parse_json_object(value: str, label: str) -> dict[str, Any]:
    import json

    text = value.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if len(lines) >= 3:
            text = "\n".join(lines[1:-1]).strip()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} did not return a JSON object") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"{label} did not return a JSON object")
    return parsed
