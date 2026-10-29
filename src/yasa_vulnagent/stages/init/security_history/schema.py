from __future__ import annotations

import json
from typing import Any, TypedDict


class SecurityHistoryState(TypedDict, total=False):
    repository: str
    artifact_dir: str
    deadline: float
    discovery_deadline: float
    snapshot: dict[str, Any]
    candidates: list[dict[str, Any]]
    reviews: list[dict[str, Any]]
    patch_results: list[dict[str, Any]]
    warnings: list[str]
    discovery_unknowns: list[str]
    discovery_truncated: bool
    security_history: dict[str, Any]


class PatchState(TypedDict, total=False):
    repository: str
    artifact_dir: str
    candidate: dict[str, Any]
    review: dict[str, Any]
    deadline: float
    changed_paths: list[dict[str, Any]]
    diff_chunks: list[dict[str, Any]]
    units: list[dict[str, Any]]
    notes: list[str]
    graph: dict[str, Any]
    validation: dict[str, Any]
    correction_attempted: bool
    correction_log: list[dict[str, Any]]
    status: str
    error: str


def parse_json_object(value: str, label: str) -> dict[str, Any]:
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


def as_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]
