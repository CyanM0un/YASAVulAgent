"""Condition-scoped behavior summaries for trace reuse."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping

from ....storage import utc_now
from ..prepare.inventory import safe_relative
from .constants import SUMMARY_MAX_PER_TASK, SUMMARY_MAX_REUSE
from .result import EvidenceIndex


class SummaryError(ValueError):
    """Raised when a summary cannot be trusted for reuse."""


class SummaryIndex:
    """Valid summaries from the current audit run, keyed by stable id."""

    def __init__(self, summaries: list[dict[str, Any]]) -> None:
        self._items = {
            str(item["id"]): dict(item)
            for item in summaries
            if isinstance(item, dict) and str(item.get("id", "")).strip()
        }

    def get(self, summary_id: str) -> dict[str, Any] | None:
        return self._items.get(str(summary_id))

    def all(self) -> list[dict[str, Any]]:
        return [dict(item) for item in self._items.values()]

    def ids(self) -> set[str]:
        return set(self._items)

    def add(self, summary: dict[str, Any]) -> None:
        summary_id = str(summary.get("id", "")).strip()
        if summary_id:
            self._items[summary_id] = dict(summary)


def build_index(
    summaries: Any,
    *,
    repository: Path,
    revision: str,
) -> SummaryIndex:
    valid: list[dict[str, Any]] = []
    if not isinstance(summaries, list):
        return SummaryIndex([])
    for item in summaries:
        if not isinstance(item, dict):
            continue
        unit = item.get("unit") if isinstance(item.get("unit"), dict) else {}
        path = safe_relative(str(unit.get("path", "")))
        if path is None or not (Path(repository) / path).is_file():
            continue
        if str(unit.get("revision", "")) != revision:
            continue
        if not unit.get("content_hash") or unit.get("content_hash") != _file_hash(
            Path(repository) / path
        ):
            continue
        valid.append(dict(item))
    return SummaryIndex(valid)


def validate_candidates(
    raw: Any,
    *,
    task: Mapping[str, Any],
    evidence_index: EvidenceIndex,
    repository: Path,
    revision: str,
    run_id: str,
) -> tuple[list[dict[str, Any]], list[str]]:
    if not isinstance(raw, list):
        return [], []
    summaries: list[dict[str, Any]] = []
    gaps: list[str] = []
    for index, item in enumerate(raw[: SUMMARY_MAX_PER_TASK * 2]):
        label = f"summary_candidates[{index}]"
        if not isinstance(item, dict):
            gaps.append(f"{label}: summary must be an object")
            continue
        unit = item.get("unit") if isinstance(item.get("unit"), dict) else {}
        path = safe_relative(str(unit.get("path", "")))
        function_fqn = str(unit.get("function_fqn", "")).strip()
        behavior = str(item.get("behavior", "")).strip()
        conditions = _strings(item.get("conditions"))
        evidence, evidence_gaps = evidence_index.hydrate(
            item.get("evidence"), f"{label}.evidence"
        )
        gaps.extend(evidence_gaps)
        if path is None or not function_fqn or not behavior or not conditions:
            gaps.append(f"{label}: path, function_fqn, behavior, and conditions are required")
            continue
        if not evidence:
            gaps.append(f"{label}: summary requires current-source evidence")
            continue
        content_hash = _file_hash(Path(repository) / path)
        summary_id = _summary_id(run_id, revision, path, function_fqn, content_hash)
        summaries.append(
            {
                "id": summary_id,
                "task_id": str(task.get("id", "")),
                "unit": {
                    "kind": str(unit.get("kind", "helper")),
                    "path": path,
                    "function_fqn": function_fqn,
                    "start_line": _int(
                        unit.get("start_line"), evidence[0]["start_line"]
                    ),
                    "end_line": _int(
                        unit.get("end_line"), evidence[0]["end_line"]
                    ),
                    "content_hash": content_hash,
                    "revision": revision,
                },
                "behavior": behavior,
                "inputs": _objects(item.get("inputs")),
                "outputs": _objects(item.get("outputs")),
                "side_effects": _objects(item.get("side_effects")),
                "conditions": conditions,
                "guards": _strings(item.get("guards")),
                "unknowns": _strings(item.get("unknowns")),
                "evidence": evidence,
                "created_at": utc_now(),
                "reuse_count": 0,
            }
        )
        if len(summaries) >= SUMMARY_MAX_PER_TASK:
            gaps.append(f"summary candidates truncated at {SUMMARY_MAX_PER_TASK}")
            break
    return _dedupe(summaries), gaps


def validate_reuse(
    raw: Any,
    *,
    task: Mapping[str, Any],
    index: SummaryIndex,
    flow_ids: set[str],
) -> tuple[list[dict[str, Any]], list[str]]:
    if not isinstance(raw, list):
        return [], []
    records: list[dict[str, Any]] = []
    gaps: list[str] = []
    for index_item in raw:
        if not isinstance(index_item, dict):
            gaps.append("summary reuse record must be an object")
            continue
        summary_id = str(index_item.get("summary_id", "")).strip()
        summary = index.get(summary_id)
        if summary is None:
            gaps.append(f"summary reuse references an unknown summary: {summary_id}")
            continue
        unit = summary.get("unit") if isinstance(summary.get("unit"), dict) else {}
        if not unit.get("path") or not unit.get("function_fqn"):
            gaps.append(f"summary {summary_id}: summary has no usable unit")
            continue
        used_for = str(index_item.get("used_for", "navigation")).strip()
        if used_for not in {"navigation", "check", "flow"}:
            gaps.append(f"summary {summary_id}: invalid used_for")
            continue
        if str(task.get("kind", "")) == "patch" and used_for != "navigation":
            gaps.append(f"summary {summary_id}: patch checks cannot be closed by reuse")
            continue
        match = str(index_item.get("match", "")).strip()
        if match not in {"exact", "partial"}:
            gaps.append(f"summary {summary_id}: invalid match")
            continue
        if used_for in {"check", "flow"} and match != "exact":
            gaps.append(f"summary {summary_id}: partial match cannot close a check or flow")
            continue
        if used_for in {"check", "flow"} and not bool(index_item.get("conditions_checked")):
            gaps.append(f"summary {summary_id}: conditions were not checked")
            continue
        if used_for == "flow" and not bool(index_item.get("source_rechecked")):
            gaps.append(f"summary {summary_id}: flow reuse requires a current-source re-read")
            continue
        refs = _strings(index_item.get("flow_ids"))
        if any(ref not in flow_ids for ref in refs):
            gaps.append(f"summary {summary_id}: references an unknown flow")
            continue
        records.append(
            {
                "summary_id": summary_id,
                "unit": f"{unit.get('path', '')}:{unit.get('function_fqn', '')}",
                "match": match,
                "conditions_checked": bool(index_item.get("conditions_checked")),
                "condition_notes": str(index_item.get("condition_notes", "")),
                "used_for": used_for,
                "source_rechecked": bool(index_item.get("source_rechecked")),
                "flow_ids": refs,
            }
        )
    if len(records) > SUMMARY_MAX_REUSE:
        gaps.append(f"summary reuse truncated at {SUMMARY_MAX_REUSE}")
    return records[:SUMMARY_MAX_REUSE], gaps


def _summary_id(run_id: str, revision: str, path: str, fqn: str, content_hash: str) -> str:
    digest = hashlib.sha256(
        "\0".join([run_id, revision, path, fqn, content_hash]).encode("utf-8")
    ).hexdigest()
    return f"summary-{digest[:16]}"


def _file_hash(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def _dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in items:
        result[str(item["id"])] = item
    return list(result.values())


def _int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _strings(value: Any) -> list[str]:
    return [item for item in value if isinstance(item, str) and item] if isinstance(value, list) else []


def _objects(value: Any) -> list[dict[str, Any]]:
    return [dict(item) for item in value if isinstance(item, dict)] if isinstance(value, list) else []
