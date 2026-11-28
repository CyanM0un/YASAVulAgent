"""Condition-scoped behavior summaries for trace reuse."""

from __future__ import annotations

import hashlib
import threading
from pathlib import Path
from typing import Any, Iterable, Mapping

from ....storage import utc_now
from ..prepare.inventory import safe_relative
from .constants import SUMMARY_MAX_PER_TASK, SUMMARY_MAX_REUSE
from .result import EvidenceIndex


class SummaryError(ValueError):
    """Raised when a summary cannot be trusted for reuse."""


class SummaryIndex:
    """Valid summaries from the current audit run, keyed by stable id."""

    def __init__(self, summaries: list[dict[str, Any]]) -> None:
        self._lock = threading.Lock()
        self._items = {
            str(item["id"]): dict(item)
            for item in summaries
            if isinstance(item, dict) and str(item.get("id", "")).strip()
        }

    def get(self, summary_id: str) -> dict[str, Any] | None:
        with self._lock:
            item = self._items.get(str(summary_id))
            return dict(item) if item is not None else None

    def all(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self._items.values()]

    def ids(self) -> set[str]:
        with self._lock:
            return set(self._items)

    def add(self, summary: Mapping[str, Any]) -> None:
        summary_id = str(summary.get("id", "")).strip()
        if not summary_id:
            return
        with self._lock:
            self._items[summary_id] = dict(summary)

    def add_many(self, summaries: Iterable[Any]) -> None:
        with self._lock:
            for item in summaries:
                if isinstance(item, Mapping):
                    summary_id = str(item.get("id", "")).strip()
                    if summary_id:
                        self._items[summary_id] = dict(item)

    def for_task(
        self,
        task: Mapping[str, Any],
        scout: Mapping[str, Any] | None = None,
        *,
        limit: int = 8,
        compact: bool = True,
    ) -> list[dict[str, Any]]:
        """Return only summaries relevant to this task's call chains or paths."""
        task_paths = {str(path).strip() for path in (task.get("paths") or []) if str(path).strip()}
        chain_paths: set[str] = set()
        chain_fqns: set[str] = set()
        chain_short_names: set[str] = set()
        if isinstance(scout, Mapping):
            for chain in scout.get("chains") or []:
                if not isinstance(chain, Mapping):
                    continue
                for node in chain.get("nodes") or []:
                    if not isinstance(node, Mapping):
                        continue
                    node_path = str(node.get("path", "")).strip()
                    if node_path:
                        chain_paths.add(node_path)
                    fqn = str(node.get("function_fqn", "")).strip()
                    if fqn:
                        chain_fqns.add(fqn)
                        short = fqn.rsplit(".", 1)[-1].rsplit("/", 1)[-1]
                        if short:
                            chain_short_names.add(short)
        all_paths = task_paths | chain_paths
        parent_dirs = {
            str(Path(path).parent).replace("\\", "/")
            for path in all_paths
            if str(Path(path).parent) not in {"", "."}
        }
        if not (all_paths or chain_fqns):
            return []

        with self._lock:
            snapshot = list(self._items.values())

        scored: list[tuple[int, str, dict[str, Any]]] = []
        for item in snapshot:
            unit = item.get("unit") if isinstance(item.get("unit"), Mapping) else {}
            unit_path = str(unit.get("path", "")).strip()
            unit_fqn = str(unit.get("function_fqn", "")).strip()
            unit_short = unit_fqn.rsplit(".", 1)[-1].rsplit("/", 1)[-1] if unit_fqn else ""
            score = 0
            if unit_fqn and (
                unit_fqn in chain_fqns
                or (unit_short and unit_short in chain_short_names and unit_path in all_paths)
            ):
                score += 4
            if unit_path and unit_path in chain_paths:
                score += 3
            if unit_path and unit_path in task_paths:
                score += 2
            if unit_path:
                unit_dir = str(Path(unit_path).parent).replace("\\", "/")
                if unit_dir in parent_dirs:
                    score += 1
            if score > 0:
                scored.append((score, str(item.get("id", "")), item))

        scored.sort(key=lambda entry: (-entry[0], entry[1]))
        selected = [entry[2] for entry in scored[: max(1, int(limit))]]
        return [_compact_summary(item) if compact else dict(item) for item in selected]


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
        if len(summaries) >= SUMMARY_MAX_PER_TASK:
            gaps.append(f"summary candidates truncated at {SUMMARY_MAX_PER_TASK}")
            break
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


def _compact_summary(item: Mapping[str, Any]) -> dict[str, Any]:
    unit = item.get("unit") if isinstance(item.get("unit"), Mapping) else {}
    anchors: list[str] = []
    for ev in item.get("evidence") or []:
        if not isinstance(ev, Mapping):
            continue
        path = str(ev.get("path", "")).strip()
        if not path:
            continue
        start = ev.get("start_line")
        end = ev.get("end_line")
        anchor = f"{path}:{start}-{end}" if start and end else path
        if anchor not in anchors:
            anchors.append(anchor)
        if len(anchors) >= 4:
            break
    return {
        "id": str(item.get("id", "")),
        "task_id": str(item.get("task_id", "")),
        "unit": {
            "kind": str(unit.get("kind", "helper")),
            "path": str(unit.get("path", "")),
            "function_fqn": str(unit.get("function_fqn", "")),
            "start_line": int(unit.get("start_line", 0) or 0),
            "end_line": int(unit.get("end_line", 0) or 0),
        },
        "behavior": str(item.get("behavior", ""))[:400],
        "conditions": [str(c)[:160] for c in (item.get("conditions") or [])[:6] if c],
        "guards": [str(g)[:160] for g in (item.get("guards") or [])[:6] if g],
        "unknowns": [str(u)[:160] for u in (item.get("unknowns") or [])[:4] if u],
        "evidence_anchors": anchors,
    }
