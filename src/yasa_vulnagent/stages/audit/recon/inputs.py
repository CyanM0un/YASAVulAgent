"""Load and compact the inputs available to audit recon."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ..storage import AuditPaths, load_json, read_business_logic
from .constants import (
    MAX_OVERVIEW_CHARS,
    MAX_SUMMARY_VIEWS,
    MAX_TRACE_VIEWS,
)


@dataclass(frozen=True)
class ReconInputs:
    audit: dict[str, Any]
    scope: dict[str, Any]
    entries: list[dict[str, Any]]
    patches: list[dict[str, Any]]
    tasks: list[dict[str, Any]]
    traces: list[dict[str, Any]]
    summaries: list[dict[str, Any]]
    existing: dict[str, Any]
    mode: str
    overview: str
    source_revision: str
    warnings: list[str]
    limitations: list[str]

    def seed(self) -> dict[str, Any]:
        return {
            "scope": self.scope,
            "overview": self.overview,
            "entries": _compact_objects(self.entries, 30),
            "patches": _compact_objects(self.patches, 30),
            "tasks": [_task_view(task) for task in self.tasks[:60]],
            "traces": [_trace_view(trace) for trace in self.traces[:MAX_TRACE_VIEWS]],
            "summaries": _compact_objects(self.summaries, MAX_SUMMARY_VIEWS),
            "existing_business": _business_view(self.existing),
        }


def load_inputs(state: Mapping[str, Any], paths: AuditPaths) -> ReconInputs:
    audit = _load_audit(paths)
    scope = state.get("scope") if isinstance(state.get("scope"), dict) else {}
    if not scope and isinstance(audit.get("scope"), dict):
        scope = audit["scope"]
    entries = _objects(audit.get("entries") or state.get("entries"))
    patches = _objects(audit.get("patches") or state.get("patches"))
    tasks = _objects(audit.get("tasks") or state.get("tasks"))
    traces = _objects(audit.get("traces") or state.get("traces"))
    summaries = _objects(audit.get("summaries") or state.get("summaries"))
    existing = read_business_logic(paths)
    overview, warnings = _overview(state)
    limitations: list[str] = []
    if not overview:
        limitations.append("project overview is unavailable")
    if existing and not isinstance(existing.get("constraints"), list):
        warnings.append("existing business sidecar is invalid and will be replaced")
        existing = {}
    return ReconInputs(
        audit=audit,
        scope=scope,
        entries=entries,
        patches=patches,
        tasks=tasks,
        traces=traces,
        summaries=summaries,
        existing=existing,
        mode=str(state.get("mode") or audit.get("mode") or "combined"),
        overview=overview,
        source_revision=_source_revision(state, paths),
        warnings=warnings,
        limitations=limitations,
    )


def _source_revision(state: Mapping[str, Any], paths: AuditPaths) -> str:
    prepare = state.get("prepare") if isinstance(state.get("prepare"), dict) else {}
    value = str(prepare.get("source_revision", ""))
    if value:
        return value
    if paths.prepare_file.is_file():
        try:
            value = load_json(paths.prepare_file)
        except (OSError, ValueError):
            return ""
        return str(value.get("source_revision", "")) if isinstance(value, dict) else ""
    return ""


def _overview(state: Mapping[str, Any]) -> tuple[str, list[str]]:
    prepare = state.get("prepare") if isinstance(state.get("prepare"), dict) else {}
    inputs = prepare.get("inputs") if isinstance(prepare.get("inputs"), dict) else {}
    value = str(inputs.get("overview_file", "") or "")
    if not value:
        return "", ["project overview path is unavailable"]
    path = Path(value)
    if not path.is_file():
        return "", [f"project overview is unavailable: {path}"]
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "", [f"project overview is unreadable: {path}"]
    return text[:MAX_OVERVIEW_CHARS], []


def _load_audit(paths: AuditPaths) -> dict[str, Any]:
    if not paths.audit_file.is_file():
        return {}
    try:
        value = load_json(paths.audit_file)
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _objects(value: Any) -> list[dict[str, Any]]:
    return [dict(item) for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _compact_objects(values: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    return [dict(item) for item in values[:limit]]


def _task_view(task: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": task.get("id", ""),
        "kind": task.get("kind", ""),
        "status": task.get("status", ""),
        "entry_ids": list(task.get("entry_ids", []) or []),
        "patch_ids": list(task.get("patch_ids", []) or []),
        "paths": list(task.get("paths", []) or []),
        "origin_task_ids": list(task.get("origin_task_ids", []) or []),
        "business_refs": dict(task.get("business_refs", {}) or {}),
        "question": task.get("question", ""),
    }


def _trace_view(trace: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: trace.get(key)
        for key in (
            "id",
            "task_id",
            "kind",
            "status",
            "summary",
            "coverage_complete",
            "flow_count",
            "summary_count",
            "gaps",
        )
    }


def _business_view(business: Mapping[str, Any]) -> dict[str, Any]:
    if not business:
        return {}
    return {
        key: business.get(key)
        for key in (
            "constraints",
            "operations",
            "investigations",
            "gaps",
            "warnings",
            "limitations",
        )
        if key in business
    }
