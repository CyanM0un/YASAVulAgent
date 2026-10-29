"""Load the bounded inputs available to audit verify."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from ..storage import (
    AuditPaths,
    load_json,
    paths_from_state,
    read_business_logic,
    read_trace_artifact,
)


@dataclass(frozen=True)
class VerifyInputs:
    audit: dict[str, Any]
    scope: dict[str, Any]
    entries: list[dict[str, Any]]
    patches: list[dict[str, Any]]
    tasks: list[dict[str, Any]]
    traces: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    reviews: list[dict[str, Any]]
    business: dict[str, Any]
    trace_artifacts: dict[str, dict[str, Any]]
    mode: str
    source_revision: str
    run_id: str
    gaps: list[str] = field(default_factory=list)

    def entry_for(self, task: Mapping[str, Any]) -> dict[str, Any]:
        values = [
            item for item in self.entries if str(item.get("id", "")) in set(task.get("entry_ids", []))
        ]
        return values[0] if len(values) == 1 else {"entries": values}

    def patch_for(self, task: Mapping[str, Any]) -> dict[str, Any]:
        values = [
            item for item in self.patches if str(item.get("id", "")) in set(task.get("patch_ids", []))
        ]
        return values[0] if len(values) == 1 else {"patches": values}

    def business_for(self, task: Mapping[str, Any]) -> dict[str, Any]:
        refs = task.get("business_refs") if isinstance(task.get("business_refs"), dict) else {}
        if not refs:
            return {}
        return {
            key: [
                item
                for item in self.business.get(key, [])
                if isinstance(item, dict) and str(item.get("id", "")) in set(refs.get(key, []))
            ]
            for key in ("constraints", "operations", "investigations")
        }


def load_inputs(state: Mapping[str, Any], paths: AuditPaths | None = None) -> VerifyInputs:
    paths = paths or paths_from_state(state)
    audit = _load_audit(paths)
    scope = state.get("scope") if isinstance(state.get("scope"), dict) else {}
    if not scope and isinstance(audit.get("scope"), dict):
        scope = audit["scope"]
    entries = _objects(audit.get("entries") or state.get("entries"))
    patches = _objects(audit.get("patches") or state.get("patches"))
    tasks = _objects(audit.get("tasks") or state.get("tasks"))
    traces = _objects(audit.get("traces") or state.get("traces"))
    findings = _objects(audit.get("findings") or state.get("findings"))
    reviews = _objects(audit.get("reviews") or state.get("reviews"))
    source_revision = _source_revision(state, paths)
    gaps: list[str] = []
    artifacts: dict[str, dict[str, Any]] = {}
    for trace in traces:
        trace_id = str(trace.get("id", "")).strip()
        if not trace_id:
            gaps.append("trace record has no id")
            continue
        full = read_trace_artifact(paths, trace_id)
        if full is None:
            gaps.append(f"trace artifact is unavailable: {trace_id}")
            continue
        artifacts[trace_id] = full
    return VerifyInputs(
        audit=audit,
        scope=scope,
        entries=entries,
        patches=patches,
        tasks=tasks,
        traces=traces,
        findings=findings,
        reviews=reviews,
        business=read_business_logic(paths),
        trace_artifacts=artifacts,
        mode=str(state.get("mode") or audit.get("mode") or "combined"),
        source_revision=source_revision,
        run_id=str(state.get("run_id") or audit.get("run_id") or ""),
        gaps=gaps,
    )


def _load_audit(paths: AuditPaths) -> dict[str, Any]:
    if not paths.audit_file.is_file():
        return {}
    try:
        return load_json(paths.audit_file)
    except (OSError, ValueError):
        return {}


def _source_revision(state: Mapping[str, Any], paths: AuditPaths) -> str:
    prepare = state.get("prepare") if isinstance(state.get("prepare"), dict) else {}
    value = str(prepare.get("source_revision", ""))
    if value:
        return value
    if paths.prepare_file.is_file():
        try:
            return str(load_json(paths.prepare_file).get("source_revision", ""))
        except (OSError, ValueError):
            return ""
    return ""


def _objects(value: Any) -> list[dict[str, Any]]:
    return [dict(item) for item in value if isinstance(item, dict)] if isinstance(value, list) else []
