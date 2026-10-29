"""Bounded, tool-free triage of the current trace frontier."""

from __future__ import annotations

import json
from typing import Any, Mapping

from .constants import MAX_FOCUS_UNITS, TRIAGE_MAX_UNITS
from .model import TraceModelError, load_prompt
from .registry import SpecialistRegistry


async def triage_task(
    task: Mapping[str, Any],
    scout: Mapping[str, Any],
    execution: Any,
) -> dict[str, Any]:
    prompt = {
        "task": {
            "id": task.get("id", ""),
            "kind": task.get("kind", ""),
            "entry_ids": task.get("entry_ids", []),
            "patch_ids": task.get("patch_ids", []),
            "repair_unit_refs": task.get("repair_unit_refs", []),
            "paths": task.get("paths", []),
        },
        "entry": _entry_view(task, execution),
        "patch": _patch_view(task, execution),
        "business": _business_view(execution, task),
        "path_scout": {
            "chains": scout.get("chains", []),
            "excerpts": scout.get("excerpts", []),
            "dynamic_suspected": bool(scout.get("dynamic_suspected")),
            "yasa": scout.get("yasa", {}),
        },
        "known_summaries": execution.summary_index.all()[:20],
        "repair": execution.repair_for(task),
        "known_rejections": execution.rejections.for_task(
            task,
            categories={
                str(check.get("category", ""))
                for check in execution.category_checks_for(task)
            },
            limit=5,
        ),
        "available_specialists": execution.registry.public(str(task.get("kind", "entry"))),
    }
    try:
        result = await execution.run_json_agent(
            system_prompt=load_prompt("triage.md"),
            user_prompt=json.dumps(prompt, ensure_ascii=False, indent=2),
            tools=[],
            max_rounds=1,
            stage="audit.trace.triage",
            task_id=str(task.get("id", "")),
        )
    except Exception as exc:
        return _failed(f"triage model call failed: {exc}")
    try:
        return validate_triage(
            result,
            task=task,
            scout=scout,
            registry=execution.registry,
            summary_ids=execution.summary_index.ids(),
        )
    except TraceModelError as exc:
        return _failed(str(exc))


def validate_triage(
    payload: Any,
    *,
    task: Mapping[str, Any],
    scout: Mapping[str, Any],
    registry: SpecialistRegistry,
    summary_ids: set[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise TraceModelError("triage output must be an object")
    nodes = {
        str(node.get("unit_id", "")): node
        for chain in scout.get("chains", [])
        if isinstance(chain, dict)
        for node in chain.get("nodes", [])
        if isinstance(node, dict) and str(node.get("unit_id", "")).strip()
    }
    raw_units = payload.get("units")
    if not isinstance(raw_units, list):
        raise TraceModelError("triage units must be an array")
    units: list[dict[str, Any]] = []
    gaps: list[str] = []
    seen: set[str] = set()
    for item in raw_units[:TRIAGE_MAX_UNITS]:
        if not isinstance(item, dict):
            gaps.append("triage unit must be an object")
            continue
        unit_id = str(item.get("unit_id", "")).strip()
        node = nodes.get(unit_id)
        if node is None:
            gaps.append(f"triage references unknown unit: {unit_id}")
            continue
        if unit_id in seen:
            continue
        seen.add(unit_id)
        relevance = _choice(item.get("relevance"), {"high", "medium", "low", "not_applicable"}, "medium")
        skip = bool(item.get("skip")) and relevance == "not_applicable"
        if relevance == "not_applicable" and not skip:
            relevance = "medium"
            gaps.append(f"{unit_id}: not_applicable requires skip=true")
        reason = str(item.get("reason", "")).strip()
        reopen = str(item.get("reopen_if", "")).strip()
        if skip and (not reason or not reopen):
            skip = False
            relevance = "medium"
            gaps.append(f"{unit_id}: skip requires reason and reopen_if")
        if skip and (
            str(task.get("kind", "")) == "patch"
            or str(node.get("role", "")) == "entry"
        ):
            skip = False
            relevance = "medium"
            gaps.append(f"{unit_id}: entry and patch units cannot be skipped")
        grounding = _strings(item.get("grounding"))
        if not grounding:
            grounding = [f"unit:{unit_id}"]
        reuse_id = str(item.get("summary_reuse_id", "")).strip()
        if reuse_id and summary_ids is not None and reuse_id not in summary_ids:
            gaps.append(f"{unit_id}: summary_reuse_id is unknown")
            reuse_id = ""
        units.append(
            {
                "unit_id": unit_id,
                "path": str(node.get("path", item.get("path", ""))),
                "function_fqn": str(node.get("function_fqn", item.get("function_fqn", ""))),
                "start_line": int(node.get("start_line", item.get("start_line", 1)) or 1),
                "end_line": int(node.get("end_line", item.get("end_line", 1)) or 1),
                "relevance": relevance,
                "reason": reason,
                "suspected_families": _strings(item.get("suspected_families")),
                "expand": bool(item.get("expand")),
                "skip": skip,
                "summary_reuse_id": reuse_id,
                "summary_candidate": bool(item.get("summary_candidate")),
                "grounding": grounding,
                "reopen_if": reopen,
            }
        )
        if len(units) >= TRIAGE_MAX_UNITS:
            break
    if len(raw_units) > TRIAGE_MAX_UNITS:
        gaps.append(f"triage units truncated at {TRIAGE_MAX_UNITS}")

    raw_delegations = payload.get("delegations")
    allowed_roles = {spec.id for spec in registry.for_kind(str(task.get("kind", "entry")))}
    delegations: list[dict[str, Any]] = []
    per_role: dict[str, int] = {}
    if isinstance(raw_delegations, list):
        for item in raw_delegations:
            if not isinstance(item, dict):
                gaps.append("triage delegation must be an object")
                continue
            role = str(item.get("role", "")).strip()
            unit_id = str(item.get("unit_id", "")).strip()
            if role not in allowed_roles:
                gaps.append(f"triage requested unknown or ineligible role: {role}")
                continue
            if unit_id not in seen:
                gaps.append(f"triage delegated an unknown unit: {unit_id}")
                continue
            question = str(item.get("focus_question", "")).strip()
            if not question:
                gaps.append(f"triage delegation for {unit_id} has no focus question")
                continue
            per_role[role] = per_role.get(role, 0) + 1
            if per_role[role] > MAX_FOCUS_UNITS:
                gaps.append(f"triage delegation for {role} exceeds its focus-unit cap")
                continue
            delegations.append(
                {
                    "role": role,
                    "unit_id": unit_id,
                    "focus_question": question,
                    "priority": _int(item.get("priority"), 1),
                    "grounding": _strings(item.get("grounding")) or [f"unit:{unit_id}"],
                }
            )
    if not units:
        raise TraceModelError("triage produced no usable units")
    return {
        "status": "complete",
        "likely_families": _strings(payload.get("likely_families")),
        "units": units,
        "delegations": delegations,
        "notes": str(payload.get("notes", "")),
        "gaps": gaps,
        "error": "",
    }


def _failed(error: str) -> dict[str, Any]:
    return {
        "status": "failed",
        "likely_families": [],
        "units": [],
        "delegations": [],
        "notes": "",
        "gaps": [error],
        "error": error,
    }


def _entry_view(task: Mapping[str, Any], execution: Any) -> dict[str, Any]:
    result = []
    if str(task.get("kind", "")) != "entry":
        return {}
    for entry_id in task.get("entry_ids", []):
        entry = execution.entries_by_id.get(str(entry_id), {})
        if isinstance(entry, dict):
            result.append(
                {
                    "id": entry.get("id", ""),
                    "name": entry.get("name", ""),
                    "entry_location": entry.get("entry_location", {}),
                    "discovery": entry.get("discovery", {}),
                }
            )
    return result[0] if len(result) == 1 else {"entries": result}


def _patch_view(task: Mapping[str, Any], execution: Any) -> dict[str, Any]:
    result = []
    if str(task.get("kind", "")) != "patch":
        return {}
    for patch_id in task.get("patch_ids", []):
        patch = execution.patches_by_id.get(str(patch_id), {})
        if isinstance(patch, dict):
            result.append(
                {
                    "id": patch.get("id", ""),
                    "commit": patch.get("commit", ""),
                    "changed_paths": patch.get("changed_paths", []),
                    "units": patch.get("units", []),
                    "explanations": patch.get("explanations", []),
                }
            )
    return result[0] if len(result) == 1 else {"patches": result}


def _choice(value: Any, allowed: set[str], default: str) -> str:
    text = str(value or "").strip()
    return text if text in allowed else default


def _strings(value: Any) -> list[str]:
    return [item for item in value if isinstance(item, str) and item] if isinstance(value, list) else []


def _int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _business_view(execution: Any, task: Mapping[str, Any]) -> dict[str, Any]:
    view = getattr(execution, "business_view", None)
    return view(task) if callable(view) else {}
