"""Select and run registry-driven trace specialists."""

from __future__ import annotations

import asyncio
import json
from typing import Any, Mapping

from .constants import (
    MAX_FOCUS_UNITS,
    MAX_SPECIALISTS,
    SPECIALIST_CONCURRENCY,
    SPECIALIST_MAX_ROUNDS,
)
from .model import load_prompt
from .result import validate_flows, validate_unit_results
from .summaries import validate_candidates


def select_specialists(
    task: Mapping[str, Any],
    triage: Mapping[str, Any],
    execution: Any,
) -> list[dict[str, Any]]:
    registry = execution.registry
    kind = str(task.get("kind", "entry"))
    units = {
        str(unit.get("unit_id", "")): unit
        for unit in triage.get("units", [])
        if isinstance(unit, dict)
    }
    selected: dict[str, dict[str, Any]] = {}
    for delegation in triage.get("delegations", []):
        if not isinstance(delegation, dict):
            continue
        role = str(delegation.get("role", ""))
        spec = registry.get(role)
        if spec is None or not spec.enabled or kind not in spec.applies_to:
            continue
        if not _eligible(spec, task, execution):
            continue
        item = selected.setdefault(
            role,
            {"spec": spec, "units": [], "questions": []},
        )
        unit_id = str(delegation.get("unit_id", ""))
        if unit_id in units and len(item["units"]) < min(spec.max_focus_units, MAX_FOCUS_UNITS):
            if all(str(unit.get("unit_id")) != unit_id for unit in item["units"]):
                item["units"].append(units[unit_id])
        question = str(delegation.get("focus_question", "")).strip()
        if question:
            item["questions"].append(question)
    for spec in registry.mandatory_for(kind):
        if _eligible(spec, task, execution):
            selected.setdefault(spec.id, {"spec": spec, "units": [], "questions": []})
    ordered = sorted(
        selected.values(),
        key=lambda item: (-item["spec"].priority, item["spec"].id),
    )
    return ordered[:MAX_SPECIALISTS]


def _eligible(spec: Any, task: Mapping[str, Any], execution: Any) -> bool:
    if spec.scope != "category":
        return True
    expected = {
        str(check.get("category", ""))
        for check in execution.category_checks_for(task)
        if isinstance(check, dict)
    }
    return bool(set(spec.categories) & expected)


async def run_specialists(
    task: Mapping[str, Any],
    scout: Mapping[str, Any],
    triage: Mapping[str, Any],
    execution: Any,
) -> list[dict[str, Any]]:
    selected = select_specialists(task, triage, execution)
    if not selected:
        return []
    semaphore = asyncio.Semaphore(SPECIALIST_CONCURRENCY)

    async def run(item: dict[str, Any]) -> dict[str, Any]:
        async with semaphore:
            return await _run_one(task, scout, triage, item, execution)

    return list(await asyncio.gather(*(run(item) for item in selected)))


async def _run_one(
    task: Mapping[str, Any],
    scout: Mapping[str, Any],
    triage: Mapping[str, Any],
    item: dict[str, Any],
    execution: Any,
) -> dict[str, Any]:
    spec = item["spec"]
    tools, receipts = execution.tools_for(spec)
    assignment = {
        "task": {
            "id": task.get("id", ""),
            "kind": task.get("kind", ""),
            "paths": task.get("paths", []),
            "entry_ids": task.get("entry_ids", []),
            "patch_ids": task.get("patch_ids", []),
            "repair_unit_refs": task.get("repair_unit_refs", []),
        },
        "assigned_units": item["units"],
        "focus_questions": item["questions"],
        "business": _business_view(execution, task),
        "call_chain": {
            "chains": scout.get("chains", [])[:4],
            "excerpts": scout.get("excerpts", [])[:8],
        },
        "known_summaries": execution.summary_index.all()[:10],
    }
    try:
        payload = await execution.run_json_agent(
            system_prompt=load_prompt(spec.prompt),
            user_prompt=json.dumps(assignment, ensure_ascii=False, indent=2),
            tools=tools,
            max_rounds=SPECIALIST_MAX_ROUNDS,
            stage=f"audit.trace.specialist.{spec.id}",
            task_id=str(task.get("id", "")),
        )
        return _validate_specialist(payload, spec.id, task, execution, receipts)
    except Exception as exc:
        return {
            "role": spec.id,
            "status": "blocked",
            "summary": "",
            "flows": [],
            "observations": [],
            "unit_results": [],
            "summary_candidates": [],
            "gaps": [f"{spec.id} specialist failed: {exc}"],
            "tool_receipts": receipts,
        }


def _validate_specialist(
    payload: Any,
    role: str,
    task: Mapping[str, Any],
    execution: Any,
    receipts: list[dict[str, Any]],
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError(f"{role} specialist output must be an object")
    flows, flow_gaps = validate_flows(
        payload.get("flows"),
        task=task,
        categories=execution.category_ids,
        evidence_index=execution.evidence,
    )
    unit_results, unit_gaps = validate_unit_results(
        payload.get("unit_results"),
        task=task,
        evidence_index=execution.evidence,
    )
    summaries, summary_gaps = validate_candidates(
        payload.get("summary_candidates"),
        task=task,
        evidence_index=execution.evidence,
        repository=execution.repository,
        revision=execution.revision,
        run_id=execution.run_id,
    )
    gaps = [
        *_strings(payload.get("gaps")),
        *flow_gaps,
        *unit_gaps,
        *summary_gaps,
    ]
    return {
        "role": role,
        "status": str(payload.get("status", "complete")),
        "summary": str(payload.get("summary", "")).strip(),
        "flows": flows,
        "observations": _objects(payload.get("observations")),
        "unit_results": unit_results,
        "summary_candidates": summaries,
        "gaps": gaps,
        "tool_receipts": receipts,
    }


def _strings(value: Any) -> list[str]:
    return [item for item in value if isinstance(item, str) and item] if isinstance(value, list) else []


def _objects(value: Any) -> list[dict[str, Any]]:
    return [dict(item) for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _business_view(execution: Any, task: Mapping[str, Any]) -> dict[str, Any]:
    view = getattr(execution, "business_view", None)
    return view(task) if callable(view) else {}
