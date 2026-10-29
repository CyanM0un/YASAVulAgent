"""Run the trace lead and normalize its candidate-chain output."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from .constants import LEAD_MAX_ROUNDS, MAX_FLOWS_PER_TASK
from .model import load_prompt
from .result import (
    EvidenceIndex,
    validate_category_checks,
    validate_flows,
    validate_mechanism_checks,
    validate_repair_responses,
    validate_unit_results,
)
from .summaries import SummaryIndex, validate_candidates, validate_reuse


async def lead_task(
    task: Mapping[str, Any],
    scout: Mapping[str, Any],
    triage: Mapping[str, Any],
    specialist_results: list[dict[str, Any]],
    execution: Any,
) -> dict[str, Any]:
    tools, receipts = execution.tools_for_task(task)
    prompt = _prompt(task, scout, triage, specialist_results, execution)
    try:
        payload = await execution.run_json_agent(
            system_prompt=load_prompt("prompt.md"),
            user_prompt=json.dumps(prompt, ensure_ascii=False, indent=2),
            tools=tools,
            max_rounds=LEAD_MAX_ROUNDS,
            stage="audit.trace.lead",
            task_id=str(task.get("id", "")),
        )
        return validate_lead(
            payload,
            task=task,
            specialist_results=specialist_results,
            expected_categories=execution.category_checks_for(task),
            expected_mechanisms=execution.mechanism_checks_for(task),
            allowed_categories=(
                execution.category_ids if str(task.get("kind", "")) == "patch" else None
            ),
            evidence_index=execution.evidence,
            summary_index=execution.summary_index,
            repository=execution.repository,
            revision=execution.revision,
            run_id=execution.run_id,
            receipts=receipts,
            repair_debts=execution.repair_for(task).get("debts", []),
        )
    except Exception as exc:
        return _failed(str(exc), specialist_results, receipts)


def validate_lead(
    payload: Any,
    *,
    task: Mapping[str, Any],
    specialist_results: list[dict[str, Any]],
    expected_categories: list[dict[str, Any]],
    expected_mechanisms: list[dict[str, Any]],
    allowed_categories: set[str] | None = None,
    evidence_index: EvidenceIndex,
    summary_index: SummaryIndex,
    repository: Any,
    revision: str,
    run_id: str,
    receipts: list[dict[str, Any]] | None = None,
    repair_debts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("lead output must be an object")
    categories = (
        set(allowed_categories)
        if allowed_categories is not None
        else {str(check.get("category", "")) for check in expected_categories}
    )
    lead_flows, flow_gaps = validate_flows(
        payload.get("flows"),
        task=task,
        categories=categories,
        evidence_index=evidence_index,
    )
    specialist_flows = [
        flow
        for result in specialist_results
        for flow in result.get("flows", [])
        if isinstance(flow, dict)
    ]
    merged_flows = _dedupe_flows([*specialist_flows, *lead_flows])
    flow_gaps.extend(
        [f"flows truncated at {MAX_FLOWS_PER_TASK}"]
        if len(merged_flows) > MAX_FLOWS_PER_TASK
        else []
    )
    flows = merged_flows[:MAX_FLOWS_PER_TASK]
    flow_ids = {str(flow["id"]) for flow in flows}

    unit_results, unit_gaps = validate_unit_results(
        [
            *[
                item
                for result in specialist_results
                for item in result.get("unit_results", [])
                if isinstance(item, dict)
            ],
            *(payload.get("unit_results") or []),
        ],
        task=task,
        evidence_index=evidence_index,
    )
    known_units = {
        (str(item.get("patch_id", "")), str(item.get("unit_id", "")))
        for item in unit_results
    }
    missing_unit_gaps: list[str] = []
    for ref in task.get("repair_unit_refs", []):
        if not isinstance(ref, dict):
            continue
        key = (str(ref.get("patch_id", "")), str(ref.get("unit_id", "")))
        if key in known_units:
            continue
        known_units.add(key)
        unit_results.append(
            {
                "patch_id": key[0],
                "unit_id": key[1],
                "effectiveness": "unknown",
                "reason": "repair unit was not reported",
                "flow_ids": [],
                "evidence": [],
            }
        )
        missing_unit_gaps.append(f"repair unit {key[1]} was not reported")
    category_checks, category_gaps = validate_category_checks(
        payload.get("categories"),
        task=task,
        expected=expected_categories,
        flows=flows,
        evidence_index=evidence_index,
    )
    mechanism_checks, mechanism_gaps = validate_mechanism_checks(
        payload.get("mechanisms"),
        expected=expected_mechanisms,
        flows=flows,
        evidence_index=evidence_index,
        unit_results=unit_results,
    )
    lead_summaries, summary_gaps = validate_candidates(
        payload.get("summaries"),
        task=task,
        evidence_index=evidence_index,
        repository=repository,
        revision=revision,
        run_id=run_id,
    )
    specialist_summaries = [
        summary
        for result in specialist_results
        for summary in result.get("summary_candidates", [])
        if isinstance(summary, dict)
    ]
    summaries = _dedupe_summaries([*specialist_summaries, *lead_summaries])
    reuse, reuse_gaps = validate_reuse(
        payload.get("summary_reuse"),
        task=task,
        index=summary_index,
        flow_ids=flow_ids,
    )
    repair_debts = repair_debts or []
    repair_responses, repair_gaps = validate_repair_responses(
        payload.get("repair_responses"),
        repair_debts,
        evidence_index,
    )
    repair_complete = True
    if repair_debts:
        repair_complete = (
            not repair_gaps
            and all(item.get("status") == "resolved" for item in repair_responses)
        )
    units_closed = (
        all(str(item.get("effectiveness", "unknown")) != "unknown" for item in unit_results)
        if str(task.get("kind", "")) == "patch"
        else True
    )
    if str(task.get("kind", "")) == "logic":
        coverage = bool(flows or summaries) and not flow_gaps
    else:
        coverage = bool(category_checks or mechanism_checks) and all(
            str(check.get("status", "")) == "checked"
            for check in category_checks
        ) and all(
            str(check.get("status", "")) == "checked"
            and str(check.get("outcome", "")) in {"found", "not_found", "not_applicable"}
            for check in mechanism_checks
        ) and units_closed
    gaps = [
        *_strings(payload.get("gaps")),
        *flow_gaps,
        *unit_gaps,
        *missing_unit_gaps,
        *category_gaps,
        *mechanism_gaps,
        *summary_gaps,
        *reuse_gaps,
        *repair_gaps,
    ]
    for check in category_checks:
        if check.get("status") != "checked":
            gaps.append(f"category check pending: {check.get('category', '')}")
    for check in mechanism_checks:
        if check.get("status") != "checked":
            gaps.append(f"mechanism check pending: {check.get('kind', '')}")
    status = str(payload.get("status", "partial"))
    if status not in {"complete", "partial", "blocked"}:
        status = "partial"
    if not coverage and status == "complete":
        status = "partial"
    return {
        "id": _trace_id(run_id, str(task.get("id", ""))),
        "task_id": str(task.get("id", "")),
        "kind": str(task.get("kind", "")),
        "status": status,
        "summary": str(payload.get("summary", "")).strip(),
        "coverage_complete": coverage,
        "entry_results": _objects(payload.get("entry_results")),
        "unit_results": unit_results,
        "flows": flows,
        "categories": category_checks,
        "mechanisms": mechanism_checks,
        "summaries": summaries,
        "summary_reuse": reuse,
        "repair_responses": repair_responses,
        "repair_debt_count": len(repair_debts),
        "repair_resolved_count": sum(
            1 for item in repair_responses if item.get("status") == "resolved"
        ),
        "repair_unresolved_count": sum(
            1 for item in repair_responses if item.get("status") != "resolved"
        ),
        "repair_complete": repair_complete,
        "triage_override": _objects(payload.get("triage_override")),
        "specialist_roles": [str(result.get("role", "")) for result in specialist_results],
        "gaps": gaps,
        "error": "",
        "tool_receipts": receipts or [],
    }


def _prompt(
    task: Mapping[str, Any],
    scout: Mapping[str, Any],
    triage: Mapping[str, Any],
    specialist_results: list[dict[str, Any]],
    execution: Any,
) -> dict[str, Any]:
    return {
        "task": {
            "id": task.get("id", ""),
            "kind": task.get("kind", ""),
            "paths": task.get("paths", []),
            "entry_ids": task.get("entry_ids", []),
            "patch_ids": task.get("patch_ids", []),
            "repair_unit_refs": task.get("repair_unit_refs", []),
        },
        "entry": execution.entry_view(task),
        "patch": execution.patch_view(task),
        "business": _business_view(execution, task),
        "path_scout": {
            "chains": scout.get("chains", [])[:6],
            "excerpts": scout.get("excerpts", [])[:12],
            "yasa": scout.get("yasa", {}),
        },
        "triage": {
            "units": triage.get("units", []),
            "delegations": triage.get("delegations", []),
            "gaps": triage.get("gaps", []),
        },
        "specialists": specialist_results,
        "required_categories": execution.category_checks_for(task),
        "required_mechanisms": execution.mechanism_checks_for(task),
        "category_details": execution.category_details_for(task),
        "known_summaries": execution.summary_index.all()[:20],
        "repair": execution.repair_for(task),
        "known_rejections": execution.rejections.for_task(
            task,
            categories={
                str(check.get("category", ""))
                for check in execution.category_checks_for(task)
            },
            limit=8,
        ),
    }


def _failed(
    error: str,
    specialist_results: list[dict[str, Any]],
    receipts: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "id": "",
        "task_id": "",
        "kind": "",
        "status": "partial",
        "summary": "",
        "coverage_complete": False,
        "entry_results": [],
        "unit_results": [],
        "flows": [
            flow
            for result in specialist_results
            for flow in result.get("flows", [])
            if isinstance(flow, dict)
        ],
        "categories": [],
        "mechanisms": [],
        "summaries": [],
        "summary_reuse": [],
        "triage_override": [],
        "specialist_roles": [str(result.get("role", "")) for result in specialist_results],
        "gaps": [error],
        "error": error,
        "tool_receipts": receipts,
    }


def _trace_id(run_id: str, task_id: str) -> str:
    digest = hashlib.sha256(f"{run_id}\0{task_id}".encode("utf-8")).hexdigest()
    return "trace-" + digest[:16]


def _dedupe_flows(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in items:
        result[str(item.get("id", ""))] = item
    return list(result.values())


def _dedupe_summaries(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in items:
        if item.get("id"):
            result[str(item["id"])] = item
    return list(result.values())[:3]


def _objects(value: Any) -> list[dict[str, Any]]:
    return [dict(item) for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _strings(value: Any) -> list[str]:
    return [item for item in value if isinstance(item, str) and item] if isinstance(value, list) else []


def _business_view(execution: Any, task: Mapping[str, Any]) -> dict[str, Any]:
    view = getattr(execution, "business_view", None)
    return view(task) if callable(view) else {}
