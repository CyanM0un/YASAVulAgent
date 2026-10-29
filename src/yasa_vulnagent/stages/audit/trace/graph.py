"""Per-task trace state graph."""

from __future__ import annotations

import hashlib
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.runtime import Runtime

from ....workflow.state import RunContext
from ..storage import write_trace_artifact
from .constants import TRIAGE_ROUNDS
from .execution import TraceExecution
from .lead import lead_task
from .path_scout import expand_frontier, scout_task
from .result import compact_trace
from .specialist_runner import run_specialists
from .triage import triage_task


class TraceTaskState(TypedDict, total=False):
    task: dict[str, Any]
    scout: dict[str, Any]
    triage: dict[str, Any]
    triage_round: int
    expand_units: list[dict[str, Any]]
    specialist_results: list[dict[str, Any]]
    lead_result: dict[str, Any]
    outcome: dict[str, Any]
    status: str
    error: str


async def run_trace_task(
    task: dict[str, Any],
    execution: TraceExecution,
    paths: Any = None,
) -> dict[str, Any]:
    graph = build_trace_task_graph()
    result = await graph.ainvoke(
        {"task": task, "triage_round": 0},
        context=_context(execution),
    )
    return dict(result.get("outcome") or {})


def build_trace_task_graph():
    workflow = StateGraph(TraceTaskState, context_schema=RunContext)
    workflow.add_node("prepare_task", _prepare_task)
    workflow.add_node("path_scout", _path_scout)
    workflow.add_node("triage", _triage)
    workflow.add_node("expand", _expand)
    workflow.add_node("specialists", _specialists)
    workflow.add_node("lead", _lead)
    workflow.add_node("validate_persist", _validate_persist)

    workflow.add_edge(START, "prepare_task")
    workflow.add_conditional_edges(
        "prepare_task",
        _after_prepare,
        {"path_scout": "path_scout", "validate_persist": "validate_persist"},
    )
    workflow.add_edge("path_scout", "triage")
    workflow.add_conditional_edges(
        "triage",
        _after_triage,
        {"expand": "expand", "specialists": "specialists", "lead": "lead"},
    )
    workflow.add_edge("expand", "triage")
    workflow.add_edge("specialists", "lead")
    workflow.add_edge("lead", "validate_persist")
    workflow.add_edge("validate_persist", END)
    return workflow.compile()


def _context(execution: TraceExecution) -> RunContext:
    return RunContext(
        settings=execution.settings,
        model=execution.model,
        usage=execution.usage,
        trace_runtime=execution,
        audit_budget=execution.audit_budget,
    )


async def _prepare_task(state: TraceTaskState, runtime: Runtime[RunContext]) -> dict[str, Any]:
    execution = _execution(runtime)
    task = dict(state.get("task") or {})
    task_id = str(task.get("id", ""))
    if not task_id:
        return {"error": "task has no id", "status": "failed"}
    if execution.audit_budget.expired():
        return {"error": "audit budget exhausted", "status": "deferred"}
    if str(task.get("status", "planned")) in {"complete", "blocked"}:
        return {"error": "task is already terminal", "status": "deferred"}
    return {"status": "running", "triage_round": int(state.get("triage_round", 0))}


async def _path_scout(state: TraceTaskState, runtime: Runtime[RunContext]) -> dict[str, Any]:
    execution = _execution(runtime)
    try:
        scout = await scout_task(state["task"], execution)
        return {"scout": scout}
    except Exception as exc:
        return {
            "scout": {
                "chains": [],
                "excerpts": [],
                "dynamic_suspected": True,
                "yasa": {"status": "unavailable"},
            },
            "error": f"path scout failed: {exc}",
        }


async def _triage(state: TraceTaskState, runtime: Runtime[RunContext]) -> dict[str, Any]:
    execution = _execution(runtime)
    try:
        triage = await triage_task(state["task"], state.get("scout") or {}, execution)
    except Exception as exc:
        triage = {
            "status": "failed",
            "units": [],
            "delegations": [],
            "gaps": [f"triage failed: {exc}"],
            "error": str(exc),
        }
    triage["rounds"] = int(state.get("triage_round", 0)) + 1
    units = [
        unit for unit in triage.get("units", [])
        if isinstance(unit, dict) and unit.get("expand") and not unit.get("skip")
    ]
    return {
        "triage": triage,
        "expand_units": units,
        "triage_round": int(state.get("triage_round", 0)) + 1,
    }


async def _expand(state: TraceTaskState, runtime: Runtime[RunContext]) -> dict[str, Any]:
    execution = _execution(runtime)
    try:
        scout = await expand_frontier(
            state["task"],
            state.get("scout") or {},
            state.get("expand_units") or [],
            execution,
        )
        return {"scout": scout, "expand_units": []}
    except Exception as exc:
        triage = dict(state.get("triage") or {})
        triage.setdefault("gaps", []).append(f"frontier expansion failed: {exc}")
        return {"triage": triage, "expand_units": []}


async def _specialists(state: TraceTaskState, runtime: Runtime[RunContext]) -> dict[str, Any]:
    execution = _execution(runtime)
    results = await run_specialists(
        state["task"],
        state.get("scout") or {},
        state.get("triage") or {},
        execution,
    )
    return {"specialist_results": results}


async def _lead(state: TraceTaskState, runtime: Runtime[RunContext]) -> dict[str, Any]:
    execution = _execution(runtime)
    result = await lead_task(
        state["task"],
        state.get("scout") or {},
        state.get("triage") or {},
        state.get("specialist_results") or [],
        execution,
    )
    return {"lead_result": result}


async def _validate_persist(
    state: TraceTaskState,
    runtime: Runtime[RunContext],
) -> dict[str, Any]:
    execution = _execution(runtime)
    task = dict(state.get("task") or {})
    lead = dict(state.get("lead_result") or {})
    triage = dict(state.get("triage") or {})
    error = str(state.get("error", ""))
    if not lead:
        lead = {
            "id": _trace_id(execution.run_id, str(task.get("id", ""))),
            "task_id": str(task.get("id", "")),
            "kind": str(task.get("kind", "")),
            "status": "failed" if error else "partial",
            "summary": "",
            "coverage_complete": False,
            "entry_results": [],
            "unit_results": [],
            "flows": [],
            "categories": [],
            "mechanisms": [],
            "summaries": [],
            "summary_reuse": [],
            "triage_override": [],
            "specialist_roles": [],
            "gaps": [error] if error else [],
            "error": error,
        }
    lead["id"] = str(lead.get("id") or _trace_id(execution.run_id, str(task.get("id", ""))))
    lead["task_id"] = str(task.get("id", ""))
    lead["kind"] = str(task.get("kind", ""))
    lead["categories"] = _fill_checks(
        lead.get("categories"),
        execution.category_checks_for(task),
    )
    lead["mechanisms"] = _fill_mechanisms(
        lead.get("mechanisms"),
        execution.mechanism_checks_for(task),
    )
    if state.get("triage") is None:
        lead.setdefault("gaps", []).append("triage did not run")
    if error:
        lead.setdefault("gaps", []).append(error)
    lead["coverage_complete"] = _coverage(lead, task) and not error
    status = str(lead.get("status", "partial"))
    if status not in {"complete", "partial", "blocked"}:
        status = "partial"
    if (not lead["coverage_complete"] or error) and status == "complete":
        status = "partial"
    lead["status"] = status
    artifact_file = f"traces/{lead['id']}.json"
    artifact = write_trace_artifact(
        _paths(execution),
        {
            **lead,
            "task": task,
            "scout": _safe_scout(state.get("scout") or {}),
            "triage": triage,
            "specialist_results": state.get("specialist_results") or [],
            "artifact_file": artifact_file,
        },
    )
    compact = compact_trace(task, lead, artifact_file=artifact, triage=triage)
    outcome = {
        "status": status,
        "trace": compact,
        "category_checks": lead.get("categories", []),
        "mechanism_checks": lead.get("mechanisms", []),
        "unit_results": lead.get("unit_results", []),
        "summaries": lead.get("summaries", []),
        "summary_reuse": lead.get("summary_reuse", []),
        "specialist_roles": lead.get("specialist_roles", []),
        "flows": lead.get("flows", []),
        "gaps": lead.get("gaps", []),
        "error": error,
    }
    return {"outcome": outcome, "status": status}


def _coverage(lead: dict[str, Any], task: dict[str, Any]) -> bool:
    categories = lead.get("categories", [])
    mechanisms = lead.get("mechanisms", [])
    units = lead.get("unit_results", [])
    if str(task.get("kind", "")) == "logic":
        return bool(lead.get("flows") or lead.get("summaries"))
    if not (categories or mechanisms):
        return False
    if any(str(check.get("status", "")) != "checked" for check in categories):
        return False
    if any(
        str(check.get("status", "")) != "checked"
        or str(check.get("outcome", "")) not in {"found", "not_found", "not_applicable"}
        for check in mechanisms
    ):
        return False
    if str(task.get("kind", "")) == "patch":
        return all(
            str(unit.get("effectiveness", "unknown")) != "unknown"
            for unit in units
        )
    return True


def _safe_scout(scout: dict[str, Any]) -> dict[str, Any]:
    return {
        **scout,
        "excerpts": [
            {
                key: value
                for key, value in item.items()
                if key != "text"
            }
            for item in scout.get("excerpts", [])
            if isinstance(item, dict)
        ],
    }


def _after_prepare(state: TraceTaskState) -> str:
    return "validate_persist" if state.get("error") else "path_scout"


def _after_triage(state: TraceTaskState) -> str:
    triage = state.get("triage") or {}
    if triage.get("status") == "failed":
        return "lead"
    if state.get("expand_units") and int(state.get("triage_round", 0)) < TRIAGE_ROUNDS:
        return "expand"
    return "specialists"


def _execution(runtime: Runtime[RunContext]) -> TraceExecution:
    execution = runtime.context.trace_runtime
    if not isinstance(execution, TraceExecution):
        raise RuntimeError("trace runtime is unavailable")
    return execution


def _paths(execution: TraceExecution) -> Any:
    from ..storage import audit_paths

    return audit_paths(execution.audit_dir.parent)


def _trace_id(run_id: str, task_id: str) -> str:
    digest = hashlib.sha256(f"{run_id}\0{task_id}".encode("utf-8")).hexdigest()
    return "trace-" + digest[:16]


def _fill_checks(raw: Any, expected: list[dict[str, Any]]) -> list[dict[str, Any]]:
    values = {
        str(item.get("id", "")): dict(item)
        for item in raw
        if isinstance(item, dict) and item.get("id")
    } if isinstance(raw, list) else {}
    result = []
    for check in expected:
        item = values.get(str(check.get("id", "")))
        if item is None:
            item = {
                **check,
                "status": "pending",
                "applicability": "unknown",
                "reason": "trace did not produce this check",
                "flow_ids": [],
                "evidence": [],
            }
        result.append(item)
    return result


def _fill_mechanisms(raw: Any, expected: list[dict[str, Any]]) -> list[dict[str, Any]]:
    values = {
        str(item.get("id", "")): dict(item)
        for item in raw
        if isinstance(item, dict) and item.get("id")
    } if isinstance(raw, list) else {}
    result = []
    for check in expected:
        item = values.get(str(check.get("id", "")))
        if item is None:
            item = {
                **check,
                "status": "pending",
                "outcome": "unknown",
                "reason": "trace did not produce this check",
                "flow_ids": [],
                "unit_results": [],
                "evidence": [],
            }
        result.append(item)
    return result
