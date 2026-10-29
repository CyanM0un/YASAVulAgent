"""Deterministic audit gate: closure assessment and final routing."""

from __future__ import annotations

from typing import Any

from langgraph.runtime import Runtime

from ....config import load_settings
from ....storage import utc_now
from ....workflow.state import RunContext
from ..budget import AuditBudget
from ..framework import MAX_NODE_VISITS
from ..gaps import make_gap, normalize_gaps, replace_source_gaps
from ..storage import paths_from_state, write_gate_checkpoint
from ..verify.inputs import load_inputs
from .assessment import assess


def gate(state: dict[str, Any], runtime: Runtime[RunContext] | None = None) -> dict[str, object]:
    """Assess audit closure and route to trace, verify, or finalize."""
    framework = dict(state.get("framework") or {})
    if not state.get("artifact_dir"):
        summary = {
            "status": "partial",
            "action": "finalize",
            "stop_reason": "artifact_missing",
            "debt_count": 0,
            "blocking_count": 0,
            "written_at": utc_now(),
        }
        framework["gate_done"] = True
        return {
            "status": "partial",
            "stop_reason": "artifact_missing",
            "next_action": "finalize",
            "gate": summary,
            "framework": framework,
        }

    context = runtime.context if runtime is not None else RunContext(settings=load_settings())
    budget = context.audit_budget or AuditBudget.create(context.settings.audit_timeout)
    paths = paths_from_state(state)
    inputs = load_inputs(state, paths)
    result = assess(inputs, framework)

    for task_id in result.get("reopened", []):
        for task in inputs.tasks:
            if str(task.get("id", "")) == task_id:
                task["status"] = "partial"
                break

    action = str(result.get("action", "finalize"))
    status = str(result.get("status", "partial"))
    stop_reason = str(result.get("stop_reason", "gate_partial"))
    previous = state.get("gate") if isinstance(state.get("gate"), dict) else {}
    if not previous:
        previous = inputs.audit.get("gate") if isinstance(inputs.audit.get("gate"), dict) else {}

    if action != "finalize":
        if budget.expired():
            action = "finalize"
            status = "partial"
            stop_reason = "gate_budget_exhausted"
        elif int(framework.get("visits", {}).get("gate", 0)) >= MAX_NODE_VISITS:
            action = "finalize"
            status = "partial"
            stop_reason = "gate_visit_limit"
        elif previous.get("fingerprint") and previous.get("fingerprint") == result.get("fingerprint"):
            action = "finalize"
            status = "partial"
            stop_reason = "gate_no_progress"
        else:
            status = "partial"
            stop_reason = "gate_pending"

    if action == "finalize":
        status = (
            "complete"
            if not result.get("blocking_count", 0) and stop_reason == "gate_complete"
            else "partial"
        )

    base_gaps = [
        gap
        for gap in normalize_gaps(inputs.audit.get("gaps"))
        if gap["source"] != "gate"
    ]
    gate_gaps = []
    if action == "finalize" and status == "partial":
        for debt in result.get("debts", []):
            if not debt.get("blocking") or debt.get("kind") == "gap":
                continue
            gap = make_gap("gate", str(debt.get("reason", "")), debt.get("paths", []))
            if gap is not None:
                gate_gaps.append(gap)
    gaps = replace_source_gaps(base_gaps, "gate", gate_gaps)

    summary = {
        key: result.get(key)
        for key in (
            "mode",
            "source_revision",
            "debt_count",
            "blocking_count",
            "task_debt_count",
            "check_debt_count",
            "trace_debt_count",
            "finding_debt_count",
            "review_debt_count",
            "business_debt_count",
            "blocked_count",
            "accepted_blocked_count",
            "gap_count",
            "candidate_count",
            "confirmed_count",
            "rejected_count",
            "needs_validation_count",
            "validation_pending",
            "debts",
            "fingerprint",
        )
    }
    summary["gap_count"] = len(gaps)
    summary.update(
        {
            "status": status,
            "action": action,
            "stop_reason": stop_reason,
            "written_at": utc_now(),
        }
    )
    framework["gate_done"] = action == "finalize"
    update = {
        "status": status,
        "stop_reason": stop_reason,
        "next_action": action,
        "tasks": inputs.tasks,
        "gaps": gaps,
        "gate": summary,
        "framework": framework,
    }
    write_gate_checkpoint({**state, **update})
    return update
