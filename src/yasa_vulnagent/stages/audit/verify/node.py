"""Audit verify node."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from langgraph.runtime import Runtime

from ....agent.runtime import run_coroutine
from ....config import load_settings
from ....workflow.state import RunContext
from ..budget import AuditBudget
from .execution import run_verify_stage


def verify(state: dict[str, Any], runtime: Runtime[RunContext] | None = None) -> dict[str, object]:
    """Verify trace candidates and route remaining debt to the gate."""
    framework = dict(state.get("framework") or {})
    if not state.get("artifact_dir"):
        framework["verify_done"] = True
        return {"next_action": "gate", "framework": framework}
    context = runtime.context if runtime is not None else RunContext(settings=load_settings())
    budget = context.audit_budget or AuditBudget.create(context.settings.audit_timeout)
    context = replace(context, audit_budget=budget)
    result = run_coroutine(run_verify_stage(state, context))
    result["next_action"] = "gate"
    result["framework"] = {
        **framework,
        **dict(result.get("framework") or {}),
        "verify_done": True,
    }
    return result
