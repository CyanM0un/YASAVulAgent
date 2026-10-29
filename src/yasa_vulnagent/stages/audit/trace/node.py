"""Audit trace node."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from langgraph.runtime import Runtime

from ....agent.runtime import run_coroutine
from ....config import load_settings
from ....workflow.state import RunContext
from ..budget import AuditBudget
from .execution import run_trace_stage


def trace(state: dict[str, Any], runtime: Runtime[RunContext] | None = None) -> dict[str, object]:
    """Run candidate-chain tracing after recon has completed."""
    framework = dict(state.get("framework") or {})
    if not framework.get("recon_done"):
        return {"next_action": "recon"}
    if not state.get("artifact_dir"):
        return {
            "next_action": "verify",
            "framework": {**framework, "trace_done": True},
        }
    context = runtime.context if runtime is not None else RunContext(settings=load_settings())
    budget = context.audit_budget or AuditBudget.create(context.settings.audit_timeout)
    context = replace(context, audit_budget=budget)
    result = run_coroutine(run_trace_stage(state, context))
    result["next_action"] = "verify"
    result["framework"] = {**framework, **dict(result.get("framework") or {}), "trace_done": True}
    return result
