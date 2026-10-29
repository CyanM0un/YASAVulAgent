"""Audit recon node."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from langgraph.runtime import Runtime

from ....agent.runtime import run_coroutine
from ....config import load_settings
from ....workflow.state import RunContext
from ..budget import AuditBudget
from .execution import run_recon_stage


def recon(state: dict[str, Any], runtime: Runtime[RunContext] | None = None) -> dict[str, object]:
    """Recover business records and route them to the second trace pass."""
    framework = dict(state.get("framework") or {})
    recon_summary = state.get("recon") if isinstance(state.get("recon"), dict) else {}
    business_file = Path(str(state.get("business_file") or ""))
    if (
        framework.get("recon_done")
        and str(recon_summary.get("status", "")) == "complete"
        and business_file.is_file()
    ):
        return {"next_action": "trace", "framework": framework}
    if not state.get("artifact_dir"):
        framework["recon_done"] = True
        return {"next_action": "trace", "framework": framework}
    context = runtime.context if runtime is not None else RunContext(settings=load_settings())
    budget = context.audit_budget or AuditBudget.create(context.settings.audit_timeout)
    context = replace(context, audit_budget=budget)
    result = run_coroutine(run_recon_stage(state, context))
    result["next_action"] = "trace"
    result["framework"] = {
        **framework,
        **dict(result.get("framework") or {}),
        "recon_done": True,
    }
    return result
