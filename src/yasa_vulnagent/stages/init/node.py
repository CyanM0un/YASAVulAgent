from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from langgraph.runtime import Runtime

from ...config import load_settings
from ...observability import trace_node
from ...agent.usage import UsageRecorder
from ...storage import utc_now
from .graph import build_init_graph
from .index import InitIndex
from ..common import record_stage
from ...workflow.state import RunContext, RunState


@trace_node("workflow.init")
def run_stage(
    state: RunState,
    runtime: Runtime[RunContext] | None = None,
) -> dict[str, object]:
    context = runtime.context if runtime is not None else RunContext(settings=load_settings())
    usage = context.usage or UsageRecorder(context.settings.usage_price_table)
    if context.usage is None:
        context = replace(context, usage=usage)
    started_at = utc_now()
    start_update = record_stage(
        "init",
        state,
        status="running",
        message="init graph is running.",
        started_at=started_at,
    )
    running_state: RunState = {**state, **start_update}
    try:
        child_state = build_init_graph().invoke(running_state, context=context)
    except Exception as exc:
        record_stage(
            "init",
            running_state,
            status="failed",
            message="init graph failed.",
            started_at=started_at,
            details={"error": str(exc)},
        )
        raise

    merged_state: RunState = {**running_state, **child_state}
    details = _init_details(merged_state)
    details["usage"] = usage.snapshot()
    init_dir = Path(state["stages_dir"]) / "init"
    try:
        index = InitIndex(init_dir / "index.sqlite")
        try:
            index.rebuild_documents(init_dir / "documents" / "notes")
            index.rebuild_history(init_dir / "security_history")
        finally:
            index.close()
        details["index_file"] = str((init_dir / "index.sqlite").relative_to(Path(state["stages_dir"]).parent))
    except Exception as exc:
        details["index_error"] = str(exc)
    status = "partial" if details["gaps"] else "complete"
    final_update = record_stage(
        "init",
        merged_state,
        status=status,
        message="init completed with gaps." if status == "partial" else "init completed.",
        started_at=started_at,
        details=details,
    )
    usage_dir = Path(state["stages_dir"]) / "init"
    usage.write(usage_dir / "usage.json")
    for key in ("init_checks", "documents", "security_history"):
        if key in child_state:
            final_update[key] = child_state[key]
    return final_update


def _init_details(state: RunState) -> dict[str, Any]:
    checks = state.get("init_checks", {})
    gaps: list[str] = []
    for name in ("yasa", "cwe"):
        check = checks.get(name)
        if not isinstance(check, dict):
            gaps.append(f"{name}: missing check result")
            continue
        if check.get("status") in {"unavailable", "partial", "failed", "timeout"}:
            reason = str(check.get("reason") or check.get("error") or check.get("status"))
            gaps.append(f"{name}: {reason}")
    for name in ("documents", "security_history"):
        result = state.get(name)
        if not isinstance(result, dict):
            gaps.append(f"{name}: missing stage result")
        elif result.get("status") in {"unavailable", "partial", "failed", "timeout"}:
            gaps.extend(f"{name}: {item}" for item in result.get("gaps", []) if item)
            if result.get("status") == "partial" and not result.get("gaps"):
                gaps.append(f"{name}: partial result")
    return {
        "checks": checks,
        "documents": state.get("documents"),
        "security_history": state.get("security_history"),
        "gaps": _unique(gaps),
    }


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))
