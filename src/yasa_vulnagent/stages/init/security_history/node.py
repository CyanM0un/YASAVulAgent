from __future__ import annotations

import time
from pathlib import Path

from langgraph.runtime import Runtime

from ....config import load_settings
from ....observability import trace_node
from ....workflow.state import RunContext, RunState
from .graph import build_security_history_graph
from .schema import SecurityHistoryState


@trace_node("init.security_history")
def run(
    state: RunState,
    runtime: Runtime[RunContext] | None = None,
) -> dict[str, object]:
    """Run historical Git evidence collection and return its durable index."""
    context = runtime.context if runtime is not None else RunContext(settings=load_settings())
    artifact_dir = Path(state["stages_dir"]) / "init" / "security_history"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    child_state: SecurityHistoryState = {
        "repository": state["repository"],
        "artifact_dir": str(artifact_dir),
        "deadline": time.monotonic() + context.settings.history_timeout,
        "candidates": [],
        "reviews": [],
        "patch_results": [],
        "warnings": [],
        "discovery_unknowns": [],
        "discovery_truncated": False,
    }
    result = build_security_history_graph().invoke(child_state, context=context)
    if context.usage is not None:
        context.usage.write(artifact_dir / "usage.json", "init.security_history")
    return {"security_history": result.get("security_history", {})}
