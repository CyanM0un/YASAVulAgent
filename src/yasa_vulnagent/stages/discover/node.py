from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from langgraph.errors import GraphRecursionError
from langgraph.runtime import Runtime

from ...agent.usage import UsageRecorder
from ...config import load_settings
from ...observability import trace_node
from ...storage import utc_now
from ...workflow.state import RunContext, RunState
from .ledger import DiscoverLedger
from .schema import DiscoverState, empty_state
from .storage import load_json, persist, summarize, unique


@trace_node("workflow.discover")
def run_stage(
    state: RunState,
    runtime: Runtime[RunContext] | None = None,
) -> dict[str, object]:
    """Run the discover outer graph and persist its durable subgraph state."""
    from .graph import build_discover_graph
    from ..common import record_stage

    context = runtime.context if runtime is not None else RunContext(settings=load_settings())
    if context.usage is None:
        context = replace(context, usage=UsageRecorder(context.settings.usage_price_table))
    started_at = utc_now()
    artifact_dir = Path(state["stages_dir"]) / "discover"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    state_file = artifact_dir / "state.json"
    start_update = record_stage(
        "discover",
        state,
        status="running",
        message="discover graph is running.",
        started_at=started_at,
        details={"state_file": str(state_file)},
    )
    running_state: RunState = {**state, **start_update}
    try:
        discover_state = _load_or_create(running_state, artifact_dir, state_file)
        timeout = int(context.settings.discover_timeout)
        if timeout > 0:
            # Per-invocation deadline, like AUDIT_TIMEOUT: a resumed run gets a fresh window.
            deadline = datetime.now(timezone.utc) + timedelta(seconds=timeout)
            discover_state = {**discover_state, "discover_deadline": deadline.isoformat()}
        result = build_discover_graph().invoke(
            discover_state,
            context=context,
            config={"recursion_limit": context.settings.discover_recursion_limit},
        )
    except GraphRecursionError:
        result = _mark_recursion_limit(discover_state, state_file)
    except Exception as exc:
        record_stage(
            "discover",
            running_state,
            status="failed",
            message="discover graph failed.",
            started_at=started_at,
            details={"state_file": str(state_file), "error": str(exc)},
        )
        raise

    summary = _summary(result)
    if context.usage is not None:
        context.usage.write(artifact_dir / "usage.json", stage_prefix="discover")
        summary["usage"] = context.usage.snapshot()["totals"]
    status = str(result.get("status", "partial"))
    if status not in {"complete", "partial"}:
        status = "partial"
    final_update = record_stage(
        "discover",
        {**running_state, "discover": summary},
        status=status,
        message=(
            "discover completed."
            if status == "complete"
            else "discover outer graph completed with pending work."
        ),
        started_at=started_at,
        details=summary,
    )
    final_update["discover"] = summary
    return final_update


def _load_or_create(run_state: RunState, artifact_dir: Path, state_file: Path) -> DiscoverState:
    if state_file.is_file():
        result = load_json(state_file)
        if not result.get("ledger_file"):
            raise ValueError("discover state is missing its run-local ledger_file")
        persisted: DiscoverState = result
        return persisted
    result = empty_state(
        run_state["repository"],
        str(artifact_dir),
        str(state_file),
        _init_reference(run_state),
    )
    persist(result)
    return result


def _init_reference(run_state: RunState) -> dict[str, Any]:
    records = [item for item in run_state.get("stages", []) if item.get("name") == "init"]
    if not records:
        return {"status": "missing"}
    record = records[-1]
    details = record.get("details", {})
    reference = {
        "status": record.get("status", "unknown"),
        "artifact_dir": record.get("artifact_dir", ""),
        "artifact_file": record.get("artifact_file", ""),
        "gaps": list(details.get("gaps", [])) if isinstance(details, dict) else [],
    }
    if isinstance(details, dict):
        for key in ("checks", "documents", "security_history"):
            if key in details:
                reference[key] = details[key]
        reference["details"] = details
    return reference


def _summary(state: DiscoverState) -> dict[str, Any]:
    return summarize(state)


def _mark_recursion_limit(state: DiscoverState, state_file: Path) -> DiscoverState:
    """Turn a LangGraph step-limit stop into a resumable partial result."""
    latest = load_json(state_file) if state_file.is_file() else dict(state)
    gaps = unique(
        [
            *latest.get("gaps", []),
            "discover graph recursion limit reached before convergence",
        ]
    )
    update: DiscoverState = {
        **latest,
        "status": "partial",
        "stop_reason": "recursion_limit",
        "next_action": "finalize",
        "gaps": gaps,
        "updated_at": utc_now(),
    }
    with DiscoverLedger.open(Path(update["ledger_file"])) as ledger:
        ledger.add_messages(gaps=gaps)
    return finalize(update, force_partial=True)


# Keep the former import surface while the implementation lives in node folders.
from .confirm.node import confirm
from .finalize.node import finalize
from .prepare.node import prepare
from .review.node import review
from .screen.node import screen
