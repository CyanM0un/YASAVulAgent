from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

from langgraph.graph import END, START, StateGraph
from langgraph.runtime import Runtime

from ...workflow.state import RunContext
from .confirm.node import confirm
from .finalize.node import finalize
from .prepare.node import prepare
from .review.node import review
from .screen.node import screen
from .schema import DiscoverState
from .ledger import DiscoverLedger
from .storage import persist, unique


_ROUTE_NAMES = frozenset({"screen", "confirm", "review", "finalize"})
_ROUTES = {name: name for name in _ROUTE_NAMES}
Node = Callable[..., dict[str, object]]
logger = logging.getLogger(__name__)


def build_discover_graph():
    workflow = StateGraph(DiscoverState, context_schema=RunContext)
    workflow.add_node("prepare", _with_transition("prepare", prepare))
    workflow.add_node("screen", _with_transition("screen", screen))
    workflow.add_node("confirm", _with_transition("confirm", confirm))
    workflow.add_node("review", _with_transition("review", review))
    workflow.add_node("finalize", _with_transition("finalize", finalize))
    workflow.add_edge(START, "prepare")
    workflow.add_edge("prepare", "screen")
    workflow.add_conditional_edges("screen", _route_after_screen, _ROUTES)
    workflow.add_conditional_edges("confirm", _route_after_confirm, _ROUTES)
    workflow.add_conditional_edges("review", _route_after_review, _ROUTES)
    workflow.add_edge("finalize", END)
    return workflow.compile()


def _with_transition(node_name: str, node: Node) -> Node:
    """Apply the outer routing contract after each stage node executes."""

    def wrapped(
        state: DiscoverState,
        runtime: Runtime[RunContext] | None = None,
    ) -> dict[str, object]:
        raw = node(state, runtime)
        update = {**state, **(dict(raw) if raw else {})}
        if node_name == "prepare" and not update.get("loop_guard"):
            update["loop_guard"] = {}
            requested_action = "screen"
        else:
            requested_action = str(raw.get("next_action", "")) if raw else ""
            if not requested_action:
                requested_action = _default_next_action(node_name, update)
        update = _record_transition(update, node_name, requested_action)
        if update.get("ledger_file"):
            with DiscoverLedger.open(Path(str(update["ledger_file"]))) as ledger:
                update["gap_count"] = ledger.message_count("gaps")
                update["gaps"] = ledger.messages("gaps")
        if update.get("state_file"):
            persist(update)  # type: ignore[arg-type]
        logger.info(
            "discover route node=%s next=%s stalled=%s stop_reason=%s",
            node_name,
            update["next_action"],
            update["loop_guard"].get("stalled", False),
            update.get("stop_reason", ""),
        )
        return update

    return wrapped


def _default_next_action(node_name: str, state: DiscoverState) -> str:
    if node_name == "prepare":
        return "screen"
    if node_name == "screen":
        return "confirm"
    if node_name == "confirm":
        return "review"
    if node_name == "review":
        return "confirm" if state.get("follow_up_required") else "finalize"
    return "finalize"


def _record_transition(
    state: DiscoverState,
    node_name: str,
    requested_action: str,
) -> DiscoverState:
    if requested_action not in _ROUTE_NAMES:
        raise ValueError(f"discover node {node_name} requested invalid action: {requested_action}")

    fingerprint = _business_fingerprint(state)
    previous = state.get("loop_guard", {})
    immediate_repeat = (
        requested_action != "finalize"
        and previous.get("last_node") == node_name
        and previous.get("last_fingerprint") == fingerprint
    )
    cycle_repeat = (
        requested_action != "finalize"
        and node_name == "review"
        and previous.get("cycle_fingerprint") == fingerprint
    )
    repeated = immediate_repeat or cycle_repeat
    cycle_fingerprint = previous.get("cycle_fingerprint", "")
    if node_name == "review":
        cycle_fingerprint = fingerprint if requested_action != "finalize" else ""
    guard: dict[str, Any] = {
        "last_node": node_name,
        "last_fingerprint": fingerprint,
        "stalled": repeated,
        "stall_node": node_name if repeated else "",
        "stall_count": int(previous.get("stall_count", 0)) + 1 if repeated else 0,
        "cycle_fingerprint": cycle_fingerprint,
    }
    gaps = list(state.get("gaps", []))
    stop_reason = state.get("stop_reason", "")
    action = requested_action
    if repeated:
        action = "finalize"
        stop_reason = "no_progress"
        message = f"{node_name} requested another pass without changing discover work state"
        gaps = unique([*gaps, message])
        ledger_file = state.get("ledger_file", "")
        if ledger_file:
            with DiscoverLedger.open(Path(str(ledger_file))) as ledger:
                ledger.add_messages(gaps=[message])
    return {
        **state,
        "next_action": action,
        "loop_guard": guard,
        "gaps": gaps,
        "stop_reason": stop_reason,
    }


def _business_fingerprint(state: DiscoverState) -> str:
    ledger_digest = ""
    ledger_file = state.get("ledger_file", "")
    if ledger_file:
        with DiscoverLedger.open(Path(str(ledger_file))) as ledger:
            ledger_digest = ledger.business_digest()
    payload = {
        "ledger": ledger_digest,
        "screen": {
            key: value
            for key, value in dict(state.get("screen", {})).items()
            if key not in {"last_wave", "planner", "waves_without_new_candidate", "wave"}
        },
        "prepare": state.get("prepare", {}),
    }
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _route_after_screen(state: DiscoverState) -> str:
    return _route_for("screen", state)


def _route_after_confirm(state: DiscoverState) -> str:
    return _route_for("confirm", state)


def _route_after_review(state: DiscoverState) -> str:
    return _route_for("review", state)


def _route_for(node_name: str, state: DiscoverState) -> str:
    action = str(state.get("next_action", "")) or _default_next_action(node_name, state)
    if action not in _ROUTE_NAMES:
        raise ValueError(f"discover {node_name} produced invalid next action: {action}")
    return action
