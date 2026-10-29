"""LangGraph state machine for Docker environment construction."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from langgraph.graph import END, START, StateGraph
from langgraph.runtime import Runtime

from ....workflow.state import RunContext
from .build import build_node
from .diagnose import diagnose_node
from .gate import gate_node
from .manifest import classify_node, finalize_node, snapshot_node
from .plan import plan_node
from .preflight import preflight_node
from .schema import EnvironmentState
from .smoke import smoke_node
from .storage import persist_state

Node = Callable[..., dict[str, Any]]
logger = logging.getLogger(__name__)

_MAX_NODE_VISITS = 12
_ALLOWED_ACTIONS = {
    "preflight": {"plan", "classify"},
    "plan": {"plan_gate", "classify"},
    "plan_gate": {"build", "plan", "classify"},
    "build": {"smoke", "diagnose", "classify"},
    "smoke": {"snapshot", "diagnose", "classify"},
    "diagnose": {"plan", "classify"},
    "snapshot": {"finalize", "classify"},
    "classify": {"finalize"},
    "finalize": {"finalize"},
}


def build_environment_graph():
    workflow = StateGraph(EnvironmentState, context_schema=RunContext)
    workflow.add_node("preflight", _with_transition("preflight", preflight_node))
    workflow.add_node("plan", _with_transition("plan", plan_node))
    workflow.add_node("plan_gate", _with_transition("plan_gate", gate_node))
    workflow.add_node("build", _with_transition("build", build_node))
    workflow.add_node("smoke", _with_transition("smoke", smoke_node))
    workflow.add_node("diagnose", _with_transition("diagnose", diagnose_node))
    workflow.add_node("snapshot", _with_transition("snapshot", snapshot_node))
    workflow.add_node("classify", _with_transition("classify", classify_node))
    workflow.add_node("finalize", _with_transition("finalize", finalize_node))

    workflow.add_edge(START, "preflight")
    workflow.add_conditional_edges("preflight", _route, {"plan": "plan", "classify": "classify"})
    workflow.add_conditional_edges("plan", _route, {"plan_gate": "plan_gate", "classify": "classify"})
    workflow.add_conditional_edges(
        "plan_gate",
        _route,
        {"build": "build", "plan": "plan", "classify": "classify"},
    )
    workflow.add_conditional_edges(
        "build",
        _route,
        {"smoke": "smoke", "diagnose": "diagnose", "classify": "classify"},
    )
    workflow.add_conditional_edges(
        "smoke",
        _route,
        {"snapshot": "snapshot", "diagnose": "diagnose", "classify": "classify"},
    )
    workflow.add_conditional_edges("diagnose", _route, {"plan": "plan", "classify": "classify"})
    workflow.add_conditional_edges(
        "snapshot",
        _route,
        {"finalize": "finalize", "classify": "classify"},
    )
    workflow.add_edge("classify", "finalize")
    workflow.add_edge("finalize", END)
    return workflow.compile()


def _with_transition(node_name: str, node: Node) -> Node:
    def wrapped(
        state: EnvironmentState,
        runtime: Runtime[RunContext] | None = None,
    ) -> dict[str, Any]:
        raw = node(state, runtime)
        update = {**dict(state), **dict(raw or {})}
        requested = str(update.get("next_action", ""))
        allowed = _ALLOWED_ACTIONS[node_name]
        action = requested or next(iter(allowed))
        if action not in allowed:
            raise ValueError(f"environment node {node_name} requested invalid action: {action}")
        visits = dict(update.get("visits", {}))
        visits[node_name] = int(visits.get(node_name, 0)) + 1
        executed = list(update.get("executed_nodes", []))
        if not executed or executed[-1] != node_name:
            executed.append(node_name)
        if node_name not in {"finalize", "classify"} and visits[node_name] > _MAX_NODE_VISITS:
            action = "classify"
            update["stop_reason"] = "node_visit_limit"
            update["errors"] = [*update.get("errors", []), f"{node_name} exceeded the visit limit"]
        update["next_action"] = action
        update["visits"] = visits
        update["executed_nodes"] = executed
        if update.get("state_file"):
            persist_state(update)
        logger.info(
            "environment route node=%s next=%s attempt=%s plan=%s status=%s",
            node_name,
            action,
            update.get("attempt", 0),
            update.get("plan_revision", 0),
            update.get("status", ""),
        )
        return update

    return wrapped


def _route(state: EnvironmentState) -> str:
    return str(state.get("next_action", "classify"))
