"""Outer audit graph.

The graph shape is stable; node bodies live in their own subpackages. This
module keeps routing and transition bookkeeping centralized.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from langgraph.graph import END, START, StateGraph
from langgraph.runtime import Runtime

from ...workflow.state import RunContext
from .finalize.node import finalize
from .framework import MAX_NODE_VISITS
from .gate.node import gate
from .plan.node import plan
from .prepare.node import prepare
from .recon.node import recon
from .schema import AuditState
from .storage import persist_audit_state
from .trace.node import trace
from .verify.node import verify


Node = Callable[..., dict[str, object]]
logger = logging.getLogger(__name__)

_DEFAULT_ACTIONS = {
    "prepare": "plan",
    "plan": "trace",
    "trace": "recon",
    "recon": "trace",
    "verify": "gate",
    "gate": "finalize",
    "finalize": "finalize",
}
_ALLOWED_ACTIONS = {
    "prepare": {"plan"},
    "plan": {"trace"},
    "trace": {"trace", "recon", "verify", "gate"},
    "recon": {"trace"},
    "verify": {"trace", "verify", "gate"},
    "gate": {"trace", "verify", "recon", "finalize"},
    "finalize": {"finalize"},
}
_TRACE_ROUTES = {name: name for name in ("trace", "recon", "verify", "gate")}
_VERIFY_ROUTES = {name: name for name in ("trace", "verify", "gate")}
_GATE_ROUTES = {name: name for name in ("trace", "verify", "recon", "finalize")}


def build_audit_graph():
    workflow = StateGraph(AuditState, context_schema=RunContext)
    workflow.add_node("prepare", _with_transition("prepare", prepare))
    workflow.add_node("plan", _with_transition("plan", plan))
    workflow.add_node("trace", _with_transition("trace", trace))
    workflow.add_node("recon", _with_transition("recon", recon))
    workflow.add_node("verify", _with_transition("verify", verify))
    workflow.add_node("gate", _with_transition("gate", gate))
    workflow.add_node("finalize", _with_transition("finalize", finalize))

    workflow.add_edge(START, "prepare")
    workflow.add_edge("prepare", "plan")
    workflow.add_edge("plan", "trace")
    workflow.add_conditional_edges("trace", _route_after_trace, _TRACE_ROUTES)
    workflow.add_edge("recon", "trace")
    workflow.add_conditional_edges("verify", _route_after_verify, _VERIFY_ROUTES)
    workflow.add_conditional_edges("gate", _route_after_gate, _GATE_ROUTES)
    workflow.add_edge("finalize", END)
    return workflow.compile()


def _with_transition(node_name: str, node: Node) -> Node:
    """Apply routing validation and persist state after each node."""

    def wrapped(
        state: AuditState,
        runtime: Runtime[RunContext] | None = None,
    ) -> dict[str, object]:
        raw = node(state, runtime)
        update = {**state, **(dict(raw) if raw else {})}
        requested = str(update.get("next_action", ""))
        update = _record_transition(update, node_name, requested)
        if update.get("state_file"):
            persist_audit_state(update)  # type: ignore[arg-type]
        logger.info(
            "audit route node=%s next=%s stop_reason=%s",
            node_name,
            update.get("next_action", ""),
            update.get("stop_reason", ""),
        )
        return update

    return wrapped


def _record_transition(
    state: AuditState,
    node_name: str,
    requested_action: str,
) -> AuditState:
    action = requested_action or _DEFAULT_ACTIONS[node_name]
    warnings = list(state.get("warnings", []))
    if action == "finalize" and node_name in {"trace", "verify"}:
        action = "gate"
        warnings.append(f"{node_name} cannot finalize directly; routed through gate")

    allowed = _ALLOWED_ACTIONS[node_name]
    if action not in allowed:
        raise ValueError(f"audit node {node_name} requested invalid action: {action}")

    framework = dict(state.get("framework") or {})
    executed = list(framework.get("executed", []))
    if not (node_name == "finalize" and executed and executed[-1] == "finalize"):
        executed.append(node_name)
    visits = dict(framework.get("visits", {}))
    visits[node_name] = int(visits.get(node_name, 0)) + 1

    stop_reason = str(state.get("stop_reason", ""))
    if node_name not in {"gate", "finalize"} and visits[node_name] > MAX_NODE_VISITS:
        action = "gate"
        stop_reason = "node_visit_limit"
        warnings.append(f"{node_name} exceeded the node visit limit")

    framework.update({"executed": executed, "visits": visits})
    return {
        **state,
        "framework": framework,
        "next_action": action,
        "stop_reason": stop_reason,
        "warnings": list(dict.fromkeys(warnings)),
    }


def _route_after_trace(state: AuditState) -> str:
    return str(state.get("next_action", "recon"))


def _route_after_verify(state: AuditState) -> str:
    return str(state.get("next_action", "gate"))


def _route_after_gate(state: AuditState) -> str:
    return str(state.get("next_action", "finalize"))
