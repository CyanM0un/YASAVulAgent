from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from ..stages.audit.node import run_stage as audit_stage
from ..stages.discover.node import run_stage as discover_stage
from ..stages.init.node import run_stage as init_stage
from ..stages.report.node import run_stage as report_stage
from ..stages.validate.node import run_stage as validate_stage
from .state import RunContext, RunState


def build_graph():
    workflow = StateGraph(RunState, context_schema=RunContext)
    workflow.add_node("init", init_stage)
    workflow.add_node("discover", discover_stage)
    workflow.add_node("audit", audit_stage)
    workflow.add_node("validate", validate_stage)
    workflow.add_node("report", report_stage)
    workflow.add_edge(START, "init")
    workflow.add_edge("init", "discover")
    workflow.add_edge("discover", "audit")
    workflow.add_edge("audit", "validate")
    workflow.add_edge("validate", "report")
    workflow.add_edge("report", END)
    return workflow.compile()
