from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from .cwe.node import run as run_cwe
from .documents.node import run as run_documents
from .security_history.node import run as run_security_history
from .yasa.node import run as run_yasa
from ...workflow.state import RunContext, RunState


def build_init_graph():
    workflow = StateGraph(RunState, context_schema=RunContext)
    workflow.add_node("yasa", run_yasa)
    workflow.add_node("documents", run_documents)
    workflow.add_node("cwe", run_cwe)
    workflow.add_node("security_history", run_security_history)
    workflow.add_edge(START, "yasa")
    workflow.add_edge("yasa", "documents")
    workflow.add_edge("documents", "cwe")
    workflow.add_edge("cwe", "security_history")
    workflow.add_edge("security_history", END)
    return workflow.compile()
