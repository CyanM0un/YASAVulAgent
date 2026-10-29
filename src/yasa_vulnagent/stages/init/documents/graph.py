from __future__ import annotations

import time

from langgraph.graph import END, START, StateGraph

from ....workflow.state import RunContext
from .node import discover, read_document, summarize
from .schema import DocumentsState


def build_documents_graph():
    workflow = StateGraph(DocumentsState, context_schema=RunContext)
    workflow.add_node("discover", discover)
    workflow.add_node("read", read_document)
    workflow.add_node("summarize", summarize)
    workflow.add_edge(START, "discover")
    workflow.add_edge("discover", "read")
    workflow.add_conditional_edges(
        "read",
        _next_node,
        {"read": "read", "summarize": "summarize"},
    )
    workflow.add_edge("summarize", END)
    return workflow.compile()


def _next_node(state: DocumentsState) -> str:
    inventory = state.get("inventory", [])
    index = state.get("document_index", 0)
    remaining = state.get("deadline", 0.0) - time.monotonic()
    reserve = state.get("summary_reserve", 180)
    if index < len(inventory) and remaining > reserve:
        return "read"
    return "summarize"
