from __future__ import annotations

import logging
from pathlib import Path

from langgraph.runtime import Runtime

from ....storage import utc_now
from ....observability import trace_node
from ....workflow.state import RunContext
from ..ledger import DiscoverLedger
from ..schema import DiscoverState
from ..storage import persist, summarize, write_json


logger = logging.getLogger(__name__)


@trace_node("discover.finalize")
def finalize(
    state: DiscoverState,
    runtime: Runtime[RunContext] | None = None,
    *,
    force_partial: bool = False,
) -> dict[str, object]:
    """Write the discover index and expose a compact hand-off to later stages."""
    del runtime
    with DiscoverLedger.open(Path(state["ledger_file"])) as ledger:
        screen_state = state.get("screen", {})
        review_state = state.get("review", {})
        debt_count = ledger.debt_count()
        handoff_count = len(ledger.open_handoffs())
        blocking_gap_count = int(review_state.get("blocking_gap_count", 0))
        complete = (
            not force_partial
            and bool(screen_state.get("initial_wave_complete"))
            and debt_count == 0
            # Handoffs have their own lifecycle; keep this explicit even though
            # an unresolved handoff is normally also counted as debt.
            and handoff_count == 0
            and review_state.get("status") == "complete"
            and review_state.get("route") == "finalize"
            and blocking_gap_count == 0
        )
        update: DiscoverState = {
            **state,
            "current_node": "finalize",
            "next_action": "finalize",
            "status": "complete" if complete else "partial",
            "file_count": ledger.file_count(),
            "screened_file_count": ledger.file_counts().get("screened", 0),
            "covered_file_count": ledger.file_counts().get("covered", 0),
            "task_count": ledger.task_count(),
            "pending_task_count": ledger.pending_task_count(),
            "open_task_count": ledger.open_task_count(),
            "entry_count": ledger.count_entries(),
            "confirmed_entry_count": ledger.count_entries("confirmed"),
            "unknown_entry_count": ledger.count_entries("unknown"),
            "deferred_entry_count": ledger.count_entries("deferred"),
            "evidence_count": ledger.count_evidence(),
            "debt_count": debt_count,
            "feature_debt_count": ledger.feature_debt_count(),
            "mechanism_count": ledger.count_mechanisms(),
            "feature_query_count": ledger.count_feature_queries(),
            "feature_hit_count": ledger.count_feature_hits(),
            "deferred_count": ledger.disposition_count("deferred"),
            "handoff_count": handoff_count,
            "deferred_items": ledger.disposition_rows(status="deferred")[:200],
            "handoff_items": ledger.open_handoffs()[:200],
            "gap_count": ledger.message_count("gaps"),
            "warning_count": ledger.message_count("warnings"),
            "gaps": ledger.messages("gaps"),
            "warnings": ledger.messages("warnings"),
            "stop_reason": "complete"
            if complete
            else (state.get("stop_reason") or "partial"),
            "updated_at": utc_now(),
        }
        summary = summarize({**update, "status": update["status"]})
        update["summary"] = summary
        ledger.export_inventory(Path(update["artifact_dir"]))
        write_json(
            Path(update["artifact_dir"]) / "confirmed-entries.json",
            ledger.entries(status="confirmed"),
        )
    persist(update)
    artifact_dir = Path(update["artifact_dir"])
    write_json(artifact_dir / "index.json", summary)
    logger.info(
        "discover finalize status=%s files=%s entries=%s gaps=%s",
        update["status"],
        summary["file_count"],
        summary["confirmed_entry_count"],
        len(summary["gaps"]),
    )
    return update
