from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from .ledger import DiscoverLedger
from .schema import DiscoverState


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid discover state file: {path}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"discover state file must contain an object: {path}")
    return value


def load_previous(state: DiscoverState) -> DiscoverState:
    state_file = Path(state["state_file"])
    if state_file.is_file():
        return cast(DiscoverState, load_json(state_file))
    return state


def persist(state: DiscoverState) -> None:
    write_json(Path(state["state_file"]), state)


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def summarize(state: DiscoverState) -> dict[str, Any]:
    ledger_file = state.get("ledger_file", "")
    if not ledger_file:
        raise ValueError("discover state requires ledger_file")
    with DiscoverLedger.open(Path(str(ledger_file))) as ledger:
        file_counts = ledger.file_counts()
        return {
                "status": state.get("status", "running"),
                "state_file": state.get("state_file", ""),
                "ledger_file": str(ledger_file),
                "artifact_dir": state.get("artifact_dir", ""),
                "source_revision": state.get("source_revision", ""),
                "file_count": file_counts.get("total", 0),
                "screened_file_count": file_counts.get("screened", 0),
                "covered_file_count": file_counts.get("covered", 0),
                "confirmed_entry_count": ledger.count_entries("confirmed"),
                "unknown_entry_count": ledger.count_entries("unknown"),
                "deferred_entry_count": ledger.count_entries("deferred"),
                "candidate_count": ledger.count_entries("candidate"),
                "debt_count": ledger.debt_count(),
                "feature_debt_count": ledger.feature_debt_count(),
                "mechanism_count": ledger.count_mechanisms(),
                "feature_query_count": ledger.count_feature_queries(),
                "feature_hit_count": ledger.count_feature_hits(),
                "deferred_count": ledger.disposition_count("deferred"),
                "handoff_count": len(ledger.open_handoffs()),
                "deferred_items": ledger.disposition_rows(status="deferred")[:200],
                "handoff_items": ledger.open_handoffs()[:200],
                "entry_count": ledger.count_entries(),
                "evidence_count": ledger.count_evidence(),
                "excluded_file_count": ledger.excluded_count(),
                "task_count": ledger.task_count(),
                "pending_task_count": ledger.pending_task_count(),
                "open_task_count": ledger.open_task_count(),
                "screen_initial_wave_complete": bool(
                    state.get("screen", {}).get("initial_wave_complete", False)
                ),
                "screen_wave": int(state.get("screen", {}).get("wave", 0)),
                "next_action": state.get("next_action", ""),
                "loop_guard": {
                    "stalled": bool(state.get("loop_guard", {}).get("stalled", False)),
                    "stall_node": state.get("loop_guard", {}).get("stall_node", ""),
                    "stall_count": int(state.get("loop_guard", {}).get("stall_count", 0)),
                },
                "review_round": state.get("review_round", 0),
                "review_status": state.get("review", {}).get("status", ""),
                "blocking_gap_count": int(state.get("review", {}).get("blocking_gap_count", 0)),
                "prepare": state.get("prepare", {}),
                "gaps": ledger.messages("gaps"),
                "gap_count": ledger.message_count("gaps"),
                "warnings": ledger.messages("warnings"),
                "warning_count": ledger.message_count("warnings"),
                "stop_reason": state.get("stop_reason", ""),
        }

