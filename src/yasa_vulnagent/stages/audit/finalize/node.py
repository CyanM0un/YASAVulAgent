"""Audit finalize node."""

from __future__ import annotations

from typing import Any

from ..storage import load_json, paths_from_state, write_final_artifacts


def finalize(state: dict[str, Any], runtime: Any = None) -> dict[str, object]:
    """Write final artifacts using the gate decision."""
    gate = state.get("gate") if isinstance(state.get("gate"), dict) else {}
    if not gate:
        try:
            audit = load_json(paths_from_state(state).audit_file)
        except (OSError, ValueError):
            audit = {}
        gate = audit.get("gate") if isinstance(audit.get("gate"), dict) else {}
    status = str(gate.get("status", "partial"))
    if status not in {"complete", "partial"}:
        status = "partial"
    stop_reason = str(state.get("stop_reason") or gate.get("stop_reason") or "gate")
    framework = dict(state.get("framework") or {})
    executed = list(framework.get("executed", []))
    if not executed or executed[-1] != "finalize":
        executed.append("finalize")
    framework["executed"] = executed
    framework["finalize_done"] = True
    if status == "complete":
        framework["gate_done"] = True
    write_final_artifacts({**state, "status": status, "framework": framework})
    try:
        status = str(load_json(paths_from_state(state).audit_file).get("status", status))
    except (OSError, ValueError):
        pass
    return {
        "status": status,
        "stop_reason": stop_reason,
        "next_action": "finalize",
        "framework": framework,
    }
