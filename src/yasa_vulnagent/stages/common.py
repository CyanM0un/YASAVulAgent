from __future__ import annotations

from pathlib import Path
from typing import Any

from ..storage import save_stage_record, save_state, utc_now
from ..workflow.state import RunState, StageRecord


def record_stage(
    name: str,
    state: RunState,
    *,
    status: str,
    message: str,
    started_at: str | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, object]:
    """Persist a real stage record while preserving the outer run contract."""
    return _write_stage_record(
        name=name,
        state=state,
        status=status,
        message=message,
        started_at=started_at or utc_now(),
        finished_at=None if status == "running" else utc_now(),
        details=details,
        replace_existing=True,
    )


def _write_stage_record(
    *,
    name: str,
    state: RunState,
    status: str,
    message: str,
    started_at: str,
    finished_at: str | None,
    details: dict[str, Any] | None = None,
    replace_existing: bool,
) -> dict[str, object]:
    artifact_dir_path = Path(state["stages_dir"]) / name
    artifact_file_path = artifact_dir_path / "stage.json"
    record: StageRecord = {
        "name": name,
        "status": status,
        "started_at": started_at,
        "finished_at": finished_at,
        "message": message,
        "artifact_dir": str(artifact_dir_path),
        "artifact_file": str(artifact_file_path),
    }
    record["details"] = details or {}
    previous = list(state.get("stages", []))
    if replace_existing:
        previous = [item for item in previous if item.get("name") != name]
    update: dict[str, object] = {
        "current_stage": name,
        "stages": [*previous, record],
    }
    save_stage_record(record)
    save_state({**state, **update})
    return update
