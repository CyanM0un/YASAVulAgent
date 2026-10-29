from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from .config import Settings
from .workflow.state import STAGE_NAMES, RunState, StageRecord


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_run_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{timestamp}-{uuid.uuid4().hex[:8]}"


def create_run(
    repository: Path,
    output_dir: Path | None,
    settings: Settings,
    audit_mode: str | None = None,
) -> RunState:
    repo = repository.expanduser().resolve()
    if not repo.is_dir():
        raise ValueError(f"repository is not a directory: {repo}")

    runs_root = (output_dir or repo / ".yasa-vulnagent" / "runs").expanduser().resolve()
    runs_root.mkdir(parents=True, exist_ok=True)
    run_id = _new_run_id()
    run_dir = runs_root / run_id
    run_dir.mkdir()
    stages_dir = run_dir / "stages"
    stages_dir.mkdir()
    for stage_name in STAGE_NAMES:
        (stages_dir / stage_name).mkdir()

    state: RunState = {
        "run_id": run_id,
        "repository": str(repo),
        "output_dir": str(runs_root),
        "run_file": str(run_dir / "run.json"),
        "stages_dir": str(stages_dir),
        "started_at": utc_now(),
        "status": "running",
        "current_stage": "",
        "stages": [],
        "audit_mode": audit_mode or settings.audit_mode,
        "config": settings.safe_dict(),
    }
    save_state(state)
    return state


def save_state(state: RunState) -> None:
    destination = Path(state["run_file"])
    temporary = destination.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(destination)


def save_stage_record(record: StageRecord) -> None:
    destination = Path(record["artifact_file"])
    temporary = destination.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(destination)


def load_state(path: Path) -> RunState:
    return cast(RunState, json.loads(path.read_text(encoding="utf-8")))


def mark_failed(state: RunState, error: Exception) -> RunState:
    failed: RunState = {
        **state,
        "status": "failed",
        "finished_at": utc_now(),
        "error": str(error),
    }
    save_state(failed)
    return failed
