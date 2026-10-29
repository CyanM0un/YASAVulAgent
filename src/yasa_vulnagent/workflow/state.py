from __future__ import annotations

from dataclasses import dataclass
from typing import Any, TypedDict

from ..config import Settings


STAGE_NAMES = ("init", "discover", "audit", "validate", "report")


class StageRecord(TypedDict):
    name: str
    status: str
    started_at: str
    finished_at: str | None
    message: str
    artifact_dir: str
    artifact_file: str
    details: dict[str, Any]


class RunState(TypedDict, total=False):
    run_id: str
    repository: str
    output_dir: str
    run_file: str
    stages_dir: str
    started_at: str
    finished_at: str
    status: str
    current_stage: str
    stages: list[StageRecord]
    config: dict[str, Any]
    init_checks: dict[str, Any]
    documents: dict[str, Any]
    security_history: dict[str, Any]
    discover: dict[str, Any]
    audit: dict[str, Any]
    audit_mode: str
    environment: dict[str, Any]
    validation: dict[str, Any]
    validation_environment_mode: str
    validation_finding_ids: list[str]
    validation_rerun: bool
    report: dict[str, Any]
    report_finding_ids: list[str]
    report_rerun: bool
    error: str


@dataclass(frozen=True)
class RunContext:
    """Ephemeral runtime dependencies; secrets never enter RunState."""

    settings: Settings
    model: Any | None = None
    progress: Any | None = None
    screen_runtime: Any | None = None
    usage: Any | None = None
    trace_runtime: Any | None = None
    audit_budget: Any | None = None
    docker: Any | None = None
