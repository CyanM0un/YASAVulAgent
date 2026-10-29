from __future__ import annotations

from pathlib import Path
from typing import Any, TypedDict


class FileRecord(TypedDict, total=False):
    path: str
    size: int
    fingerprint: str
    content_type: str
    kind: str
    usage_hint: str
    source_origin: str
    large: bool
    status: str
    task_ids: list[str]
    entry_ids: list[str]
    error: str


class TaskRecord(TypedDict, total=False):
    task_id: str
    kind: str
    status: str
    origin: str
    candidate_ids: list[str]
    follow_up_key: str
    parent_task_id: str
    paths: list[str]
    scope_paths: list[str]
    scope_type: str
    scope_prefix: str
    scope_count: int
    coverage_required: bool
    artifact_dir: str
    question: str
    attempts: int
    depends_on: list[str]
    stale_reason: str
    wave: int
    view: str
    independent: bool
    read_ranges: list[dict[str, Any]]
    tool_receipts: list[dict[str, Any]]
    candidates: list[dict[str, Any]]
    scope_proposals: list[dict[str, Any]]
    priority: str
    negative_results: list[dict[str, Any]]
    unknowns: list[str]
    deferred: list[str]
    deferred_items: list[dict[str, Any]]
    follow_up: list[dict[str, Any]]
    follow_up_items: list[dict[str, Any]]
    feature_observations: list[dict[str, Any]]
    derived_processed: bool
    entry_results: list[dict[str, Any]]
    same_file_reviewed: bool
    result: dict[str, Any]
    error: str


class EntryRecord(TypedDict, total=False):
    entry_id: str
    status: str
    kind: str
    role: str
    location: dict[str, Any]
    summary: str
    input_origin: dict[str, Any]
    registration: dict[str, Any]
    input_binding: dict[str, Any]
    activation: dict[str, Any]
    trust_boundary: dict[str, Any]
    evidence_refs: list[str]
    assumptions: list[str]
    attempts: list[str]
    owner: str
    reason: str
    reopen_condition: str
    same_file_reviewed: bool
    stale_reason: str


class EvidenceRecord(TypedDict, total=False):
    evidence_id: str
    kind: str
    source_file: str
    source_fingerprint: str
    line_start: int
    line_end: int
    excerpt_ref: str
    summary: str


class InitResource(TypedDict, total=False):
    kind: str
    status: str
    path: str
    available: bool
    required: bool
    reason: str


class DiscoverState(TypedDict, total=False):
    """Durable state for the discover subgraph.

    Values are deliberately JSON-compatible. Runtime clients, model objects and
    MCP connections belong in ``RunContext`` instead.
    """

    repository: str
    artifact_dir: str
    state_file: str
    ledger_file: str
    init_reference: dict[str, Any]
    init_resources: dict[str, list[InitResource]]
    prepare: dict[str, Any]
    current_node: str
    status: str
    source_revision: str
    file_count: int
    screened_file_count: int
    covered_file_count: int
    excluded_file_count: int
    task_count: int
    pending_task_count: int
    open_task_count: int
    entry_count: int
    confirmed_entry_count: int
    unknown_entry_count: int
    deferred_entry_count: int
    mechanism_count: int
    feature_query_count: int
    feature_hit_count: int
    feature_debt_count: int
    evidence_count: int
    gap_count: int
    warning_count: int
    review: dict[str, Any]
    confirm: dict[str, Any]
    review_round: int
    follow_up_required: bool
    planner: dict[str, Any]
    debt_count: int
    deferred_count: int
    handoff_count: int
    deferred_items: list[dict[str, Any]]
    handoff_items: list[dict[str, Any]]
    screen: dict[str, Any]
    next_action: str
    loop_guard: dict[str, Any]
    warnings: list[str]
    gaps: list[str]
    stop_reason: str
    summary: dict[str, Any]
    updated_at: str


def empty_state(
    repository: str,
    artifact_dir: str,
    state_file: str,
    init_reference: dict[str, Any] | None = None,
) -> DiscoverState:
    return {
        "repository": repository,
        "artifact_dir": artifact_dir,
        "state_file": state_file,
        "ledger_file": str(Path(artifact_dir) / "ledger.sqlite"),
        "init_reference": init_reference or {},
        "init_resources": {},
        "prepare": {},
        "current_node": "prepare",
        "status": "running",
        "source_revision": "",
        "file_count": 0,
        "screened_file_count": 0,
        "covered_file_count": 0,
        "excluded_file_count": 0,
        "task_count": 0,
        "pending_task_count": 0,
        "open_task_count": 0,
        "entry_count": 0,
        "confirmed_entry_count": 0,
        "unknown_entry_count": 0,
        "deferred_entry_count": 0,
        "mechanism_count": 0,
        "feature_query_count": 0,
        "feature_hit_count": 0,
        "feature_debt_count": 0,
        "evidence_count": 0,
        "gap_count": 0,
        "warning_count": 0,
        "review": {},
        "confirm": {},
        "review_round": 0,
        "follow_up_required": False,
        "planner": {},
        "debt_count": 0,
        "deferred_count": 0,
        "handoff_count": 0,
        "deferred_items": [],
        "handoff_items": [],
        "screen": {
            "initial_wave_complete": False,
            "wave": 0,
            "last_wave": {},
            "follow_up_queue": [],
            "follow_up_queue_count": 0,
            "planner": {},
            "waves_without_new_candidate": 0,
        },
        "next_action": "screen",
        "loop_guard": {},
        "warnings": [],
        "gaps": [],
        "stop_reason": "",
        "summary": {},
        "updated_at": "",
    }
