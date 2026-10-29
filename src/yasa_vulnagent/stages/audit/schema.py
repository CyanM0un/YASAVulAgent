"""Durable state for the audit stage."""

from __future__ import annotations

from typing import Any, Mapping, TypedDict


class AuditFramework(TypedDict, total=False):
    executed: list[str]
    visits: dict[str, int]
    invocations: int
    recon_done: bool
    plan_done: bool
    trace_done: bool
    verify_done: bool
    gate_done: bool
    finalize_done: bool
    inputs: dict[str, Any]


class AuditGap(TypedDict, total=False):
    id: str
    source: str
    reason: str
    paths: list[str]


class AuditGate(TypedDict, total=False):
    status: str
    mode: str
    source_revision: str
    debt_count: int
    blocking_count: int
    task_debt_count: int
    check_debt_count: int
    trace_debt_count: int
    finding_debt_count: int
    review_debt_count: int
    business_debt_count: int
    blocked_count: int
    accepted_blocked_count: int
    gap_count: int
    candidate_count: int
    confirmed_count: int
    rejected_count: int
    needs_validation_count: int
    validation_pending: list[dict[str, Any]]
    debts: list[dict[str, Any]]
    action: str
    stop_reason: str
    fingerprint: str
    written_at: str


class AuditPrepare(TypedDict, total=False):
    status: str
    mode: str
    routes: dict[str, str]
    input_signature: dict[str, Any]
    inputs: dict[str, Any]
    source_revision: str
    current_source_revision: str
    scope_file_count: int
    excluded_file_count: int
    entries_loaded: int
    patches_loaded: int
    usable_patch_count: int
    gaps: list[str]
    warnings: list[str]
    limitations: list[str]
    stop_reason: str


class AuditPlan(TypedDict, total=False):
    status: str
    mode: str
    task_count: int
    entry_task_count: int
    patch_task_count: int
    category_obligation_count: int
    mechanism_obligation_count: int
    category_profile_version: int
    input_signature: dict[str, Any]
    seed_task_count: int
    batch_count: int
    batch_size: int
    gaps: list[str]
    warnings: list[str]
    limitations: list[str]
    stop_reason: str
    model: dict[str, Any]


class AuditRecon(TypedDict, total=False):
    status: str
    mode: str
    constraint_count: int
    operation_count: int
    investigation_count: int
    logic_task_count: int
    trace_count: int
    scope_file_count: int
    source_revision: str
    model: dict[str, Any]
    gaps: list[str]
    warnings: list[str]
    limitations: list[str]
    stop_reason: str
    written_at: str


class AuditTrace(TypedDict, total=False):
    id: str
    task_id: str
    kind: str
    status: str
    summary: str
    coverage_complete: bool
    entry_ids: list[str]
    patch_ids: list[str]
    flow_count: int
    complete_flow_count: int
    partial_flow_count: int
    reachable_flow_count: int
    triage_rounds: int
    triaged_unit_count: int
    skipped_unit_count: int
    specialist_roles: list[str]
    summary_count: int
    summary_reuse_count: int
    repair_debt_count: int
    repair_resolved_count: int
    repair_unresolved_count: int
    artifact_file: str
    gaps: list[str]
    error: str


class AuditVerify(TypedDict, total=False):
    status: str
    mode: str
    source_revision: str
    candidate_count: int
    finding_count: int
    confirmed_count: int
    rejected_count: int
    needs_validation_count: int
    unverified_count: int
    review_count: int
    complete_review_count: int
    pending_review_count: int
    second_verifier_count: int
    deferred_count: int
    gaps: list[str]
    warnings: list[str]
    limitations: list[str]
    stop_reason: str
    model: dict[str, Any]
    written_at: str


class AuditState(TypedDict, total=False):
    """JSON-compatible state for the audit graph.

    Runtime clients and model objects belong in ``RunContext`` instead.
    """

    run_id: str
    repository: str
    artifact_dir: str
    state_file: str
    audit_file: str
    business_file: str
    report_file: str
    index_file: str
    validation_file: str
    usage_file: str
    framework_file: str
    stage_file: str
    prepare_file: str
    mode: str
    status: str
    stop_reason: str
    next_action: str
    references: dict[str, Any]
    framework: AuditFramework
    prepare: AuditPrepare
    plan: AuditPlan
    recon: AuditRecon
    trace: dict[str, Any]
    traces: list[AuditTrace]
    verify: AuditVerify
    gate: AuditGate
    summaries: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    reviews: list[dict[str, Any]]
    scope: dict[str, Any]
    entries: list[dict[str, Any]]
    patches: list[dict[str, Any]]
    tasks: list[dict[str, Any]]
    category_checks: list[dict[str, Any]]
    mechanism_checks: list[dict[str, Any]]
    gaps: list[AuditGap]
    warnings: list[str]


def empty_state(run_state: Mapping[str, Any], paths: Any) -> AuditState:
    """Build a fresh audit state from a run record and artifact paths."""
    return {
        "run_id": str(run_state.get("run_id", "")),
        "repository": str(run_state.get("repository", "")),
        "artifact_dir": str(paths.root),
        "state_file": str(paths.state_file),
        "audit_file": str(paths.audit_file),
        "business_file": str(paths.business_file),
        "report_file": str(paths.report_file),
        "index_file": str(paths.index_file),
        "validation_file": str(paths.validation_file),
        "usage_file": str(paths.usage_file),
        "framework_file": str(paths.framework_file),
        "stage_file": str(paths.stage_file),
        "prepare_file": str(paths.prepare_file),
        "mode": str(run_state.get("audit_mode") or "combined"),
        "status": "running",
        "stop_reason": "",
        "next_action": "prepare",
        "references": {},
        "framework": {},
        "prepare": {},
        "plan": {},
        "recon": {},
        "trace": {},
        "traces": [],
        "verify": {},
        "gate": {},
        "summaries": [],
        "findings": [],
        "reviews": [],
        "scope": {},
        "entries": [],
        "patches": [],
        "tasks": [],
        "category_checks": [],
        "mechanism_checks": [],
        "gaps": [],
        "warnings": [],
    }
