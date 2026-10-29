"""Run the audit graph and persist its stage record."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, cast

from langgraph.errors import GraphRecursionError
from langgraph.runtime import Runtime

from ...agent.usage import UsageRecorder
from ...config import load_settings
from ...observability import trace_node
from ...storage import utc_now
from ...workflow.state import RunContext, RunState
from .budget import AuditBudget
from .framework import NODE_NAMES
from .schema import AuditState, empty_state
from .storage import AuditPaths, audit_paths, load_json, persist_audit_state, unique


@trace_node("workflow.audit")
def run_stage(
    state: RunState,
    runtime: Runtime[RunContext] | None = None,
) -> dict[str, object]:
    """Run the audit outer graph and persist its stage record."""
    from ..common import record_stage
    from .graph import build_audit_graph

    context = runtime.context if runtime is not None else RunContext(settings=load_settings())
    usage = context.usage or UsageRecorder(
        context.settings.usage_price_table,
        max_tokens=context.settings.audit_max_total_tokens,
        max_cost=context.settings.audit_max_total_cost,
    )
    usage.configure_limits(
        max_tokens=context.settings.audit_max_total_tokens,
        max_cost=context.settings.audit_max_total_cost,
    )
    context = replace(context, usage=usage)
    context = replace(
        context,
        audit_budget=context.audit_budget or AuditBudget.create(context.settings.audit_timeout),
    )
    started_at = utc_now()
    paths = audit_paths(state["stages_dir"])
    paths.root.mkdir(parents=True, exist_ok=True)
    start_update = record_stage(
        "audit",
        state,
        status="running",
        message="audit graph is running.",
        started_at=started_at,
        details={"state_file": str(paths.state_file)},
    )
    running_state: RunState = {**state, **start_update}
    audit_state: AuditState = {}
    try:
        audit_state = _begin_invocation(_load_or_create(running_state, paths))
        persist_audit_state(audit_state)
        result = build_audit_graph().invoke(
            audit_state,
            context=context,
            config={"recursion_limit": context.settings.audit_recursion_limit},
        )
    except GraphRecursionError:
        result = _mark_recursion_limit(audit_state, paths)
    except Exception as exc:
        record_stage(
            "audit",
            running_state,
            status="failed",
            message="audit graph failed.",
            started_at=started_at,
            details={
                "state_file": str(paths.state_file),
                "error": str(exc),
            },
        )
        raise

    summary = _summary(result, paths)
    usage.write(paths.usage_file, stage_prefix="audit")
    summary["usage"] = usage.snapshot()["totals"]
    status = str(result.get("status", "partial"))
    if status not in {"complete", "partial", "degraded", "failed"}:
        status = "partial"
    final_update = record_stage(
        "audit",
        {**running_state, "audit": summary},
        status=status,
        message=(
            "Audit graph failed."
            if status == "failed"
            else f"Audit graph finished with status {status}."
        ),
        started_at=started_at,
        details=summary,
    )
    final_update["audit"] = summary
    return final_update


def _load_or_create(run_state: RunState, paths: AuditPaths) -> AuditState:
    if paths.state_file.is_file():
        try:
            existing = load_json(paths.state_file)
        except (OSError, ValueError):
            paths.state_file.replace(paths.state_file.with_suffix(".corrupt.json"))
        else:
            existing["references"] = _references(run_state)
            existing.setdefault("mode", str(run_state.get("audit_mode") or "combined"))
            framework = existing.setdefault("framework", {})
            # Drop implementation-status fields from older audit states.
            framework.pop("scaffold", None)
            framework.pop("pending_nodes", None)
            return cast(AuditState, existing)
    result = empty_state(run_state, paths)
    result["references"] = _references(run_state)
    persist_audit_state(result)
    return result


def _begin_invocation(state: AuditState) -> AuditState:
    """Start a new audit invocation with fresh per-node visit counters.

    ``executed`` remains an append-only trail across invocations.  Only the
    transient ``node_visit_limit`` stop reason is cleared; structural stop
    reasons such as input gaps are preserved.
    """
    updated = dict(state)
    framework = dict(updated.get("framework") or {})
    framework["invocations"] = int(framework.get("invocations", 0)) + 1
    framework["visits"] = {}
    updated["framework"] = cast(Any, framework)
    if updated.get("stop_reason") == "node_visit_limit":
        updated["stop_reason"] = ""
    return cast(AuditState, updated)


def _references(run_state: RunState) -> dict[str, Any]:
    latest: dict[str, dict[str, Any]] = {}
    for item in run_state.get("stages", []):
        name = item.get("name")
        if name in {"init", "discover"}:
            latest[str(name)] = item
    return {
        name: {
            "status": record.get("status", ""),
            "artifact_dir": record.get("artifact_dir", ""),
            "artifact_file": record.get("artifact_file", ""),
            "details": record.get("details", {}) if isinstance(record.get("details"), dict) else {},
        }
        for name, record in latest.items()
    }


def _summary(result: AuditState, paths: AuditPaths) -> dict[str, Any]:
    framework = result.get("framework") or {}
    prepare = result.get("prepare") or {}
    plan = result.get("plan") or {}
    trace = result.get("trace") or {}
    recon = result.get("recon") or {}
    verify = result.get("verify") or {}
    gate = result.get("gate") or {}
    return {
        "status": str(result.get("status", "partial")),
        "mode": str(result.get("mode", "combined")),
        "state_file": str(result.get("state_file", paths.state_file)),
        "audit_file": str(result.get("audit_file", paths.audit_file)),
        "prepare_file": str(result.get("prepare_file", paths.prepare_file)),
        "business_artifact_file": str(result.get("business_file", paths.business_file)),
        "report_file": str(result.get("report_file", paths.report_file)),
        "index_file": str(result.get("index_file", paths.index_file)),
        "validation_file": str(result.get("validation_file", paths.validation_file)),
        "usage_file": str(result.get("usage_file", paths.usage_file)),
        "executed_nodes": list(framework.get("executed", [])),
        "implemented_nodes": list(NODE_NAMES),
        "stop_reason": str(result.get("stop_reason", "")),
        "verify": {
            key: verify.get(key)
            for key in (
                "status",
                "mode",
                "source_revision",
                "candidate_count",
                "finding_count",
                "confirmed_count",
                "rejected_count",
                "needs_validation_count",
                "unverified_count",
                "review_count",
                "complete_review_count",
                "pending_review_count",
                "second_verifier_count",
                "deferred_count",
                "gaps",
                "warnings",
                "limitations",
                "stop_reason",
                "model",
                "written_at",
            )
        },
        "recon": {
            key: recon.get(key)
            for key in (
                "status",
                "mode",
                "constraint_count",
                "operation_count",
                "investigation_count",
                "logic_task_count",
                "trace_count",
                "scope_file_count",
                "source_revision",
                "gaps",
                "warnings",
                "limitations",
                "stop_reason",
                "model",
                "written_at",
            )
        },
        "gate": {
            key: gate.get(key)
            for key in (
                "status",
                "mode",
                "source_revision",
                "debt_count",
                "blocking_count",
                "task_debt_count",
                "check_debt_count",
                "trace_debt_count",
                "finding_debt_count",
                "review_debt_count",
                "business_debt_count",
                "blocked_count",
                "accepted_blocked_count",
                "gap_count",
                "candidate_count",
                "confirmed_count",
                "rejected_count",
                "needs_validation_count",
                "validation_pending",
                "action",
                "stop_reason",
                "fingerprint",
                "written_at",
            )
        },
        "trace": {
            key: trace.get(key)
            for key in (
                "status",
                "task_count",
                "trace_count",
                "complete_count",
                "deferred_count",
                "flow_count",
                "complete_flow_count",
                "partial_flow_count",
                "reachable_flow_count",
                "summary_count",
                "gaps",
                "model",
            )
        },
        "prepare": {
            key: prepare.get(key)
            for key in (
                "status",
                "mode",
                "routes",
                "source_revision",
                "scope_file_count",
                "entries_loaded",
                "patches_loaded",
                "usable_patch_count",
                "gaps",
                "warnings",
                "limitations",
                "stop_reason",
            )
        },
        "plan": {
            key: plan.get(key)
            for key in (
                "status",
                "mode",
                "task_count",
                "entry_task_count",
                "patch_task_count",
                "category_obligation_count",
                "mechanism_obligation_count",
                "category_profile_version",
                "seed_task_count",
                "batch_count",
                "batch_size",
                "gaps",
                "warnings",
                "limitations",
                "stop_reason",
                "model",
            )
        },
        "limitations": [],
    }


def _mark_recursion_limit(state: AuditState, paths: AuditPaths) -> AuditState:
    from .finalize.node import finalize

    latest = state
    if paths.state_file.is_file():
        try:
            latest = cast(AuditState, load_json(paths.state_file))
        except (OSError, ValueError):
            pass
    latest = {
        **latest,
        "status": "partial",
        "stop_reason": "recursion_limit",
        "next_action": "finalize",
        "warnings": unique(
            [
                *latest.get("warnings", []),
                "audit graph reached the recursion limit",
            ]
        ),
    }
    framework = dict(latest.get("framework") or {})
    executed = list(framework.get("executed", []))
    if not executed or executed[-1] != "finalize":
        executed.append("finalize")
    framework["executed"] = executed
    latest["framework"] = framework
    finalize(latest)
    persist_audit_state(latest)
    return latest
