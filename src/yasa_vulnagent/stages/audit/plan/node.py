"""Audit plan: build seed tasks, consolidate batches, and write obligations."""

from __future__ import annotations

from typing import Any

from ....agent.retry import RetryPolicy
from ....config import DEFAULT_AUDIT_PLAN_BATCH_SIZE
from ....workflow.state import RunContext
from ..categories import load_category_manifest
from ..storage import load_json, paths_from_state, write_plan_checkpoint
from .batches import build_seed_batches
from .model import PlanConfigurationError, build_model, run_batch
from .tasks import (
    build_seed_tasks,
    build_seed_views,
    derive_final_tasks,
    validate_final_tasks,
)


def plan(state: dict[str, Any], runtime: Any = None) -> dict[str, object]:
    """Build the first audit task plan and its coverage obligations."""
    context = getattr(runtime, "context", None) if runtime is not None else None
    paths = paths_from_state(state)
    audit = _load_audit(paths.audit_file)
    framework = dict(state.get("framework") or {})
    tasks = audit.get("tasks") if isinstance(audit, dict) else []
    if isinstance(tasks, list) and (tasks or framework.get("plan_done")):
        return _existing_result(state, audit or {}, context)

    manifest = load_category_manifest()
    prepare = state.get("prepare") if isinstance(state.get("prepare"), dict) else {}
    entries = state.get("entries") if isinstance(state.get("entries"), list) else []
    patches = state.get("patches") if isinstance(state.get("patches"), list) else []
    scope = state.get("scope") if isinstance(state.get("scope"), dict) else {}
    scope_files = [str(path) for path in scope.get("files", []) if isinstance(path, str)]
    seed_tasks, plan_gaps = build_seed_tasks(entries, patches, scope_files)

    batch_size = (
        int(context.settings.audit_plan_batch_size)
        if context is not None
        else DEFAULT_AUDIT_PLAN_BATCH_SIZE
    )
    batches = build_seed_batches(seed_tasks, batch_size)
    views = build_seed_views(seed_tasks, entries, patches) if batches else []
    view_by_id = {str(view["id"]): view for view in views}

    outputs: list[dict[str, Any]] = []
    model_name = ""
    if batches:
        if context is None:
            raise PlanConfigurationError(
                "audit plan requires a RunContext to call the planning model"
            )
        model = build_model(context)
        model_name = str(
            getattr(model, "model_name", "") or getattr(model, "model", "") or ""
        )
        for batch in batches:
            batch_views = [view_by_id[str(task["id"])] for task in batch["tasks"]]
            outputs.append(
                run_batch(
                    model,
                    batch,
                    batch_views,
                    context.usage,
                    model_name=model_name,
                    retry=RetryPolicy(attempts=context.settings.agent_model_retries),
                )
            )

    tasks, category_checks, mechanism_checks = derive_final_tasks(
        seed_tasks, batches, outputs, manifest
    )
    validate_final_tasks(
        seed_tasks,
        tasks,
        category_checks,
        mechanism_checks,
        scope_files,
        manifest,
    )

    stop_reason = str(
        state.get("stop_reason")
        or prepare.get("stop_reason")
        or ("" if tasks else "inputs_unavailable")
    )
    limitations = []
    if len(batches) > 1:
        limitations.append(
            f"planning split into {len(batches)} batches; cross-batch merging is disabled"
        )
    plan_summary = {
        "status": (
            "complete"
            if tasks and not plan_gaps and prepare.get("status") == "complete"
            else "partial"
        ),
        "mode": str(state.get("mode", "combined")),
        "task_count": len(tasks),
        "entry_task_count": sum(1 for task in tasks if task.get("kind") == "entry"),
        "patch_task_count": sum(1 for task in tasks if task.get("kind") == "patch"),
        "category_obligation_count": len(category_checks),
        "mechanism_obligation_count": len(mechanism_checks),
        "category_profile_version": manifest.profile_version,
        "input_signature": dict(prepare.get("input_signature") or {}),
        "seed_task_count": len(seed_tasks),
        "batch_count": len(batches),
        "batch_size": batch_size,
        "gaps": plan_gaps,
        "warnings": [],
        "limitations": limitations,
        "stop_reason": stop_reason,
        "model": {
            "status": "used" if batches else "not_run",
            "model": model_name,
            "calls": len(batches),
            "batches": len(batches),
        },
    }
    framework.update(
        {
            "executed": list(framework.get("executed", [])),
            "plan_done": True,
        }
    )
    updated = {
        **state,
        "tasks": tasks,
        "category_checks": category_checks,
        "mechanism_checks": mechanism_checks,
        "plan": plan_summary,
        "framework": framework,
        "status": "running",
        "stop_reason": stop_reason,
        "next_action": "trace",
    }
    write_plan_checkpoint(updated)
    return _result(updated)


def _result(state: dict[str, Any]) -> dict[str, object]:
    return {
        "plan": state["plan"],
        "tasks": state["tasks"],
        "category_checks": state["category_checks"],
        "mechanism_checks": state["mechanism_checks"],
        "framework": state["framework"],
        "status": "running",
        "stop_reason": state.get("stop_reason", ""),
        "next_action": "trace",
    }


def _existing_result(
    state: dict[str, Any],
    audit: dict[str, Any],
    context: RunContext | None,
) -> dict[str, object]:
    prepare = state.get("prepare") if isinstance(state.get("prepare"), dict) else {}
    tasks = audit.get("tasks") if isinstance(audit.get("tasks"), list) else []
    category_checks = (
        audit.get("category_checks")
        if isinstance(audit.get("category_checks"), list)
        else []
    )
    mechanism_checks = (
        audit.get("mechanism_checks")
        if isinstance(audit.get("mechanism_checks"), list)
        else []
    )
    framework = dict(state.get("framework") or {})
    framework["plan_done"] = True
    summary = {
        "status": "complete" if tasks else "partial",
        "mode": str(state.get("mode", "combined")),
        "task_count": len(tasks),
        "entry_task_count": sum(1 for task in tasks if task.get("kind") == "entry"),
        "patch_task_count": sum(1 for task in tasks if task.get("kind") == "patch"),
        "category_obligation_count": len(category_checks),
        "mechanism_obligation_count": len(mechanism_checks),
        "category_profile_version": 0,
        "input_signature": dict(prepare.get("input_signature") or {}),
        "seed_task_count": len(tasks),
        "batch_count": 0,
        "batch_size": (
            int(context.settings.audit_plan_batch_size)
            if context is not None
            else DEFAULT_AUDIT_PLAN_BATCH_SIZE
        ),
        "gaps": [],
        "warnings": [],
        "limitations": ["existing plan reused"],
        "stop_reason": str(state.get("stop_reason") or prepare.get("stop_reason") or ""),
        "model": {
            "status": "existing",
            "model": "",
            "calls": 0,
            "batches": 0,
        },
    }
    return {
        "plan": summary,
        "tasks": tasks,
        "category_checks": category_checks,
        "mechanism_checks": mechanism_checks,
        "framework": framework,
        "status": "running",
        "stop_reason": summary["stop_reason"],
        "next_action": "trace",
    }


def _load_audit(path: Any) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        return load_json(path)
    except (OSError, ValueError):
        return None
