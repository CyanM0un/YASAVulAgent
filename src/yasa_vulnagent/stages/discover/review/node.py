from __future__ import annotations

import json
import logging
import time
from collections import Counter
from importlib.resources import files
from pathlib import Path
from typing import Any

from langgraph.runtime import Runtime

from ....observability import trace_node
from ....storage import utc_now
from ....workflow.state import RunContext
from ..agent import run_task_agent_sync, task_tool_store
from ..budget import exceeded_reason
from ..evidence import validate_refs
from ..features import process_observations, resume_incomplete_queries
from ..ledger import DiscoverLedger
from ..schema import DiscoverState
from ..storage import persist, write_json
from ..screen.graph import ScreenBudget
from ..screen.model import ScreenConfigurationError, build_configured_model
from ..screen.planner import next_task_number, parse_json, validate_new_tasks
from .tools import ReviewToolbox


logger = logging.getLogger(__name__)
_STATUSES = frozenset({"not_applicable", "deferred", "handoff_to_confirm"})
_REASONS = frozenset(
    {"out_of_scope", "external_dependency", "manual_review", "downstream_confirm", "unsupported"}
)
_OWNERS = frozenset({"review", "manual", "confirm"})


@trace_node("discover.review")
def review(
    state: DiscoverState,
    runtime: Runtime[RunContext] | None = None,
) -> dict[str, object]:
    """Audit durable debt, repair feature/handoff queues, then route."""
    context = runtime.context if runtime is not None else None
    round_number = int(state.get("review_round", 0)) + 1
    artifact_dir = Path(state["artifact_dir"])
    repository = Path(state["repository"])
    with DiscoverLedger.open(Path(state["ledger_file"])) as ledger:
        settings = context.settings if context is not None else None
        next_wave = max(
            int(state.get("screen", {}).get("wave", 0)),
            max(
                [int(item.get("wave", 0)) for item in ledger.list_tasks()],
                default=0,
            ),
        ) + 1
        repair = (
            _repair_queues(
                ledger,
                repository,
                artifact_dir=artifact_dir,
                wave=next_wave,
                settings=settings,
            )
            if settings is not None
            else {"handoffs": 0, "mechanisms": 0, "queries": 0, "candidates": 0, "tasks": 0}
        )
        debt = ledger.debt_items()
        budget_reason = exceeded_reason(state, context)
        record: dict[str, Any] = {
            "status": "complete" if not debt else "partial",
            "round": round_number,
            "route": _route_for_debt(debt),
            "debt_count": len(debt),
            "disposed_count": 0,
            "dispositions": [],
            "new_tasks": [],
            "warnings": [],
            "blocking_gaps": [],
            "blocking_gap_count": 0,
            "model_calls": 0,
            "source_reads": [],
            "deferred_count": ledger.disposition_count("deferred"),
            "handoff_count": len(ledger.open_handoffs()),
            "feature_repair": repair,
        }
        record["warnings"].extend(_source_hint_warnings(ledger))
        if debt and context is not None and not budget_reason:
            _review_debt(
                ledger,
                debt,
                record,
                context=context,
                repository=repository,
                round_number=round_number,
                next_wave=next_wave,
                artifact_dir=artifact_dir,
            )
        elif debt and context is None:
            record["status"] = "partial"
            record["route"] = _route_for_debt(debt)
            record["blocking_gaps"] = ["review runtime context is unavailable"]
        remaining = ledger.debt_items()
        record["debt_remaining"] = len(remaining)
        record["disposed_count"] = len(record["dispositions"])
        record["blocking_gap_count"] = len(record.get("blocking_gaps", []))
        record["deferred_count"] = ledger.disposition_count("deferred")
        record["handoff_count"] = len(ledger.open_handoffs())
        if remaining:
            record["route"] = _route_for_debt(remaining)
            record["status"] = "partial"
        elif record["blocking_gaps"]:
            record["route"] = "finalize"
            record["status"] = "partial"
        else:
            record["route"] = "finalize"
            record["status"] = "complete"
        if budget_reason:
            record["route"] = "finalize"
            record["status"] = "partial"
            record["blocking_gaps"] = [*record.get("blocking_gaps", []), budget_reason]
        record["debt_remaining"] = len(remaining)
        record["blocking_gap_count"] = len(record.get("blocking_gaps", []))
        if record.get("blocking_gaps"):
            ledger.add_messages(gaps=list(record["blocking_gaps"]))
        if record.get("warnings"):
            ledger.add_messages(warnings=list(record["warnings"]))
        counts = ledger.file_counts()
        update: DiscoverState = {
            **state,
            "current_node": "review",
            "review": record,
            "review_round": round_number,
            "follow_up_required": record["route"] != "finalize",
            "next_action": str(record["route"]),
            "file_count": counts.get("total", 0),
            "screened_file_count": counts.get("screened", 0),
            "covered_file_count": counts.get("covered", 0),
            "task_count": ledger.task_count(),
            "pending_task_count": ledger.pending_task_count(),
            "entry_count": ledger.count_entries(),
            "confirmed_entry_count": ledger.count_entries("confirmed"),
            "unknown_entry_count": ledger.count_entries("unknown"),
            "deferred_entry_count": ledger.count_entries("deferred"),
            "evidence_count": ledger.count_evidence(),
            "debt_count": ledger.debt_count(),
            "feature_debt_count": ledger.feature_debt_count(),
            "mechanism_count": ledger.count_mechanisms(),
            "feature_query_count": ledger.count_feature_queries(),
            "feature_hit_count": ledger.count_feature_hits(),
            "deferred_count": ledger.disposition_count("deferred"),
            "handoff_count": len(ledger.open_handoffs()),
            "gap_count": ledger.message_count("gaps"),
            "warning_count": ledger.message_count("warnings"),
            "gaps": ledger.messages("gaps"),
            "warnings": ledger.messages("warnings"),
            "stop_reason": (
                budget_reason
                if budget_reason
                else "review_complete"
                if record["status"] == "complete"
                else "review_unavailable"
                if record["blocking_gaps"] and record["model_calls"] == 0
                else "review_pending"
            ),
            "updated_at": utc_now(),
        }
        write_json(artifact_dir / "review.json", record)
    persist(update)
    logger.info(
        "discover review round=%s debt=%s disposed=%s route=%s status=%s",
        round_number,
        record["debt_count"],
        record["disposed_count"],
        record["route"],
        record["status"],
    )
    return update


def _source_hint_warnings(ledger: DiscoverLedger) -> list[str]:
    scheduled: set[str] = set()
    for task in ledger.list_tasks():
        scheduled.update(ledger.task_scope_paths(str(task.get("task_id", ""))))
    warnings: list[str] = []
    for entry in ledger.entries():
        if str(entry.get("role", "")) != "source":
            continue
        location = entry.get("location") if isinstance(entry.get("location"), dict) else {}
        path = str(location.get("path", ""))
        if path and path not in scheduled:
            warnings.append(
                f"source-role entry {entry.get('entry_id', '')} in {path} was never scheduled; "
                "source priority is a hint, not coverage evidence"
            )
    return warnings


def _route_for_debt(debt: list[dict[str, Any]]) -> str:
    if not debt:
        return "finalize"
    for item in debt:
        if item.get("debt_type") in {"candidate", "handoff"}:
            return "confirm"
        if item.get("debt_type") == "task" and str(item.get("kind", "")).startswith("confirm"):
            return "confirm"
    return "screen"


def _repair_queues(
    ledger: DiscoverLedger,
    repository: Path,
    *,
    artifact_dir: Path,
    wave: int,
    settings: Any,
) -> dict[str, int]:
    summary = {"handoffs": 0, "mechanisms": 0, "queries": 0, "candidates": 0, "tasks": 0}
    for disposition in ledger.open_handoffs():
        ref_id = str(disposition.get("ref_id", ""))
        entry = ledger.get_entry(ref_id)
        location = entry.get("location") if isinstance(entry, dict) and isinstance(entry.get("location"), dict) else {}
        path = str(location.get("path", ""))
        if not path:
            ledger.add_messages(warnings=[f"open handoff has no candidate location: {ref_id}"])
            continue
        task_id = ledger.ensure_confirm_task(
            path=path,
            candidate_ids=[ref_id],
            origin="handoff",
            question=f"Verify handoff candidate {ref_id} in {path}.",
            artifact_dir=str(artifact_dir),
            wave=wave,
        )
        ledger.mark_handoff_consumed(str(disposition.get("debt_id", "")), task_id)
        summary["handoffs"] += 1
    existing_query_mechanisms = {
        str(query.get("mechanism_id", "")) for query in ledger.query_rows()
    }
    for mechanism in ledger.mechanism_rows():
        if str(mechanism.get("mechanism_id", "")) in existing_query_mechanisms:
            continue
        observation = {
            "kind": mechanism.get("kind", "text"),
            "name": mechanism.get("name", ""),
            "role": mechanism.get("role", "unknown"),
            "definition": {
                "path": mechanism.get("definition_path", ""),
                "line_start": mechanism.get("line_start", 0),
                "line_end": mechanism.get("line_end", 0),
            },
            "evidence_refs": mechanism.get("evidence_refs", []),
            "query": {
                "kind": mechanism.get("kind", "text"),
                "target": mechanism.get("name", ""),
                "regex": False,
                "scope": [],
                "max_results": int(getattr(settings, "feature_max_results", 200)),
            },
        }
        result = process_observations(
            repository,
            ledger,
            [observation],
            task_id=f"review-repair:{mechanism.get('mechanism_id', '')}",
            artifact_dir=artifact_dir,
            wave=wave,
            max_results=int(getattr(settings, "feature_max_results", 200)),
            max_tasks=int(getattr(settings, "feature_max_tasks", 32)),
            timeout=int(getattr(settings, "feature_query_timeout", 30)),
            max_regex_chars=int(getattr(settings, "feature_max_regex_chars", 512)),
        )
        summary["mechanisms"] += 1
        old_id = str(mechanism.get("mechanism_id", ""))
        repaired_ids = set(result.get("mechanism_ids", []))
        if repaired_ids and old_id and old_id not in repaired_ids:
            ledger.delete_mechanism(old_id)
        summary["queries"] += int(result.get("queries", 0))
        summary["candidates"] += int(result.get("candidates", 0))
        summary["tasks"] += int(result.get("tasks", 0))
    resumed = resume_incomplete_queries(
        repository,
        ledger,
        artifact_dir=artifact_dir,
        wave=wave,
        max_results=int(getattr(settings, "feature_max_results", 200)),
        max_tasks=int(getattr(settings, "feature_max_tasks", 32)),
        timeout=int(getattr(settings, "feature_query_timeout", 30)),
        max_regex_chars=int(getattr(settings, "feature_max_regex_chars", 512)),
    )
    summary["queries"] += int(resumed.get("queries", 0))
    summary["candidates"] += int(resumed.get("candidates", 0))
    summary["tasks"] += int(resumed.get("tasks", 0))
    return summary


def _review_debt(
    ledger: DiscoverLedger,
    debt: list[dict[str, Any]],
    record: dict[str, Any],
    *,
    context: RunContext,
    repository: Path,
    round_number: int,
    next_wave: int,
    artifact_dir: Path,
) -> None:
    settings = context.settings
    model_name = str(getattr(settings, "review_model", "") or "")
    try:
        model = build_configured_model(
            context,
            model_name=model_name,
            timeout=getattr(settings, "review_timeout", 300),
        )
    except ScreenConfigurationError as exc:
        record["blocking_gaps"] = [f"review model unavailable: {exc}"]
        record["status"] = "partial"
        record["route"] = _route_for_debt(debt)
        return
    budget = ScreenBudget(
        deadline=time.monotonic() + max(1, int(getattr(settings, "review_timeout", 300))),
        model_calls_limit=max(1, int(getattr(settings, "review_max_calls", 8))),
    )
    allowed_paths = {
        str(item.get("path", ""))
        for item in debt
        if item.get("path")
    }
    toolbox = ReviewToolbox(repository, allowed_paths)
    prompt = _load_prompt()
    disposition_rows = ledger.disposition_rows()
    user_prompt = json.dumps(
        {
            "round": round_number,
            "debt": debt[:200],
            "existing_dispositions": {
                "counts": dict(
                    Counter(str(row.get("status", "")) for row in disposition_rows)
                ),
                "status_by_debt": {
                    str(row.get("debt_id", "")): str(row.get("status", ""))
                    for row in disposition_rows
                },
            },
            "limits": {
                "max_new_tasks": getattr(settings, "planner_max_new_tasks", 2),
                "max_files": getattr(settings, "planner_max_files", 8),
                "max_chars": getattr(settings, "planner_max_chars", 40000),
            },
        },
        ensure_ascii=False,
        default=str,
    )
    parsed: Any = None
    for attempt in range(2):
        try:
            response = run_task_agent_sync(
                model=model,
                system_prompt=prompt,
                user_prompt=user_prompt,
                tools=toolbox.langchain_tools(),
                budget=budget,
                usage=context.usage,
                stage="discover.review",
                task_id=f"review-round-{round_number}",
                store=task_tool_store(artifact_dir),
                settings=settings,
                max_rounds=4,
            ).content
        except Exception as exc:
            record["blocking_gaps"] = [f"review model failed: {str(exc)[:1000]}"]
            record["status"] = "partial"
            record["route"] = _route_for_debt(debt)
            record["model_calls"] = budget.model_calls
            record["source_reads"] = toolbox.receipts
            return
        parsed = parse_json(response)
        if isinstance(parsed, dict):
            break
        if attempt == 0:
            record["warnings"].append("review returned malformed JSON; retrying once")
    record["model_calls"] = budget.model_calls
    record["source_reads"] = toolbox.receipts
    if not isinstance(parsed, dict):
        record["blocking_gaps"] = ["review did not return a JSON object after retry"]
        record["status"] = "partial"
        record["route"] = _route_for_debt(debt)
        return
    accepted, rejected = _apply_dispositions(
        ledger,
        repository,
        debt,
        parsed.get("dispositions", []),
        artifact_dir=artifact_dir,
        wave=next_wave,
    )
    record["dispositions"] = accepted
    record["blocking_gaps"].extend(rejected)
    proposals = parsed.get("new_tasks", [])
    if not isinstance(proposals, list):
        proposals = []
    new_tasks, task_rejected = validate_new_tasks(
        proposals,
        ledger=ledger,
        next_number=next_task_number(ledger.list_tasks()),
        wave=next_wave,
        max_new_tasks=getattr(settings, "planner_max_new_tasks", 2),
        max_files=getattr(settings, "planner_max_files", 8),
        max_chars=getattr(settings, "planner_max_chars", 40000),
    )
    for task in new_tasks:
        ledger.put_task(task)
    record["new_tasks"] = new_tasks
    record["warnings"].extend(
        f"review task rejected: {item.get('reason', '')}" for item in task_rejected
    )
    remaining = ledger.debt_items()
    record["route"] = _route_for_debt(remaining)
    record["status"] = "complete" if not remaining and not record["blocking_gaps"] else "partial"


def _apply_dispositions(
    ledger: DiscoverLedger,
    repository: Path,
    debt: list[dict[str, Any]],
    values: Any,
    *,
    artifact_dir: Path,
    wave: int,
) -> tuple[list[dict[str, Any]], list[str]]:
    by_id = {str(item.get("debt_id", "")): item for item in debt}
    accepted: list[dict[str, Any]] = []
    rejected: list[str] = []
    seen: set[str] = set()
    for value in values if isinstance(values, list) else []:
        if not isinstance(value, dict):
            rejected.append("review disposition is not an object")
            continue
        debt_id = str(value.get("debt_id", ""))
        item = by_id.get(debt_id)
        if item is None:
            rejected.append(f"review disposition references unknown debt: {debt_id}")
            continue
        if debt_id in seen:
            rejected.append(f"review disposition is duplicated: {debt_id}")
            continue
        seen.add(debt_id)
        status = str(value.get("status", ""))
        reason = str(value.get("reason", ""))
        owner = str(value.get("owner", ""))
        evidence = value.get("evidence_refs", [])
        evidence = [str(entry) for entry in evidence if str(entry).strip()] if isinstance(evidence, list) else []
        if status not in _STATUSES:
            rejected.append(f"review disposition has invalid status: {debt_id}")
            continue
        if reason not in _REASONS:
            rejected.append(f"review disposition has invalid reason: {debt_id}")
            continue
        if owner not in _OWNERS:
            rejected.append(f"review disposition has invalid owner: {debt_id}")
            continue
        canonical, evidence_errors = validate_refs(repository, ledger, evidence)
        if evidence_errors or not canonical:
            rejected.append(
                f"review disposition evidence is not verifiable: {debt_id}: "
                + "; ".join(evidence_errors or ["no evidence"])
            )
            continue
        if status == "deferred" and not str(value.get("reopen_condition", "")).strip():
            rejected.append(f"deferred disposition requires reopen_condition: {debt_id}")
            continue
        if status == "handoff_to_confirm" and item.get("debt_type") != "candidate":
            rejected.append(f"handoff_to_confirm is candidate-only: {debt_id}")
            continue
        if status == "handoff_to_confirm" and reason != "downstream_confirm":
            rejected.append(f"handoff_to_confirm requires downstream_confirm: {debt_id}")
            continue
        if reason == "downstream_confirm" and item.get("debt_type") != "candidate":
            rejected.append(f"downstream_confirm is candidate-only: {debt_id}")
            continue
        confirm_task_id = ""
        if status == "handoff_to_confirm":
            path = str(item.get("path", ""))
            if not path:
                rejected.append(f"handoff candidate has no path: {debt_id}")
                continue
            confirm_task_id = ledger.ensure_confirm_task(
                path=path,
                candidate_ids=[str(item.get("ref_id", ""))],
                origin="handoff",
                question=f"Verify handoff candidate {item.get('ref_id', '')} in {path}.",
                artifact_dir=str(artifact_dir),
                wave=wave,
            )
        ledger.put_disposition(
            debt_id=debt_id,
            debt_type=str(item.get("debt_type", "")),
            ref_id=str(item.get("ref_id", "")),
            status=status,
            reason=reason,
            owner=owner,
            evidence_refs=canonical,
            source="review",
            confirm_task_id=confirm_task_id,
            reopen_condition=str(value.get("reopen_condition", "")),
        )
        if status == "handoff_to_confirm":
            ledger.mark_handoff_consumed(debt_id, confirm_task_id)
        if str(item.get("debt_type", "")) == "task":
            ledger.close_task(str(item.get("ref_id", "")))
        accepted.append(
            {
                "debt_id": debt_id,
                "status": status,
                "reason": reason,
                "owner": owner,
                "evidence_refs": canonical,
                "confirm_task_id": confirm_task_id,
                "reopen_condition": str(value.get("reopen_condition", "")),
            }
        )
    return accepted, rejected


def _load_prompt() -> str:
    return files("yasa_vulnagent.stages.discover.review").joinpath(
        "prompts", "review.md"
    ).read_text(encoding="utf-8")

