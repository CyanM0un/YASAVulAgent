from __future__ import annotations

import hashlib
import logging
import time
from pathlib import Path
from typing import Any

from langgraph.runtime import Runtime

from ....observability import trace_node
from ....storage import utc_now
from ....workflow.state import RunContext
from ..agent import TASK_MAX_ATTEMPTS
from ..budget import exceeded_reason
from ..features import ensure_confirm_tasks_for_candidates, process_observations
from ..ledger import DiscoverLedger
from ..schema import DiscoverState
from ..storage import load_json, persist, write_json
from .graph import ScreenBudget
from .harness import run_wave
from .planner import PlanResult, plan_wave
from .repo_map import build_repo_map, build_work_board


logger = logging.getLogger(__name__)
_INITIAL_VIEWS = (
    ("component-runtime", False, "Map externally reachable components and runtime registration points."),
    ("input-boundary", False, "Trace externally supplied values and their binding or boundary points."),
    ("independent-exploration", True, "Independently explore the repository for overlooked input entry candidates."),
)


@trace_node("discover.screen")
def screen(
    state: DiscoverState,
    runtime: Runtime[RunContext] | None = None,
) -> dict[str, object]:
    """Schedule and execute one bounded screen wave from the run-local ledger."""
    context = runtime.context if runtime is not None else None
    budget_reason = exceeded_reason(state, context)
    if budget_reason:
        logger.info("discover screen skipped: %s", budget_reason)
        return {"next_action": "finalize", "stop_reason": budget_reason}
    artifact_dir = Path(state["artifact_dir"])
    repository = Path(state["repository"])
    screen_meta = dict(state.get("screen", {}))
    with DiscoverLedger.open(Path(state["ledger_file"])) as ledger:
        settings = context.settings if context is not None else None
        ledger.recover_running_tasks()
        restored = _restore_completed_tasks(ledger, artifact_dir)
        _ensure_initial_tasks(ledger, screen_meta, artifact_dir)
        replayed = _replay_unprocessed_tasks(
            ledger,
            repository,
            artifact_dir,
            wave=max(1, int(screen_meta.get("wave", 0)) + 1),
            settings=settings,
        )
        if restored or replayed["tasks"]:
            logger.info(
                "discover screen recovery restored=%s replayed=%s",
                len(restored),
                replayed["tasks"],
            )
        before_digest = ledger.business_digest()

        max_tasks = int(getattr(settings, "screen_wave_max_tasks", 6)) if settings else 0
        budget = (
            ScreenBudget(
                deadline=time.monotonic() + max(1, int(settings.screen_wave_timeout)),
                model_calls_limit=max(1, int(settings.screen_wave_model_calls)),
            )
            if settings is not None
            else None
        )
        planner_meta: dict[str, Any] = {
            "status": "skipped",
            "model_calls": 0,
            "selected_task_ids": [],
            "new_task_ids": [],
            "error": "",
        }
        pending = ledger.retire_exhausted_tasks(
            ledger.list_tasks(statuses={"pending", "partial"}, kind_prefix="screen"),
            max_attempts=TASK_MAX_ATTEMPTS,
        )
        if not screen_meta.get("initial_wave_complete"):
            initial_views = {name for name, _, _ in _INITIAL_VIEWS}
            pending = [
                task
                for task in pending
                if int(task.get("wave", 0)) == 1 and str(task.get("view", "")) in initial_views
            ]
        plan = PlanResult(status="skipped")
        next_wave = max(1, int(screen_meta.get("wave", 0)) + 1)
        can_plan = (
            settings is not None
            and int(screen_meta.get("waves_without_new_candidate", 0))
            < int(settings.review_stagnation_waves)
        )
        if (
            context is not None
            and settings is not None
            and screen_meta.get("initial_wave_complete")
            and max_tasks > 0
            and len(pending) < max_tasks
            and can_plan
            and _has_planning_material(ledger)
        ):
            repo_map = build_repo_map(ledger)
            write_json(artifact_dir / "screen" / "repo-map.json", repo_map)
            work_board = build_work_board(
                ledger,
                repo_map,
                screen_meta=screen_meta,
                budget=budget,
                max_tasks=max_tasks,
            )
            plan = plan_wave(
                context=context,
                ledger=ledger,
                repo_map=repo_map,
                work_board=work_board,
                artifact_dir=artifact_dir,
                shared_budget=budget,
                wave=next_wave,
            )
            planner_meta = {
                "status": plan.status,
                "model_calls": plan.model_calls,
                "selected_task_ids": plan.selected_task_ids,
                "new_task_ids": [str(task.get("task_id")) for task in plan.new_tasks],
                "error": plan.error,
            }
            for task in plan.new_tasks:
                ledger.put_task(task)
            if plan.error:
                ledger.add_messages(warnings=[f"screen planner: {plan.error}"])
            pending = ledger.retire_exhausted_tasks(
                ledger.list_tasks(statuses={"pending", "partial"}, kind_prefix="screen"),
                max_attempts=TASK_MAX_ATTEMPTS,
            )
        selected = _select_tasks(pending, plan.selected_task_ids, max_tasks)
        for task in selected:
            task["status"] = "running"
            task["artifact_dir"] = str(artifact_dir)
            task["derived_processed"] = False
            ledger.put_task(task)

        reservation = _state_update(state, ledger, screen_meta, current_node="screen")
        reservation["updated_at"] = utc_now()
        persist(reservation)

        if selected and context is not None:
            results, wave_meta = run_wave(
                selected,
                repository=repository,
                artifact_dir=artifact_dir,
                context=context,
                init_context=_init_context(state),
                ledger=ledger,
                budget=budget,
            )
        elif selected:
            results = [_defer_without_context(task, artifact_dir) for task in selected]
            wave_meta = {"status": "partial", "error": "screen runtime context is unavailable"}
        else:
            results = []
            wave_meta = {"status": "complete", "task_count": 0, "reason": "no pending screen tasks"}

        candidate_before = ledger.count_entries("candidate")
        attempts_before = {
            str(item.get("task_id", "")): int(item.get("attempts", 0)) for item in selected
        }
        for task in results:
            failed = str(task.get("status", "")) != "complete"
            task["attempts"] = attempts_before.get(str(task.get("task_id", "")), 0) + (1 if failed else 0)
            ledger.commit_task(dict(task))

        feature_summary = _process_screen_observations(
            ledger,
            repository,
            results,
            artifact_dir=artifact_dir,
            wave=max(1, int(screen_meta.get("wave", 0)) + 1),
            settings=settings,
        )
        ensure_confirm_tasks_for_candidates(
            ledger,
            artifact_dir=artifact_dir,
            wave=max(1, int(screen_meta.get("wave", 0)) + 1),
            max_candidates=int(getattr(settings, "confirm_max_candidates", 8)) if settings else 8,
        )
        follow_up_created = _ensure_follow_up_tasks(
            ledger,
            results,
            artifact_dir=artifact_dir,
            wave=max(1, int(screen_meta.get("wave", 0)) + 1),
        )
        for task in results:
            task["derived_processed"] = True
            ledger.put_task(task)

        candidate_count = ledger.count_entries("candidate")
        if candidate_count > candidate_before:
            screen_meta["waves_without_new_candidate"] = 0
        else:
            screen_meta["waves_without_new_candidate"] = (
                int(screen_meta.get("waves_without_new_candidate", 0)) + 1
            )

        initial_ids = {
            str(task.get("task_id"))
            for task in ledger.list_tasks(kind_prefix="screen")
            if int(task.get("wave", 0)) == 1
            and str(task.get("view", "")) in {name for name, _, _ in _INITIAL_VIEWS}
        }
        initial_tasks = [
            task for task in ledger.list_tasks(kind_prefix="screen")
            if str(task.get("task_id")) in initial_ids
        ]
        screen_meta["initial_wave_complete"] = bool(initial_ids) and all(
            task.get("status") == "complete" for task in initial_tasks
        )
        executed_wave = max((int(task.get("wave", 0)) for task in selected), default=0)
        screen_meta["wave"] = max(int(screen_meta.get("wave", 0)), executed_wave)
        screen_meta["last_wave"] = {
            **wave_meta,
            "task_ids": [str(task.get("task_id")) for task in selected],
            "completed_task_ids": [
                str(task.get("task_id"))
                for task in results
                if task.get("status") == "complete"
            ],
            "planner": planner_meta,
            "features": feature_summary,
            "follow_up_tasks_created": follow_up_created,
        }
        screen_meta["planner"] = planner_meta
        screen_meta["features"] = feature_summary
        pending_after = ledger.list_tasks(
            statuses={"pending", "partial", "running"}, kind_prefix="screen"
        )
        screen_meta["follow_up_queue"] = [str(task.get("task_id")) for task in pending_after[:100]]
        screen_meta["follow_up_queue_count"] = len(pending_after)

        gaps = [
            f"screen {task.get('task_id', '')}: {message}"
            for task in results
            for message in [*task.get("unknowns", [])[:5], *task.get("deferred", [])[:5]]
        ]
        gaps.extend(
            f"screen {task.get('task_id', '')}: {task['error']}"
            for task in results
            if task.get("error")
        )
        if selected and wave_meta.get("error"):
            gaps.append(f"screen wave: {wave_meta['error']}")
        ledger.add_messages(gaps=gaps, warnings=list(wave_meta.get("warnings", [])))
        candidate_count = ledger.count_entries("candidate")
        unchanged_wave = bool(selected) and ledger.business_digest() == before_digest
        if unchanged_wave:
            message = "screen wave produced no durable progress"
            ledger.add_messages(gaps=[message])
            next_action = "finalize"
            stop_reason = "no_progress"
        else:
            next_action = "confirm" if candidate_count else ("screen" if pending_after else "review")
            stop_reason = "screening_pending" if pending_after else "screen_wave_complete"
        update = _state_update(
            state,
            ledger,
            screen_meta,
            current_node="screen",
            next_action=next_action,
            stop_reason=stop_reason,
        )
        update["updated_at"] = utc_now()
        persist(update)
        write_json(
            artifact_dir / "screen" / "waves" / f"wave-{int(screen_meta['wave']):04d}.json",
            screen_meta["last_wave"],
        )
        logger.info(
            "discover screen wave=%s selected=%s completed=%s candidates=%s pending=%s next=%s",
            screen_meta["wave"],
            len(selected),
            len([task for task in results if task.get("status") == "complete"]),
            candidate_count,
            len(pending_after),
            next_action,
        )
        return update


def _state_update(
    state: DiscoverState,
    ledger: DiscoverLedger,
    screen_meta: dict[str, Any],
    *,
    current_node: str,
    next_action: str | None = None,
    stop_reason: str | None = None,
) -> DiscoverState:
    counts = ledger.file_counts()
    update: DiscoverState = {
        **state,
        "ledger_file": str(ledger.path),
        "file_count": counts.get("total", 0),
        "screened_file_count": counts.get("screened", 0),
        "covered_file_count": counts.get("covered", 0),
        "excluded_file_count": ledger.excluded_count(),
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
        "planner": dict(screen_meta.get("planner", {})),
        "gap_count": ledger.message_count("gaps"),
        "warning_count": ledger.message_count("warnings"),
        "gaps": ledger.messages("gaps"),
        "warnings": ledger.messages("warnings"),
        "screen": screen_meta,
        "current_node": current_node,
    }
    if next_action is not None:
        update["next_action"] = next_action
    if stop_reason is not None:
        update["stop_reason"] = stop_reason
    return update


def _process_screen_observations(
    ledger: DiscoverLedger,
    repository: Path,
    results: list[dict[str, Any]],
    *,
    artifact_dir: Path,
    wave: int,
    settings: Any,
) -> dict[str, Any]:
    observations: list[dict[str, Any]] = []
    read_ranges_by_task: dict[str, list[dict[str, Any]]] = {}
    for task in results:
        task_id = str(task.get("task_id", ""))
        read_ranges_by_task[task_id] = list(task.get("read_ranges", []))
        for item in task.get("feature_observations", []):
            if isinstance(item, dict):
                observations.append({**item, "_source_task_id": task_id})
    if not observations:
        return {"observations": 0}
    summary = process_observations(
        repository,
        ledger,
        observations,
        task_id="screen-wave",
        artifact_dir=artifact_dir,
        wave=wave,
        read_ranges_by_task=read_ranges_by_task,
        max_results=int(getattr(settings, "feature_max_results", 200)) if settings else 200,
        max_tasks=int(getattr(settings, "feature_max_tasks", 32)) if settings else 32,
        timeout=int(getattr(settings, "feature_query_timeout", 30)) if settings else 30,
        max_regex_chars=int(getattr(settings, "feature_max_regex_chars", 512)) if settings else 512,
    )
    return summary


def _replay_unprocessed_tasks(
    ledger: DiscoverLedger,
    repository: Path,
    artifact_dir: Path,
    *,
    wave: int,
    settings: Any,
) -> dict[str, Any]:
    tasks = [
        task
        for task in ledger.list_tasks(kind_prefix="screen")
        if not bool(task.get("derived_processed", False))
        and (
            task.get("feature_observations")
            or (task.get("status") == "complete" and task.get("follow_up"))
        )
    ]
    if not tasks:
        return {
            "tasks": 0,
            "features": {"observations": 0},
            "follow_up_tasks_created": 0,
        }
    features = _process_screen_observations(
        ledger,
        repository,
        tasks,
        artifact_dir=artifact_dir,
        wave=wave,
        settings=settings,
    )
    follow_up_created = _ensure_follow_up_tasks(
        ledger,
        tasks,
        artifact_dir=artifact_dir,
        wave=wave,
    )
    for task in tasks:
        task["derived_processed"] = True
        ledger.put_task(task)
    return {
        "tasks": len(tasks),
        "features": features,
        "follow_up_tasks_created": follow_up_created,
    }


def _ensure_follow_up_tasks(
    ledger: DiscoverLedger,
    results: list[dict[str, Any]],
    *,
    artifact_dir: Path,
    wave: int,
) -> int:
    created = 0
    for task in results:
        if task.get("status") != "complete":
            continue
        task_id = str(task.get("task_id", ""))
        for index, item in enumerate(task.get("follow_up", [])):
            if not isinstance(item, dict):
                continue
            paths = [str(path) for path in item.get("paths", []) if str(path).strip()]
            if not paths:
                continue
            question = str(item.get("question", "Inspect related source scope."))
            key = hashlib.sha256(f"{task_id}:{index}:{question}".encode()).hexdigest()[:16]
            before = ledger.task_count()
            ledger.ensure_screen_task(
                paths=paths,
                question=question,
                reason=str(item.get("reason", "screen follow-up")),
                origin="screen_followup",
                parent_task_id=task_id,
                follow_up_key=key,
                artifact_dir=str(artifact_dir),
                wave=wave,
            )
            created += max(0, ledger.task_count() - before)
    return created


def _restore_completed_tasks(
    ledger: DiscoverLedger, artifact_dir: Path
) -> list[dict[str, Any]]:
    restored: list[dict[str, Any]] = []
    for task in ledger.list_tasks(kind_prefix="screen"):
        if task.get("status") not in {"pending", "running"}:
            continue
        task_id = str(task.get("task_id", ""))
        path = artifact_dir / "screen" / "tasks" / f"{task_id}.json"
        if not path.is_file():
            continue
        try:
            saved = load_json(path)
        except ValueError:
            continue
        if saved.get("task_id") == task_id and saved.get("status") == "complete":
            logger.info("discover screen restored completed task task_id=%s", task_id)
            ledger.commit_task(saved)
            restored.append(saved)
    return restored


def _ensure_initial_tasks(ledger: DiscoverLedger, screen_meta: dict[str, Any], artifact_dir: Path) -> None:
    if screen_meta.get("initial_wave_complete"):
        return
    existing_views = {
        str(task.get("view"))
        for task in ledger.list_tasks(kind_prefix="screen")
        if int(task.get("wave", 0)) == 1 and task.get("view")
    }
    production_count = ledger.file_counts().get("production_text", 0)
    if production_count == 0:
        return
    next_number = _next_task_number(ledger.list_tasks())
    for view, independent, question in _INITIAL_VIEWS:
        if view in existing_views:
            continue
        ledger.put_task(
            {
                "task_id": f"screen-{next_number:04d}",
                "kind": "screen",
                "status": "pending",
                "question": question,
                "attempts": 0,
                "depends_on": [],
                "wave": 1,
                "view": view,
                "independent": independent,
                "coverage_required": False,
                "scope_type": "production-text",
                "scope_count": production_count,
                "read_ranges": [],
                "tool_receipts": [],
                "candidates": [],
                "negative_results": [],
                "unknowns": [],
                "deferred": [],
                "follow_up": [],
                "artifact_dir": str(artifact_dir),
            }
        )
        next_number += 1


def _next_task_number(tasks: list[dict[str, Any]]) -> int:
    numbers = []
    for task in tasks:
        try:
            numbers.append(int(str(task.get("task_id", "")).rsplit("-", 1)[1]))
        except (IndexError, ValueError):
            continue
    return max(numbers, default=0) + 1


def _has_planning_material(ledger: DiscoverLedger) -> bool:
    if ledger.count_entries("candidate"):
        return True
    if ledger.eligible_paths(limit=1, uncovered_only=True):
        return True
    return any(task.get("follow_up") for task in ledger.list_tasks(kind_prefix="screen"))


def _select_tasks(
    pending: list[dict[str, Any]],
    selected_ids: list[str],
    max_tasks: int,
) -> list[dict[str, Any]]:
    if not pending or max_tasks <= 0:
        return []
    by_id = {str(task.get("task_id")): task for task in pending}
    ordered = [by_id[task_id] for task_id in selected_ids if task_id in by_id]
    ordered.extend(task for task in pending if str(task.get("task_id")) not in set(selected_ids))
    return ordered[: max(1, max_tasks)]


def _init_context(state: DiscoverState) -> dict[str, Any]:
    reference = state.get("init_reference", {})
    if not isinstance(reference, dict):
        return {}
    return {
        "status": reference.get("status", "unknown"),
        "documents": reference.get("documents", {}),
        "security_history": reference.get("security_history", {}),
        "checks": reference.get("checks", {}),
    }


def _defer_without_context(task: dict[str, Any], artifact_dir: Path) -> dict[str, Any]:
    result = dict(task)
    result["status"] = "pending"
    result["attempts"] = int(result.get("attempts", 0)) + 1
    result["error"] = "screen runtime context is unavailable"
    result["unknowns"] = [result["error"]]
    result["deferred"] = [result["error"]]
    result["result"] = {
        "parse_status": "deferred",
        "coverage_complete": False,
        "candidates": [],
        "negative_results": [],
        "unknowns": result["unknowns"],
        "deferred": result["deferred"],
        "follow_up": [],
    }
    write_json(artifact_dir / "screen" / "tasks" / f"{result.get('task_id', 'unknown')}.json", result)
    return result


def _entry_id(candidate: dict[str, Any]) -> str:
    return "entry-" + hashlib.sha256(
        f"{candidate.get('path')}:{candidate.get('line_start')}:{candidate.get('line_end')}:{candidate.get('kind')}".encode()
    ).hexdigest()[:16]


def _evidence_id(candidate: dict[str, Any]) -> str:
    return "evidence-" + hashlib.sha256(
        f"{candidate.get('path')}:{candidate.get('line_start')}:{candidate.get('line_end')}:{candidate.get('summary')}".encode()
    ).hexdigest()[:16]
