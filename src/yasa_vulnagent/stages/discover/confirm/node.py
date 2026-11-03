from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any

from langgraph.runtime import Runtime

from ....agent.context import compact_json
from ....agent.runtime import run_coroutine
from ....observability import trace_node
from ....storage import utc_now
from ....workflow.state import RunContext
from ..agent import TASK_MAX_ATTEMPTS, run_task_agent, task_tool_store
from ..evidence import validate_location, validate_refs
from ..features import (
    ensure_confirm_tasks_for_candidates,
    process_observations,
)
from ..ledger import DiscoverLedger
from ..schema import DiscoverState
from ..storage import persist, write_json
from ..screen.graph import ScreenBudget
from ..screen.model import ScreenConfigurationError, build_configured_model
from ..screen.tools import ReadCache, SourceToolbox, YasaToolbox
from ..screen.mcp import open_yasa_mcp


logger = logging.getLogger(__name__)
_TERMINAL = {"confirmed", "not_applicable", "unknown", "deferred"}
_FIELDS = ("input_origin", "registration", "activation", "input_binding", "trust_boundary")
_ROLES = {"source", "registration", "activation", "binding", "boundary", "unknown"}


def _load_prompt() -> str:
    return files("yasa_vulnagent.stages.discover.confirm").joinpath("prompt.md").read_text(
        encoding="utf-8"
    )


def _parse_json(response: str) -> Any:
    text = str(response).strip()
    fenced = re.search(r"```(?:json)?\s*(.*?)```", text, flags=re.IGNORECASE | re.DOTALL)
    if fenced:
        text = fenced.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                return None
    return None


def _text(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("summary", value.get("value", "")))[:4000]
    return str(value or "")[:4000]


def _flatten_refs(value: Any) -> list[str]:
    if isinstance(value, dict):
        result: list[str] = []
        for item in value.values():
            result.extend(_flatten_refs(item))
        return result
    if isinstance(value, list):
        result = []
        for item in value:
            result.extend(_flatten_refs(item))
        return result
    return [str(value)] if str(value).strip() else []


def _refs(value: Any, fallback: Any = None) -> list[str]:
    raw = value.get("evidence_refs", []) if isinstance(value, dict) else value
    if not isinstance(raw, (list, dict)):
        raw = fallback if isinstance(fallback, (list, dict)) else []
    return _flatten_refs(raw)


def _field(result: dict[str, Any], name: str) -> tuple[str, list[str]]:
    value = result.get(name)
    refs = result.get("evidence_refs")
    if isinstance(refs, dict):
        fallback = refs.get(name, [])
    elif isinstance(refs, list) and not isinstance(value, dict):
        fallback = refs
    else:
        fallback = []
    return _text(value), _refs(value, fallback)


def _simple_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item)[:2000] for item in value if str(item).strip()]


def _task_paths(ledger: DiscoverLedger, task: dict[str, Any]) -> list[str]:
    paths = ledger.task_scope_paths(str(task.get("task_id", "")))
    if paths:
        return paths
    return [str(item) for item in task.get("paths", []) if str(item).strip()]


def _task_context(
    ledger: DiscoverLedger,
    task: dict[str, Any],
    *,
    limit: int = 40000,
) -> str:
    candidate_ids = [str(item) for item in task.get("candidate_ids", [])]
    entries = [ledger.get_entry(entry_id) for entry_id in candidate_ids]
    context: dict[str, Any] = {
        "task_id": task.get("task_id", ""),
        "origin": task.get("origin", "candidate"),
        "question": task.get("question", ""),
        "paths": _task_paths(ledger, task),
        "candidates": [
            {
                "entry_id": str(entry.get("entry_id", "")),
                "path": str((entry.get("location") or {}).get("path", "")),
                "line_start": (entry.get("location") or {}).get("line_start"),
                "line_end": (entry.get("location") or {}).get("line_end"),
                "summary": str(entry.get("summary", ""))[:300],
            }
            for entry in entries
            if entry
        ],
        "source_policy": (
            "Read source to confirm. Do not confirm from a candidate summary alone. "
            "Keep broad cross-file work in screen_scope."
        ),
    }
    if int(task.get("attempts", 0)) > 1:
        context["attempts"] = int(task.get("attempts", 0))
        if task.get("error"):
            context["last_error"] = str(task["error"])[:1000]
    prior = ledger.prior_context_for_task(str(task.get("task_id", "")), limit=10)
    if prior:
        context["prior_findings"] = {
            **prior,
            "notice": (
                "Leads from other tasks in the same scope; they are not established facts. "
                "Verify against source before reusing them."
            ),
        }
    return compact_json(context, limit, drop_keys=("priority_hints",))


def _checklist_hint(ledger: DiscoverLedger, task: dict[str, Any]) -> str:
    """Remind the model which candidates still need an entry result after compaction."""
    candidate_ids = [str(item) for item in task.get("candidate_ids", [])]
    if not candidate_ids:
        return ""
    lines = ["Candidate checklist (one entry_result per pending candidate is required):"]
    for entry_id in candidate_ids:
        entry = ledger.get_entry(entry_id) or {}
        status = str(entry.get("status", "candidate"))
        location = entry.get("location") if isinstance(entry.get("location"), dict) else {}
        marker = "pending" if status == "candidate" else f"{status}, no resubmission needed"
        lines.append(
            f"- {entry_id} [{marker}] {location.get('path', '')}:"
            f"{location.get('line_start', '')}-{location.get('line_end', '')} | "
            f"{str(entry.get('summary', ''))[:120]}"
        )
    return "\n".join(lines)


def _hint_text(source: Any, ledger: DiscoverLedger, task: dict[str, Any]) -> str:
    notes = source.notes_text()
    checklist = _checklist_hint(ledger, task)
    return "\n\n".join(item for item in (notes, checklist) if item)


def _validate_field(
    repository: Path,
    ledger: DiscoverLedger,
    result: dict[str, Any],
    name: str,
) -> tuple[dict[str, Any] | None, list[str]]:
    summary, refs = _field(result, name)
    errors: list[str] = []
    if not summary.strip():
        errors.append(f"{name} is empty")
    canonical, ref_errors = validate_refs(repository, ledger, refs)
    errors.extend(ref_errors)
    if not refs:
        errors.append(f"{name} has no evidence_refs")
    if errors:
        return None, errors
    return {"summary": summary, "evidence_refs": canonical}, []


def _invalid_unknown(
    result: dict[str, Any],
    entries: dict[str, dict[str, Any]],
    entry_id: str,
    reason: str,
) -> dict[str, Any]:
    location = entries[entry_id].get("location") if isinstance(entries[entry_id].get("location"), dict) else {}
    return {
        "entry_id": entry_id,
        "status": "unknown",
        "role": str(result.get("role", entries[entry_id].get("role", "unknown"))),
        "summary": str(result.get("summary", ""))[:4000],
        "location": dict(location),
        "reason": reason[:2000],
        "owner": str(result.get("owner", "confirm"))[:200],
        "attempts": _simple_list(result.get("attempts")) or [reason[:1000]],
        "reopen_condition": str(result.get("reopen_condition", "new source evidence is available"))[:1000],
        "evidence_refs": [],
        "same_file_reviewed": bool(result.get("same_file_reviewed", False)),
    }


def _normalize_entry_result(
    repository: Path,
    ledger: DiscoverLedger,
    *,
    result: dict[str, Any],
    entry: dict[str, Any],
    same_file_reviewed: bool,
) -> tuple[dict[str, Any] | None, list[str], list[str]]:
    entry_id = str(result.get("entry_id", ""))
    errors: list[str] = []
    warnings: list[str] = []
    status = str(result.get("status", ""))
    if entry_id != str(entry.get("entry_id", "")):
        return None, [f"entry result does not match the task candidate: {entry_id}"], warnings
    role = str(result.get("role", entry.get("role", "unknown")))
    if role not in _ROLES:
        role = "unknown"
    location = result.get("location") if isinstance(result.get("location"), dict) else {}
    path = str(location.get("path", "")) or str((entry.get("location") or {}).get("path", ""))
    start = int(location.get("line_start", 0) or (entry.get("location") or {}).get("line_start", 0) or 0)
    end = int(location.get("line_end", 0) or (entry.get("location") or {}).get("line_end", 0) or 0)
    location_result = validate_location(repository, ledger, path=path, start=start, end=end)
    if not location_result.get("ok"):
        errors.append(str(location_result.get("error", "invalid entry location")))
        return None, errors, warnings
    base = {
        "entry_id": entry_id,
        "status": status,
        "role": role,
        "summary": str(result.get("summary", ""))[:4000],
        "location": {
            "path": str(location_result.get("path", path)),
            "line_start": start,
            "line_end": end,
        },
        "same_file_reviewed": same_file_reviewed,
        "reopen_condition": str(result.get("reopen_condition", ""))[:1000],
        "owner": str(result.get("owner", ""))[:200],
        "attempts": _simple_list(result.get("attempts")),
        "reason": str(result.get("reason", ""))[:2000],
        "evidence_refs": [],
    }
    if status == "confirmed":
        if not same_file_reviewed:
            errors.append("confirmed entry requires same_file_reviewed=true")
            return None, errors, warnings
        if errors:
            warnings.append(f"{entry_id}: confirmed downgraded: {'; '.join(errors)}")
            return _invalid_unknown(result, {entry_id: entry}, entry_id, "; ".join(errors)), [], warnings
        canonical, ref_errors = validate_refs(
            repository, ledger, _flatten_refs(result.get("evidence_refs"))
        )
        errors.extend(ref_errors)
        for name in _FIELDS:
            field, field_errors = _validate_field(repository, ledger, result, name)
            if field_errors:
                errors.extend(field_errors)
            else:
                base[name] = field
        if errors:
            warnings.append(f"{entry_id}: confirmed downgraded: {'; '.join(errors)}")
            return _invalid_unknown(result, {entry_id: entry}, entry_id, "; ".join(errors)), [], warnings
        base["evidence_refs"] = canonical
        base["status"] = "confirmed"
        return base, [], warnings
    if status == "not_applicable":
        canonical, ref_errors = validate_refs(repository, ledger, _refs(result.get("evidence_refs")))
        errors.extend(ref_errors)
        if not base["reason"]:
            errors.append("not_applicable requires reason")
        if not canonical:
            errors.append("not_applicable requires evidence_refs")
        if errors:
            return None, errors, warnings
        base["evidence_refs"] = canonical
        return base, [], warnings
    if status == "unknown":
        if not base["reason"]:
            errors.append("unknown requires reason")
        if not base["owner"]:
            errors.append("unknown requires owner")
        if not base["attempts"]:
            errors.append("unknown requires attempts")
        if not base["reopen_condition"]:
            errors.append("unknown requires reopen_condition")
        canonical, ref_errors = validate_refs(repository, ledger, _refs(result.get("evidence_refs")))
        errors.extend(ref_errors)
        if not canonical:
            errors.append("unknown requires evidence_refs")
        if errors:
            return None, errors, warnings
        base["evidence_refs"] = canonical
        return base, [], warnings
    if status == "deferred":
        if not base["reason"]:
            errors.append("deferred requires reason")
        if not base["owner"]:
            errors.append("deferred requires owner")
        if not base["reopen_condition"]:
            errors.append("deferred requires reopen_condition")
        canonical, ref_errors = validate_refs(repository, ledger, _refs(result.get("evidence_refs")))
        errors.extend(ref_errors)
        if not canonical:
            errors.append("deferred requires evidence_refs")
        if errors:
            return None, errors, warnings
        base["evidence_refs"] = canonical
        return base, [], warnings
    return None, [f"unsupported confirm status: {status}"], warnings


def _apply_task_result(
    repository: Path,
    ledger: DiscoverLedger,
    task: dict[str, Any],
    parsed: dict[str, Any],
) -> dict[str, Any]:
    candidate_ids = [str(item) for item in task.get("candidate_ids", [])]
    entries = {
        entry_id: ledger.get_entry(entry_id) or {"entry_id": entry_id}
        for entry_id in candidate_ids
    }
    raw_results = parsed.get("entry_results", [])
    results = [item for item in raw_results if isinstance(item, dict)] if isinstance(raw_results, list) else []
    same_file_reviewed = bool(parsed.get("same_file_reviewed", False))
    applied: list[dict[str, Any]] = []
    errors: list[str] = []
    warnings: list[str] = []
    by_id = {str(item.get("entry_id", "")): item for item in results}
    for entry_id in candidate_ids:
        result = by_id.get(entry_id)
        if result is None:
            if str(entries.get(entry_id, {}).get("status", "candidate")) != "candidate":
                # Already resolved by an earlier attempt; resubmitting is not required.
                continue
            errors.append(f"missing entry result for {entry_id}")
            continue
        normalized, entry_errors, entry_warnings = _normalize_entry_result(
            repository,
            ledger,
            result=result,
            entry=entries[entry_id],
            same_file_reviewed=same_file_reviewed,
        )
        warnings.extend(entry_warnings)
        if normalized is None:
            errors.extend(f"{entry_id}: {error}" for error in entry_errors)
            continue
        updates = dict(normalized)
        updates.pop("entry_id", None)
        updates.pop("status", None)
        ledger.update_entry(entry_id, status=str(normalized["status"]), updates=updates)
        applied.append(normalized)
    extra = len(results) - len(candidate_ids)
    if extra > 0:
        warnings.append(f"{extra} entry result(s) were outside the task candidate scope")
    task["entry_results"] = applied
    task["same_file_reviewed"] = same_file_reviewed
    task["feature_observations"] = [
        item for item in parsed.get("feature_observations", []) if isinstance(item, dict)
    ]
    task["unknowns"] = [*task.get("unknowns", []), *errors]
    task["warnings"] = warnings
    applied_ids = {str(item.get("entry_id")) for item in applied}
    terminal = all(entry_id in applied_ids for entry_id in candidate_ids)
    confirmed_ok = all(
        bool(item.get("same_file_reviewed", False))
        for item in applied
        if item.get("status") == "confirmed"
    )
    task["status"] = "complete" if not errors and terminal and confirmed_ok else "partial"
    return task


def _expand_after_task(
    ledger: DiscoverLedger,
    task: dict[str, Any],
    parsed: dict[str, Any],
    *,
    artifact_dir: Path,
    wave: int,
    max_same_file: int,
) -> dict[str, int]:
    created = {"confirm": 0, "screen": 0}
    current_paths = set(ledger.task_scope_paths(str(task.get("task_id", ""))))
    raw_same = parsed.get("same_file_targets", [])
    if isinstance(raw_same, list):
        for item in raw_same[: max(0, int(max_same_file))]:
            if not isinstance(item, dict):
                continue
            path = str(item.get("path", "")).removeprefix("./")
            if not path or (current_paths and path not in current_paths):
                continue
            before = ledger.task_count()
            ledger.ensure_confirm_task(
                path=path,
                candidate_ids=[],
                origin="same_file",
                question=str(item.get("question", "Inspect uncovered same-file entry scope."))[:2000],
                artifact_dir=str(artifact_dir),
                wave=wave,
                exclude_task_id=str(task.get("task_id", "")),
            )
            created["confirm"] += max(0, ledger.task_count() - before)
    raw_screen = parsed.get("screen_scope", [])
    if isinstance(raw_screen, list):
        for item in raw_screen[:4]:
            if not isinstance(item, dict):
                continue
            paths = [
                str(path).removeprefix("./")
                for path in item.get("paths", [])
                if str(path).strip()
            ]
            paths = [
                path for path in paths
                if (ledger.get_file(path) or {}).get("usage_hint") == "production-candidate"
                and (ledger.get_file(path) or {}).get("content_type") == "text"
            ]
            if not paths:
                continue
            before = ledger.task_count()
            ledger.ensure_screen_task(
                paths=paths,
                question=str(item.get("question", "Inspect broad related entry scope."))[:2000],
                reason=str(item.get("reason", "confirm requested broader screen scope"))[:2000],
                origin="confirm_scope",
                parent_task_id=str(task.get("task_id", "")),
                artifact_dir=str(artifact_dir),
                wave=wave,
            )
            created["screen"] += max(0, ledger.task_count() - before)
    return created


async def _run_one(
    task: dict[str, Any],
    *,
    repository: Path,
    model: Any,
    budget: ScreenBudget,
    ledger: DiscoverLedger,
    settings: Any,
    yasa_session: Any,
    production_paths: list[str],
    usage: Any | None = None,
    store: Any | None = None,
    cache: ReadCache | None = None,
) -> dict[str, Any]:
    source = SourceToolbox(
        repository,
        allowed_paths=production_paths,
        max_output_chars=settings.screen_tool_output_chars,
        cache=cache,
        notes_max=settings.discover_notes_max,
        note_chars=settings.discover_note_chars,
        search_max_file_bytes=settings.discover_search_max_file_bytes,
        max_scan_files=settings.discover_search_max_scan_files,
    )
    tools: list[Any] = source.langchain_tools()
    yasa = None
    if yasa_session is not None:
        yasa = YasaToolbox(
            yasa_session,
            repository,
            max_output_chars=settings.screen_tool_output_chars,
            budget=budget,
        )
        tools.extend(yasa.langchain_tools())
    system_prompt = _load_prompt()
    try:
        result = await run_task_agent(
            model=model,
            system_prompt=system_prompt,
            user_prompt=_task_context(ledger, task, limit=settings.screen_context_chars),
            tools=tools,
            budget=budget,
            usage=usage,
            stage="discover.confirm",
            task_id=str(task.get("task_id", "")),
            store=store or task_tool_store(Path(str(task.get("artifact_dir", ".")))),
            settings=settings,
            max_rounds=16,
            notes_provider=lambda: _hint_text(source, ledger, task),
        )
    except Exception as exc:
        task["read_ranges"] = [item for item in source.receipts if item.get("tool") == "read_file"]
        task["tool_receipts"] = [*source.receipts, *(yasa.receipts if yasa is not None else [])]
        task["error"] = str(exc)[:1000]
        task["status"] = "partial"
        task["stop_reason"] = "error"
        return task
    task["read_ranges"] = [item for item in source.receipts if item.get("tool") == "read_file"]
    task["tool_receipts"] = [*source.receipts, *(yasa.receipts if yasa is not None else [])]
    task["stop_reason"] = result.stop_reason
    task["rounds"] = result.rounds
    task["model_calls"] = result.model_calls
    task["compactions"] = result.compactions
    task["agent_receipts"] = list(result.receipts)[:50]
    if result.stop_reason != "complete":
        task["partial_summary"] = (result.last_text or result.content)[:4000]
    parsed = _parse_json(result.content)
    if not isinstance(parsed, dict):
        task["error"] = "confirm model did not return a JSON object"
        task["status"] = "partial"
        task["unknowns"] = [task["error"]]
        return task
    task = _apply_task_result(repository, ledger, task, parsed)
    _expand_after_task(
        ledger,
        task,
        parsed,
        artifact_dir=Path(str(task.get("artifact_dir", "."))),
        wave=int(task.get("wave", 0)),
        max_same_file=int(settings.confirm_max_same_file),
    )
    return task


def _process_confirm_observations(
    ledger: DiscoverLedger,
    repository: Path,
    tasks: list[dict[str, Any]],
    *,
    artifact_dir: Path,
    wave: int,
    settings: Any,
) -> dict[str, Any]:
    observations: list[dict[str, Any]] = []
    read_ranges_by_task: dict[str, list[dict[str, Any]]] = {}
    for task in tasks:
        task_id = str(task.get("task_id", ""))
        read_ranges_by_task[task_id] = list(task.get("read_ranges", []))
        for item in task.get("feature_observations", []):
            if isinstance(item, dict):
                observations.append({**item, "_source_task_id": task_id})
    if not observations:
        return {"observations": 0}
    return process_observations(
        repository,
        ledger,
        observations,
        task_id="confirm-wave",
        artifact_dir=artifact_dir,
        wave=wave,
        read_ranges_by_task=read_ranges_by_task,
        max_results=int(getattr(settings, "feature_max_results", 200)) if settings else 200,
        max_tasks=int(getattr(settings, "feature_max_tasks", 32)) if settings else 32,
        timeout=int(getattr(settings, "feature_query_timeout", 30)) if settings else 30,
        max_regex_chars=int(getattr(settings, "feature_max_regex_chars", 512)) if settings else 512,
    )


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
        for task in ledger.list_tasks(kind_prefix="confirm")
        if not bool(task.get("derived_processed", False))
        and task.get("feature_observations")
    ]
    if not tasks:
        return {"tasks": 0, "features": {"observations": 0}}
    features = _process_confirm_observations(
        ledger,
        repository,
        tasks,
        artifact_dir=artifact_dir,
        wave=wave,
        settings=settings,
    )
    for task in tasks:
        task["derived_processed"] = True
        ledger.put_task(task)
    return {"tasks": len(tasks), "features": features}


@trace_node("discover.confirm")
def confirm(
    state: DiscoverState,
    runtime: Runtime[RunContext] | None = None,
) -> dict[str, object]:
    context = runtime.context if runtime is not None else None
    artifact_dir = Path(state["artifact_dir"])
    repository = Path(state["repository"])
    confirm_meta = dict(state.get("confirm", {}))
    with DiscoverLedger.open(Path(state["ledger_file"])) as ledger:
        settings = context.settings if context is not None else None
        ledger.recover_running_tasks()
        replayed = _replay_unprocessed_tasks(
            ledger,
            repository,
            artifact_dir,
            wave=max(1, int(state.get("screen", {}).get("wave", 1))),
            settings=settings,
        )
        if replayed["tasks"]:
            logger.info("discover confirm recovery replayed=%s", replayed["tasks"])
        ensure_confirm_tasks_for_candidates(
            ledger,
            artifact_dir=artifact_dir,
            wave=max(1, int(state.get("screen", {}).get("wave", 1))),
            max_candidates=int(getattr(settings, "confirm_max_candidates", 8)) if settings else 8,
        )
        pending = ledger.retire_exhausted_tasks(
            ledger.list_tasks(statuses={"pending", "partial", "running"}, kind_prefix="confirm"),
            max_attempts=TASK_MAX_ATTEMPTS,
        )
        selected = pending[: max(1, int(getattr(settings, "confirm_max_tasks", 6)) if settings else 6)]
        for task in selected:
            task["status"] = "running"
            task["artifact_dir"] = str(artifact_dir)
            task["derived_processed"] = False
            ledger.put_task(task)
        update = _state_update(state, ledger, confirm_meta, current_node="confirm")
        update["updated_at"] = utc_now()
        persist(update)
        if not selected:
            update = _state_update(
                state,
                ledger,
                confirm_meta,
                current_node="confirm",
                next_action="review",
                stop_reason="confirm_queue_empty",
            )
            update["updated_at"] = utc_now()
            persist(update)
            return update
        if context is None:
            errors = ["confirm runtime context is unavailable"]
            for task in selected:
                task["status"] = "pending"
                task["error"] = errors[0]
                ledger.put_task(task)
            ledger.add_messages(gaps=errors)
            update = _state_update(
                state,
                ledger,
                confirm_meta,
                current_node="confirm",
                next_action="review",
                stop_reason="confirm_context_unavailable",
            )
            update["updated_at"] = utc_now()
            persist(update)
            return update
        budget = ScreenBudget(
            deadline=time.monotonic() + max(1, int(settings.confirm_timeout)),
            model_calls_limit=max(1, int(settings.confirm_max_calls)),
        )
        try:
            model = build_configured_model(
                context,
                model_name=settings.confirm_model,
                timeout=settings.confirm_timeout,
            )
        except ScreenConfigurationError as exc:
            errors = [str(exc)]
            for task in selected:
                task["status"] = "pending"
                task["error"] = errors[0]
                ledger.put_task(task)
            ledger.add_messages(gaps=errors)
            update = _state_update(
                state,
                ledger,
                confirm_meta,
                current_node="confirm",
                next_action="review",
                stop_reason="confirm_model_unavailable",
            )
            update["updated_at"] = utc_now()
            persist(update)
            return update
        production_paths = [
            str(file.get("path", ""))
            for file in ledger.iter_files(limit=1000)
            if file.get("usage_hint") == "production-candidate"
            and file.get("content_type") == "text"
            and file.get("status") != "unavailable"
        ]

        store = task_tool_store(artifact_dir)
        cache = ReadCache()

        async def execute() -> tuple[list[dict[str, Any]], dict[str, Any]]:
            async with open_yasa_mcp(settings, repository) as session:
                results = await asyncio.gather(
                    *(
                        _run_one(
                            task,
                            repository=repository,
                            model=model,
                            budget=budget,
                            ledger=ledger,
                            settings=settings,
                            yasa_session=session,
                            production_paths=production_paths,
                            usage=context.usage,
                            store=store,
                            cache=cache,
                        )
                        for task in selected
                    ),
                    return_exceptions=True,
                )
                normalized = []
                for task, result in zip(selected, results):
                    if isinstance(result, Exception):
                        task["status"] = "partial"
                        task["error"] = str(result)[:1000]
                        normalized.append(task)
                    else:
                        normalized.append(dict(result))
                return normalized, {
                    "status": "complete" if all(item.get("status") == "complete" for item in normalized) else "partial",
                    "task_count": len(normalized),
                    "budget": budget.snapshot(),
                    "yasa_mcp": "available" if session is not None else "unavailable",
                }

        results, wave_meta = run_coroutine(execute())
        attempts_before = {
            str(item.get("task_id", "")): int(item.get("attempts", 0)) for item in selected
        }
        for task in results:
            failed = str(task.get("status", "")) != "complete"
            task["attempts"] = attempts_before.get(str(task.get("task_id", "")), 0) + (1 if failed else 0)
            ledger.commit_task(dict(task))
            write_json(artifact_dir / "confirm" / "tasks" / f"{task.get('task_id', 'unknown')}.json", task)
        feature_summary = _process_confirm_observations(
            ledger,
            repository,
            results,
            artifact_dir=artifact_dir,
            wave=max(1, int(state.get("screen", {}).get("wave", 1))),
            settings=settings,
        )
        for task in results:
            task["derived_processed"] = True
            ledger.put_task(task)
        pending_after = ledger.list_tasks(
            statuses={"pending", "partial", "running"}, kind_prefix="confirm"
        )
        confirm_meta["wave"] = int(confirm_meta.get("wave", 0)) + 1
        confirm_meta["last_wave"] = {
            **wave_meta,
            "task_ids": [str(task.get("task_id")) for task in selected],
            "features": feature_summary,
        }
        confirm_meta["features"] = feature_summary
        confirm_meta["follow_up_queue_count"] = len(pending_after)
        candidate_count = ledger.count_entries("candidate")
        if pending_after:
            next_action = "review"
            stop_reason = "confirm_pending"
        elif candidate_count:
            next_action = "review"
            stop_reason = "confirm_queue_empty"
        else:
            next_action = "review"
            stop_reason = "confirm_complete"
        update = _state_update(
            state,
            ledger,
            confirm_meta,
            current_node="confirm",
            next_action=next_action,
            stop_reason=stop_reason,
        )
        update["updated_at"] = utc_now()
        persist(update)
        write_json(artifact_dir / "confirm" / "latest.json", confirm_meta["last_wave"])
        return update


def _state_update(
    state: DiscoverState,
    ledger: DiscoverLedger,
    confirm_meta: dict[str, Any],
    *,
    current_node: str,
    next_action: str | None = None,
    stop_reason: str | None = None,
) -> DiscoverState:
    update: DiscoverState = {
        **state,
        "ledger_file": str(ledger.path),
        "task_count": ledger.task_count(),
        "pending_task_count": ledger.pending_task_count(),
        "entry_count": ledger.count_entries(),
        "confirmed_entry_count": ledger.count_entries("confirmed"),
        "unknown_entry_count": ledger.count_entries("unknown"),
        "deferred_entry_count": ledger.count_entries("deferred"),
        "debt_count": ledger.debt_count(),
        "feature_debt_count": ledger.feature_debt_count(),
        "mechanism_count": ledger.count_mechanisms(),
        "feature_query_count": ledger.count_feature_queries(),
        "feature_hit_count": ledger.count_feature_hits(),
        "handoff_count": len(ledger.open_handoffs()),
        "confirm": confirm_meta,
        "current_node": current_node,
    }
    if next_action is not None:
        update["next_action"] = next_action
    if stop_reason is not None:
        update["stop_reason"] = stop_reason
    return update
