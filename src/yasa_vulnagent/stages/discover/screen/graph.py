from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.runtime import Runtime

from ....agent.context import compact_json
from ....config import DEFAULT_SCREEN_TASK_MAX_ROUNDS
from ....workflow.state import RunContext
from ..agent import run_task_agent, task_tool_store
from ..ledger import DiscoverLedger
from ..schema import TaskRecord
from ..storage import write_json
from .model import ScreenConfigurationError, load_prompt
from .tools import SourceToolbox, YasaToolbox


logger = logging.getLogger(__name__)
_MAX_SUMMARY_CHARS = 4000
_MAX_ERROR_CHARS = 1000
_ISOLATED_VIEWS = frozenset({"component-runtime", "input-boundary", "independent-exploration"})
_CONTEXT_DROP_KEYS = (
    "init_context.details",
    "init_context.checks",
    "init_context.security_history",
    "init_context.documents.chunks",
)


class ScreenTaskState(TypedDict, total=False):
    task: TaskRecord
    response: str
    result: dict[str, Any]
    status: str
    error: str


@dataclass
class ScreenBudget:
    """A single wave-wide budget shared by all concurrent task contexts."""

    deadline: float
    model_calls_limit: int
    model_calls: int = 0

    def __post_init__(self) -> None:
        import threading

        self._lock = threading.Lock()

    def consume_model_call(self) -> bool:
        import time

        with self._lock:
            if time.monotonic() >= self.deadline or self.model_calls >= self.model_calls_limit:
                return False
            self.model_calls += 1
            return True

    def snapshot(self) -> dict[str, Any]:
        import time

        with self._lock:
            return {
                "model_calls": self.model_calls,
                "model_calls_limit": self.model_calls_limit,
                "remaining_seconds": max(0.0, self.deadline - time.monotonic()),
            }

    def remaining_seconds(self) -> float:
        import time

        with self._lock:
            return max(0.0, self.deadline - time.monotonic())


@dataclass
class ScreenExecution:
    repository: Path
    artifact_dir: Path
    model: Any
    budget: ScreenBudget
    init_context: dict[str, Any]
    ledger: DiscoverLedger
    settings: Any
    mcp_session: Any | None = None
    max_output_chars: int = 12000
    context_chars: int = 40000
    usage: Any | None = None
    store: Any | None = None
    cache: Any | None = None
    max_rounds: int = DEFAULT_SCREEN_TASK_MAX_ROUNDS

    def tools_for(self, task: TaskRecord) -> tuple[list[Any], SourceToolbox, YasaToolbox | None]:
        source = SourceToolbox(
            self.repository,
            ledger=self.ledger,
            task_id=str(task.get("task_id", "")),
            max_output_chars=self.max_output_chars,
            cache=self.cache,
            notes_max=self.settings.discover_notes_max,
            note_chars=self.settings.discover_note_chars,
            search_max_file_bytes=self.settings.discover_search_max_file_bytes,
            max_scan_files=self.settings.discover_search_max_scan_files,
        )
        tools: list[Any] = source.langchain_tools()
        yasa: YasaToolbox | None = None
        if self.mcp_session is not None:
            yasa = YasaToolbox(
                self.mcp_session,
                self.repository,
                max_output_chars=self.max_output_chars,
                budget=self.budget,
            )
            tools.extend(yasa.langchain_tools())
        return tools, source, yasa

    async def analyze(self, task: TaskRecord) -> tuple[Any, SourceToolbox, YasaToolbox | None]:
        task["scope_count"] = self.ledger.scope_count(task)
        tools, source, yasa = self.tools_for(task)
        system_prompt = load_prompt("screen.md")
        context = _task_context(task, self.init_context, self.context_chars, ledger=self.ledger)
        try:
            result = await run_task_agent(
                model=self.model,
                system_prompt=system_prompt,
                user_prompt=context,
                tools=tools,
                budget=self.budget,
                usage=self.usage,
                stage="discover.screen",
                task_id=str(task.get("task_id", "")),
                store=self.store or task_tool_store(self.artifact_dir),
                settings=self.settings,
                max_rounds=self.max_rounds,
                notes_provider=source.notes_text,
            )
        except Exception as exc:
            setattr(exc, "screen_receipts", [*source.receipts, *(yasa.receipts if yasa is not None else [])])
            raise
        return result, source, yasa


def build_screen_task_graph():
    workflow = StateGraph(ScreenTaskState, context_schema=RunContext)
    workflow.add_node("prepare_context", _prepare_context)
    workflow.add_node("analyze", _analyze)
    workflow.add_node("validate", _validate)
    workflow.add_node("persist", _persist)
    workflow.add_edge(START, "prepare_context")
    workflow.add_edge("prepare_context", "analyze")
    workflow.add_edge("analyze", "validate")
    workflow.add_edge("validate", "persist")
    workflow.add_edge("persist", END)
    return workflow.compile()


async def run_screen_task(
    task: TaskRecord,
    execution: ScreenExecution,
    context: RunContext,
) -> TaskRecord:
    result = await build_screen_task_graph().ainvoke(
        {"task": dict(task)},
        context=context,
    )
    return dict(result.get("task", task))


def _prepare_context(state: ScreenTaskState, runtime: Runtime[RunContext] | None = None) -> dict[str, Any]:
    del runtime
    task = dict(state.get("task", {}))
    task["status"] = "running"
    task["attempts"] = int(task.get("attempts", 0)) + 1
    return {"task": task, "status": "running"}


async def _analyze(state: ScreenTaskState, runtime: Runtime[RunContext] | None = None) -> dict[str, Any]:
    task = dict(state.get("task", {}))
    execution = getattr(runtime.context, "screen_runtime", None) if runtime is not None else None
    if not isinstance(execution, ScreenExecution):
        return {"task": task, "status": "partial", "error": "screen execution context is unavailable"}
    try:
        result, source, yasa = await execution.analyze(task)  # type: ignore[arg-type]
    except ScreenConfigurationError as exc:
        return {"task": task, "status": "pending", "error": str(exc)}
    except Exception as exc:
        receipts = list(getattr(exc, "screen_receipts", []))
        task["read_ranges"] = [item for item in receipts if item.get("tool") == "read_file"]
        task["tool_receipts"] = receipts
        task["stop_reason"] = "error"
        return {"task": task, "status": "partial", "error": str(exc)[:_MAX_ERROR_CHARS]}
    receipts = [*source.receipts, *(yasa.receipts if yasa is not None else [])]
    task["read_ranges"] = [item for item in receipts if item.get("tool") == "read_file"]
    task["tool_receipts"] = receipts
    task["stop_reason"] = result.stop_reason
    task["rounds"] = result.rounds
    task["model_calls"] = result.model_calls
    task["compactions"] = result.compactions
    task["agent_receipts"] = list(result.receipts)[:50]
    if result.stop_reason != "complete":
        task["partial_summary"] = (result.last_text or result.content)[:_MAX_SUMMARY_CHARS]
    return {"task": task, "response": result.content, "status": "analyzed"}


def _validate(state: ScreenTaskState, runtime: Runtime[RunContext] | None = None) -> dict[str, Any]:
    task = dict(state.get("task", {}))
    error = state.get("error", "")
    if error:
        task["error"] = error
        task["status"] = state.get("status", "partial")
        task["unknowns"] = [error]
        task["deferred"] = [error]
        task["result"] = {
            "status": task["status"],
            "coverage_complete": False,
            "unknowns": [error],
            "deferred": [],
            "deferred_items": [],
            "candidates": [],
            "follow_up": [],
            "feature_observations": [],
        }
        return {"task": task, "result": task["result"], "status": task["status"]}
    execution = getattr(runtime.context, "screen_runtime", None) if runtime is not None else None
    ledger = execution.ledger if isinstance(execution, ScreenExecution) else None
    result = validate_response(state.get("response", ""), task, ledger=ledger)
    task["result"] = result
    task["candidates"] = result.get("candidates", [])
    task["scope_proposals"] = result.get("scope", [])
    task["priority"] = result.get("priority", "normal")
    task["negative_results"] = result.get("negative_results", [])
    task["unknowns"] = result.get("unknowns", [])
    task["deferred"] = result.get("deferred", [])
    task["deferred_items"] = result.get("deferred_items", [])
    task["follow_up"] = result.get("follow_up", [])
    task["feature_observations"] = result.get("feature_observations", [])
    task["status"] = (
        "complete"
        if result.get("parse_status") == "ok"
        and (not task.get("coverage_required") or result.get("coverage_complete"))
        and task.get("stop_reason", "complete") == "complete"
        else "partial"
    )
    return {"task": task, "result": result, "status": task["status"]}


def _persist(state: ScreenTaskState, runtime: Runtime[RunContext] | None = None) -> dict[str, Any]:
    del runtime
    task = dict(state.get("task", {}))
    artifact_dir = Path(task.get("artifact_dir", "")) if task.get("artifact_dir") else None
    if artifact_dir is not None:
        write_json(artifact_dir / "screen" / "tasks" / f"{task.get('task_id', 'unknown')}.json", task)
    return {"task": task, "status": state.get("status", task.get("status", "partial"))}


def validate_response(
    response: str,
    task: TaskRecord,
    allowed_paths: Any = None,
    *,
    ledger: DiscoverLedger | None = None,
) -> dict[str, Any]:
    """Validate model JSON and discard claims outside the scheduler's scope."""
    parsed = _parse_json(response)
    allowed = {str(path) for path in allowed_paths or []}

    def is_allowed(path: str) -> bool:
        if ledger is not None:
            return ledger.path_allowed(str(task.get("task_id", "")), path)
        return path in allowed
    if not isinstance(parsed, dict):
        return {
            "parse_status": "invalid",
            "coverage_complete": False,
            "candidates": [],
            "negative_results": [],
            "unknowns": ["screen model did not return a JSON object"],
            "deferred": [],
            "deferred_items": [],
            "follow_up": [],
            "feature_observations": [],
        }
    candidates: list[dict[str, Any]] = []
    for item in parsed.get("candidates", []) if isinstance(parsed.get("candidates", []), list) else []:
        if not isinstance(item, dict) or not is_allowed(str(item.get("path", ""))):
            continue
        candidate = {
            "path": str(item["path"]),
            "line_start": _positive_int(item.get("line_start")),
            "line_end": _positive_int(item.get("line_end")),
            "kind": str(item.get("kind", "input-candidate"))[:120],
            "role": str(item.get("role", "unknown"))
            if str(item.get("role", "unknown"))
            in {"source", "registration", "activation", "binding", "boundary", "unknown"}
            else "unknown",
            "summary": str(item.get("summary", item.get("reason", "")))[:_MAX_SUMMARY_CHARS],
            "task_id": str(task.get("task_id", "")),
        }
        candidates.append(candidate)
    scope = []
    raw_scope = parsed.get("scope", [])
    if isinstance(raw_scope, list):
        for item in raw_scope[:100]:
            if not isinstance(item, dict):
                continue
            paths = [str(path) for path in item.get("paths", []) if is_allowed(str(path))]
            if paths:
                scope.append(
                    {
                        "paths": paths,
                        "priority": str(item.get("priority", "normal"))[:40],
                        "reason": str(item.get("reason", ""))[:_MAX_SUMMARY_CHARS],
                    }
                )
    follow_up: list[dict[str, Any]] = []
    raw_follow_up = parsed.get("follow_up", [])
    if isinstance(raw_follow_up, list):
        for item in raw_follow_up:
            if not isinstance(item, dict):
                continue
            paths = [str(path) for path in item.get("paths", []) if is_allowed(str(path))]
            if not paths:
                continue
            follow_up.append(
                {
                    "paths": paths,
                    "question": str(item.get("question", "Inspect related source scope."))[:_MAX_SUMMARY_CHARS],
                    "reason": str(item.get("reason", "screen follow-up"))[:_MAX_SUMMARY_CHARS],
                    "depends_on": [str(task.get("task_id", ""))],
                }
            )
    negative = parsed.get("negative_results", [])
    negative_results: list[dict[str, Any]] = []
    if isinstance(negative, list):
        for item in negative[:50]:
            if not isinstance(item, dict):
                negative_results.append({"summary": str(item)[:_MAX_SUMMARY_CHARS]})
                continue
            path = str(item.get("path", ""))
            if path and not is_allowed(path):
                continue
            negative_results.append(
                {
                    "path": path,
                    "summary": str(item.get("summary", item.get("reason", "")))[:_MAX_SUMMARY_CHARS],
                }
            )
    unknowns = _strings(parsed.get("unknowns", []))
    deferred = _strings(parsed.get("deferred", []))
    deferred_items: list[dict[str, Any]] = []
    raw_deferred = parsed.get("deferred_items", [])
    if isinstance(raw_deferred, list):
        for item in raw_deferred:
            if not isinstance(item, dict):
                continue
            paths = [str(path) for path in item.get("paths", []) if is_allowed(str(path))]
            deferred_items.append(
                {
                    "paths": paths,
                    "reason": str(item.get("reason", ""))[:_MAX_SUMMARY_CHARS],
                    "reopen_condition": str(item.get("reopen_condition", ""))[:_MAX_SUMMARY_CHARS],
                    "owner": str(item.get("owner", ""))[:120],
                    "evidence_refs": _strings(item.get("evidence_refs", [])),
                }
            )
    feature_observations: list[dict[str, Any]] = []
    raw_observations = parsed.get("feature_observations", [])
    if isinstance(raw_observations, list):
        for item in raw_observations[:50]:
            if not isinstance(item, dict):
                continue
            definition = item.get("definition") if isinstance(item.get("definition"), dict) else {}
            definition_path = str(definition.get("path", ""))
            if not definition_path or not is_allowed(definition_path):
                continue
            query = item.get("query") if isinstance(item.get("query"), dict) else {}
            raw_scope = query.get("scope", [])
            if raw_scope and not isinstance(raw_scope, list):
                continue
            raw_scope = raw_scope if isinstance(raw_scope, list) else []
            scope_paths = [str(path) for path in raw_scope if is_allowed(str(path))]
            if raw_scope and not scope_paths:
                continue
            feature_observations.append(
                {
                    "kind": str(item.get("kind", "text"))[:80],
                    "name": str(item.get("name", ""))[:240],
                    "role": str(item.get("role", "unknown")),
                    "definition": {
                        "path": definition_path,
                        "line_start": _positive_int(definition.get("line_start")) or 0,
                        "line_end": _positive_int(definition.get("line_end")) or 0,
                    },
                    "evidence_refs": _strings(item.get("evidence_refs", [])),
                    "query": {
                        "kind": str(query.get("kind", item.get("kind", "text")))[:80],
                        "target": str(query.get("target", item.get("name", "")))[:512],
                        "regex": bool(query.get("regex", False)),
                        "scope": scope_paths,
                        "max_results": _positive_int(query.get("max_results")) or 200,
                    },
                    "limitations": _strings(item.get("limitations", [])),
                }
            )
    read_ranges = task.get("read_ranges", [])
    coverage_complete = False
    if task.get("coverage_required") and parsed.get("scope_status") == "complete":
        coverage_complete = (
            ledger.coverage_complete_for_task(task, read_ranges)
            if ledger is not None
            else _full_scope_coverage(task.get("paths", []), read_ranges)
        )
    return {
        "parse_status": "ok",
        "scope_status": str(parsed.get("scope_status", "partial")),
        "scope": scope,
        "priority": str(parsed.get("priority", "normal"))[:40],
        "coverage_complete": coverage_complete,
        "candidates": candidates,
        "negative_results": negative_results,
        "unknowns": unknowns,
        "deferred": deferred,
        "deferred_items": deferred_items,
        "follow_up": follow_up,
        "feature_observations": feature_observations,
        "summary": str(parsed.get("summary", ""))[:_MAX_SUMMARY_CHARS],
    }


def _task_context(
    task: TaskRecord,
    init_context: dict[str, Any],
    limit: int,
    *,
    ledger: DiscoverLedger | None = None,
) -> str:
    independent = bool(task.get("independent"))
    context: dict[str, Any] = {
        "task_id": task.get("task_id", ""),
        "view": task.get("view", "follow-up"),
        "question": task.get("question", ""),
        "scope": {
            "type": task.get("scope_type", "production-text"),
            "prefix": task.get("scope_prefix", ""),
            "file_count": task.get("scope_count", 0),
            "pagination": "Use list_directory, glob, or search_text cursors to navigate this scope.",
        },
        "parent_tasks": task.get("depends_on", []),
    }
    if task.get("result"):
        context["prior_result"] = task.get("result")
    if task.get("read_ranges"):
        context["prior_read_ranges"] = task.get("read_ranges")
    if int(task.get("attempts", 0)) > 1:
        context["attempts"] = int(task.get("attempts", 0))
        if task.get("error"):
            context["last_error"] = str(task["error"])[:1000]
    if not independent:
        context["init_context"] = init_context
        if ledger is not None and str(task.get("view", "")) not in _ISOLATED_VIEWS:
            prior = ledger.prior_context_for_task(str(task.get("task_id", "")), limit=20)
            if prior:
                prior["notice"] = (
                    "Leads from other tasks in the same scope; they are not established facts. "
                    "Verify against source before reusing them."
                )
                context["prior_findings"] = prior
    return compact_json(context, limit, drop_keys=_CONTEXT_DROP_KEYS)


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


def _positive_int(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item)[:_MAX_SUMMARY_CHARS] for item in value if str(item).strip()]


def _full_scope_coverage(paths: Any, receipts: Any) -> bool:
    if not paths or not isinstance(receipts, list):
        return False
    by_path: dict[str, list[dict[str, Any]]] = {}
    for receipt in receipts:
        if isinstance(receipt, dict) and receipt.get("status") == "ok":
            by_path.setdefault(str(receipt.get("path", "")), []).append(receipt)
    for path in paths:
        ranges = by_path.get(str(path), [])
        if not ranges or any(item.get("truncated") for item in ranges):
            return False
        total = max(int(item.get("total_lines", 0)) for item in ranges)
        covered = sorted(
            (int(item.get("start_line", 0)), int(item.get("end_line", 0)))
            for item in ranges
        )
        cursor = 1
        for start, end in covered:
            if start > cursor:
                break
            cursor = max(cursor, end + 1)
        if cursor <= total:
            return False
    return True
