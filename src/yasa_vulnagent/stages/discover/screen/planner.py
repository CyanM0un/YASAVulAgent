from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ....workflow.state import RunContext
from ..agent import run_task_agent_sync, task_tool_store
from ..ledger import DiscoverLedger
from ..storage import write_json
from .model import ScreenConfigurationError, build_configured_model, load_prompt
from .repo_map import PlannerToolbox


logger = logging.getLogger(__name__)
_SOURCES = frozenset({"coverage_debt", "follow_up", "candidate"})


class PlannerBudget:
    """Cap planner calls while charging the shared wave budget."""

    def __init__(self, shared: Any, limit: int) -> None:
        self.shared = shared
        self.limit = max(1, int(limit))
        self.calls = 0
        self._lock = threading.Lock()

    def consume_model_call(self) -> bool:
        with self._lock:
            if self.calls >= self.limit:
                return False
            if not self.shared.consume_model_call():
                return False
            self.calls += 1
            return True

    def remaining_seconds(self) -> float:
        return self.shared.remaining_seconds()

    def snapshot(self) -> dict[str, Any]:
        return {
            "model_calls": self.calls,
            "model_calls_limit": self.limit,
            "shared": self.shared.snapshot(),
        }


@dataclass
class PlanResult:
    status: str = "skipped"
    selected_task_ids: list[str] = field(default_factory=list)
    new_tasks: list[dict[str, Any]] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)
    model_calls: int = 0
    error: str = ""


def plan_wave(
    *,
    context: RunContext,
    ledger: DiscoverLedger,
    repo_map: dict[str, Any],
    work_board: dict[str, Any],
    artifact_dir: Path,
    shared_budget: Any,
    wave: int,
) -> PlanResult:
    settings = context.settings
    pending_count = int(work_board.get("pending_count", 0))
    capacity = int(work_board.get("max_tasks", 0))
    if pending_count >= capacity:
        return PlanResult(status="skipped")
    model_name = str(getattr(settings, "planner_model", "") or "")
    try:
        model = build_configured_model(
            context,
            model_name=model_name,
            timeout=settings.screen_wave_timeout,
        )
    except ScreenConfigurationError as exc:
        return PlanResult(status="failed", error=str(exc))
    budget = PlannerBudget(shared_budget, getattr(settings, "planner_max_calls", 6))
    toolbox = PlannerToolbox(ledger, repo_map)
    system_prompt = load_prompt("planner.md")
    user_prompt = json.dumps(
        {
            "wave": wave,
            "work_board": work_board,
            "limits": {
                "max_new_tasks": getattr(settings, "planner_max_new_tasks", 2),
                "max_files": getattr(settings, "planner_max_files", 8),
                "max_chars": getattr(settings, "planner_max_chars", 40000),
            },
        },
        ensure_ascii=False,
        default=str,
    )
    raw = ""
    parsed: Any = None
    error = ""
    for _attempt in range(2):
        try:
            raw = run_task_agent_sync(
                model=model,
                system_prompt=system_prompt,
                user_prompt=user_prompt + (f"\n\nPrevious plan was invalid: {error}" if error else ""),
                tools=toolbox.langchain_tools(),
                budget=budget,
                usage=context.usage,
                stage="discover.planner",
                task_id=f"planner-wave-{wave}",
                store=task_tool_store(artifact_dir),
                settings=settings,
                max_rounds=3,
            ).content
        except Exception as exc:
            error = str(exc)[:1000]
            break
        parsed = parse_json(raw)
        if isinstance(parsed, dict):
            break
        error = "planner did not return a JSON object"
    result = PlanResult(
        status="failed" if not isinstance(parsed, dict) else "planned",
        model_calls=budget.calls,
        error=error,
    )
    if isinstance(parsed, dict):
        selected, new_tasks, rejected = validate_plan(
            parsed,
            ledger=ledger,
            next_number=next_task_number(ledger.list_tasks()),
            wave=wave,
            max_new_tasks=getattr(settings, "planner_max_new_tasks", 2),
            max_files=getattr(settings, "planner_max_files", 8),
            max_chars=getattr(settings, "planner_max_chars", 40000),
        )
        result.selected_task_ids = selected
        result.new_tasks = new_tasks
        result.rejected = rejected
        if not new_tasks and not selected:
            result.status = "planned"
    write_json(
        artifact_dir / "screen" / "plans" / f"wave-{wave:04d}.json",
        {
            "status": result.status,
            "selected_task_ids": result.selected_task_ids,
            "new_tasks": result.new_tasks,
            "rejected": result.rejected,
            "model_calls": result.model_calls,
            "error": result.error,
            "fallback": False,
        },
    )
    return result


def validate_plan(
    plan: dict[str, Any],
    *,
    ledger: DiscoverLedger,
    next_number: int,
    wave: int,
    max_new_tasks: int,
    max_files: int,
    max_chars: int,
) -> tuple[list[str], list[dict[str, Any]], list[dict[str, Any]]]:
    pending_ids = {
        str(task.get("task_id"))
        for task in ledger.list_tasks(statuses={"pending", "partial"}, kind_prefix="screen")
    }
    selected: list[str] = []
    rejected: list[dict[str, Any]] = []
    raw_selected = plan.get("selected_task_ids", [])
    if isinstance(raw_selected, list):
        for item in raw_selected:
            task_id = str(item)
            if task_id in pending_ids and task_id not in selected:
                selected.append(task_id)
            elif task_id:
                rejected.append({"kind": "selection", "value": task_id, "reason": "task is not pending"})
    proposals = plan.get("new_tasks", [])
    if not isinstance(proposals, list):
        proposals = []
    new_tasks, task_rejected = validate_new_tasks(
        proposals,
        ledger=ledger,
        next_number=next_number,
        wave=wave,
        max_new_tasks=max_new_tasks,
        max_files=max_files,
        max_chars=max_chars,
    )
    return selected, new_tasks, [*rejected, *task_rejected]


def validate_new_tasks(
    proposals: list[Any],
    *,
    ledger: DiscoverLedger,
    next_number: int,
    wave: int,
    max_new_tasks: int,
    max_files: int,
    max_chars: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    existing = {
        task_signature(task)
        for task in ledger.list_tasks(kind_prefix="screen")
    }
    tasks: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    accepted = 0
    for proposal in proposals:
        if accepted >= max(0, int(max_new_tasks)):
            break
        if not isinstance(proposal, dict):
            rejected.append({"kind": "proposal", "reason": "proposal is not an object"})
            continue
        source = str(proposal.get("source", ""))
        if source not in _SOURCES:
            rejected.append({"kind": "proposal", "reason": f"unsupported source: {source}"})
            continue
        raw_paths = proposal.get("paths", [])
        paths = sorted(
            {
                str(path).removeprefix("./")
                for path in (raw_paths if isinstance(raw_paths, list) else [])
                if str(path).strip()
            }
        )
        if not paths:
            rejected.append({"kind": "proposal", "source": source, "reason": "paths are required"})
            continue
        if len(paths) > max(1, int(max_files)):
            rejected.append({"kind": "proposal", "source": source, "reason": "too many files"})
            continue
        files = [ledger.get_file(path) for path in paths]
        if any(
            file is None
            or file.get("usage_hint") != "production-candidate"
            or file.get("content_type") != "text"
            or file.get("status") == "unavailable"
            for file in files
        ):
            rejected.append({"kind": "proposal", "source": source, "reason": "paths are not production text"})
            continue
        chars = sum(int((file or {}).get("size", 0)) for file in files)
        if chars > max(1, int(max_chars)):
            rejected.append({"kind": "proposal", "source": source, "reason": "content budget exceeded", "chars": chars})
            continue
        refs = proposal.get("source_refs", [])
        refs = [str(item) for item in refs if str(item).strip()] if isinstance(refs, list) else []
        if not refs:
            rejected.append({"kind": "proposal", "source": source, "reason": "source_refs are required"})
            continue
        if not _grounded(source, refs, paths, ledger):
            rejected.append({"kind": "proposal", "source": source, "reason": "source_refs do not ground the paths"})
            continue
        task = {
            "task_id": f"screen-{next_number:04d}",
            "kind": "screen_coverage" if source == "coverage_debt" else "screen_follow_up",
            "status": "pending",
            "question": str(proposal.get("question", "Inspect this source scope."))[:2000],
            "reason": str(proposal.get("reason", ""))[:2000],
            "source": source,
            "source_refs": refs,
            "attempts": 0,
            "depends_on": [
                ref.removeprefix("task:") for ref in refs if ref.startswith("task:")
            ],
            "wave": int(wave),
            "view": "coverage" if source == "coverage_debt" else "follow-up",
            "independent": False,
            "coverage_required": True,
            "scope_type": "explicit",
            "scope_paths": paths,
            "scope_count": len(paths),
            "read_ranges": [],
            "tool_receipts": [],
            "candidates": [],
            "negative_results": [],
            "unknowns": [],
            "deferred": [],
            "follow_up": [],
        }
        signature = task_signature(task)
        if signature in existing:
            rejected.append({"kind": "proposal", "source": source, "reason": "duplicate task"})
            continue
        existing.add(signature)
        tasks.append(task)
        accepted += 1
        next_number += 1
    return tasks, rejected


def _grounded(
    source: str,
    refs: list[str],
    paths: list[str],
    ledger: DiscoverLedger,
) -> bool:
    path_set = set(paths)
    if source == "coverage_debt":
        if any(not ref.startswith("file:") for ref in refs):
            return False
        ref_paths = {ref.removeprefix("file:") for ref in refs}
        if not ref_paths or not path_set.issubset(ref_paths):
            return False
        return all(
            (file := ledger.get_file(path)) is not None
            and file.get("status") not in {"screened", "candidate", "unavailable"}
            for path in ref_paths
        )
    if source == "follow_up":
        if any(not ref.startswith("task:") for ref in refs):
            return False
        task_ids = [ref.removeprefix("task:") for ref in refs]
        if not task_ids:
            return False
        allowed: set[str] = set()
        for task_id in task_ids:
            task = ledger.get_task(task_id)
            if not task:
                return False
            for item in task.get("follow_up", []):
                if isinstance(item, dict):
                    allowed.update(str(path) for path in item.get("paths", []))
        return path_set.issubset(allowed)
    if source == "candidate":
        if any(not ref.startswith("candidate:") for ref in refs):
            return False
        entry_ids = [ref.removeprefix("candidate:") for ref in refs]
        if not entry_ids:
            return False
        entries = {str(entry.get("entry_id", "")): entry for entry in ledger.entries(status="candidate")}
        for entry_id in entry_ids:
            if entry_id not in entries:
                return False
            location = entries[entry_id].get("location") if isinstance(entries[entry_id].get("location"), dict) else {}
            if str(location.get("path", "")) not in path_set:
                return False
        return True
    return False


def task_signature(task: dict[str, Any]) -> str:
    scope_type = str(task.get("scope_type", "production-text"))
    if scope_type == "explicit":
        scope: Any = sorted(str(path) for path in task.get("scope_paths", task.get("paths", [])))
    else:
        scope = str(task.get("scope_prefix", ""))
    return json.dumps(
        {
            "kind": task.get("kind"),
            "scope_type": scope_type,
            "scope": scope,
            "question": task.get("question", ""),
        },
        ensure_ascii=False,
        sort_keys=True,
    )


def next_task_number(tasks: list[dict[str, Any]]) -> int:
    numbers: list[int] = []
    for task in tasks:
        try:
            numbers.append(int(str(task.get("task_id", "")).rsplit("-", 1)[1]))
        except (IndexError, ValueError):
            continue
    return max(numbers, default=0) + 1


def parse_json(response: str) -> Any:
    text = str(response).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        text = text[start : end + 1]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None

