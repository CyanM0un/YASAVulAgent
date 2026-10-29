from __future__ import annotations

from pathlib import Path
from typing import Any

from langchain_core.tools import StructuredTool

from ..features import build_source_hints
from ..ledger import DiscoverLedger


_ENTRY_HINTS = ("main", "app", "server", "route", "controller", "handler", "cmd", "cli", "config")


def build_repo_map(ledger: DiscoverLedger, *, max_modules: int = 40) -> dict[str, Any]:
    """Build a compact, deterministic repository map from ledger facts only."""
    modules: dict[str, dict[str, Any]] = {}
    candidates_by_path: dict[str, int] = {}
    for entry in ledger.entries(status="candidate"):
        location = entry.get("location") if isinstance(entry.get("location"), dict) else {}
        path = str(location.get("path", ""))
        if path:
            candidates_by_path[path] = candidates_by_path.get(path, 0) + 1
    for file in ledger.iter_files(limit=1000):
        if file.get("usage_hint") != "production-candidate" or file.get("content_type") != "text":
            continue
        path = str(file.get("path", ""))
        parts = Path(path).parts
        module = parts[0] if len(parts) > 1 else "."
        item = modules.setdefault(
            module,
            {"module": module, "files": 0, "chars": 0, "unread_files": 0, "candidates": 0},
        )
        item["files"] += 1
        item["chars"] += int(file.get("size", 0))
        if file.get("status") not in {"screened", "candidate"}:
            item["unread_files"] += 1
        item["candidates"] += candidates_by_path.get(path, 0)
    ordered = sorted(
        modules.values(),
        key=lambda item: (-int(item["unread_files"]), -int(item["candidates"]), str(item["module"])),
    )
    follow_ups = open_follow_ups(ledger, limit=50)
    return {
        "modules": ordered[: max(1, int(max_modules))],
        "module_count": len(ordered),
        "truncated": len(ordered) > max_modules,
        "entry_hints": [module for module in ordered if any(hint in str(module["module"]).lower() for hint in _ENTRY_HINTS)][:20],
        "open_follow_up_count": len(follow_ups),
        "open_follow_ups": follow_ups,
        "candidate_count": ledger.count_entries("candidate"),
        "unread_count": sum(int(item["unread_files"]) for item in ordered),
        "files": {
            "total": ledger.file_count(),
            "production_text": ledger.file_counts().get("production_text", 0),
            "screened": ledger.file_counts().get("screened", 0),
        },
        "recent_tasks": recent_tasks(ledger, limit=20),
    }


def build_work_board(
    ledger: DiscoverLedger,
    repo_map: dict[str, Any],
    *,
    screen_meta: dict[str, Any],
    budget: Any | None,
    max_tasks: int,
) -> dict[str, Any]:
    pending = ledger.list_tasks(
        statuses={"pending", "partial"}, kind_prefix="screen"
    )
    candidate_entries = ledger.entries(status="candidate")
    return {
        "wave": int(screen_meta.get("wave", 0)),
        "max_tasks": int(max_tasks),
        "pending_tasks": [
            {
                "task_id": task.get("task_id", ""),
                "kind": task.get("kind", ""),
                "status": task.get("status", ""),
                "wave": task.get("wave", 0),
                "question": task.get("question", ""),
                "scope_type": task.get("scope_type", ""),
                "paths": ledger.task_scope_paths(str(task.get("task_id", "")))[:20],
            }
            for task in pending[:100]
        ],
        "pending_count": len(pending),
        "open_candidates": candidate_entries[:100],
        "open_candidate_count": len(candidate_entries),
        "priority_hints": build_source_hints(ledger),
        "repo": {
            "files": repo_map.get("files", {}),
            "unread_count": repo_map.get("unread_count", 0),
            "modules": repo_map.get("modules", []),
            "open_follow_ups": repo_map.get("open_follow_ups", []),
        },
        "budget": budget.snapshot() if budget is not None else {},
    }


class PlannerToolbox:
    """Read-only summary tools; source text is intentionally unavailable."""

    def __init__(self, ledger: DiscoverLedger, repo_map: dict[str, Any]) -> None:
        self.ledger = ledger
        self.repo_map = repo_map

    def repo_overview(self, max_modules: int = 20) -> dict[str, Any]:
        modules = list(self.repo_map.get("modules", []))[: max(1, min(int(max_modules), 40))]
        return {
            "files": self.repo_map.get("files", {}),
            "unread_count": self.repo_map.get("unread_count", 0),
            "module_count": self.repo_map.get("module_count", 0),
            "modules": modules,
            "entry_hints": self.repo_map.get("entry_hints", []),
            "candidate_count": self.repo_map.get("candidate_count", 0),
        }

    def list_module(self, path: str = "", max_files: int = 100) -> dict[str, Any]:
        prefix = str(path).removeprefix("./").rstrip("/")
        files: list[dict[str, Any]] = []
        total_chars = 0
        file_count = 0
        for file in self.ledger.iter_files(limit=1000):
            candidate = str(file.get("path", ""))
            if file.get("usage_hint") != "production-candidate" or file.get("content_type") != "text":
                continue
            if prefix and not (candidate == prefix or candidate.startswith(prefix + "/")):
                continue
            total_chars += int(file.get("size", 0))
            file_count += 1
            if len(files) < max(1, min(int(max_files), 200)):
                files.append(
                    {
                        "path": candidate,
                        "size": int(file.get("size", 0)),
                        "kind": file.get("kind", ""),
                        "status": file.get("status", ""),
                    }
                )
        return {"path": prefix or ".", "files": files, "file_count": file_count, "chars": total_chars}

    def coverage_debt(self, prefix: str = "", limit: int = 50) -> list[dict[str, Any]]:
        normalized = str(prefix).removeprefix("./").rstrip("/")
        result: list[dict[str, Any]] = []
        for file in self.ledger.iter_files(limit=1000):
            if len(result) >= max(1, min(int(limit), 200)):
                break
            if file.get("usage_hint") != "production-candidate" or file.get("content_type") != "text":
                continue
            if file.get("status") in {"screened", "candidate"}:
                continue
            path = str(file.get("path", ""))
            if normalized and not (path == normalized or path.startswith(normalized + "/")):
                continue
            result.append(
                {"path": path, "size": int(file.get("size", 0)), "status": file.get("status", "")}
            )
        return result

    def recent_tasks(self, prefix: str = "", limit: int = 20) -> list[dict[str, Any]]:
        return recent_tasks(self.ledger, limit=limit, prefix=prefix)

    def list_candidates(self, limit: int = 50) -> list[dict[str, Any]]:
        return self.ledger.entries(status="candidate")[: max(1, min(int(limit), 200))]

    def get_task_detail(self, task_id: str) -> dict[str, Any]:
        task = self.ledger.get_task(task_id)
        if not task:
            return {"error": "task not found"}
        return {
            key: task.get(key)
            for key in (
                "task_id",
                "kind",
                "status",
                "wave",
                "question",
                "scope_type",
                "scope_prefix",
                "scope_paths",
                "attempts",
                "follow_up",
                "unknowns",
                "deferred",
            )
        }

    def langchain_tools(self) -> list[StructuredTool]:
        return [
            StructuredTool.from_function(
                func=self.repo_overview,
                name="repo_overview",
                description="Return compact repository modules, entry hints and coverage counts.",
            ),
            StructuredTool.from_function(
                func=self.list_module,
                name="list_module",
                description="List bounded production file metadata for one module prefix.",
            ),
            StructuredTool.from_function(
                func=self.coverage_debt,
                name="coverage_debt",
                description="List unread production files, optionally under a path prefix.",
            ),
            StructuredTool.from_function(
                func=self.recent_tasks,
                name="recent_tasks",
                description="List recent screening tasks and their status.",
            ),
            StructuredTool.from_function(
                func=self.list_candidates,
                name="list_candidates",
                description="List candidate entries awaiting disposition.",
            ),
            StructuredTool.from_function(
                func=self.get_task_detail,
                name="get_task_detail",
                description="Return bounded metadata for one screening task.",
            ),
        ]


def recent_tasks(
    ledger: DiscoverLedger, *, limit: int = 20, prefix: str = ""
) -> list[dict[str, Any]]:
    normalized = str(prefix).removeprefix("./").rstrip("/")
    tasks = ledger.list_tasks(kind_prefix="screen")
    if normalized:
        tasks = [
            task
            for task in tasks
            if any(
                str(path) == normalized or str(path).startswith(normalized + "/")
                for path in task.get("scope_paths", task.get("paths", []))
            )
        ]
    tasks = sorted(tasks, key=lambda task: (int(task.get("wave", 0)), str(task.get("task_id", ""))), reverse=True)
    return [
        {
            "task_id": task.get("task_id", ""),
            "kind": task.get("kind", ""),
            "status": task.get("status", ""),
            "wave": task.get("wave", 0),
            "question": task.get("question", ""),
            "attempts": task.get("attempts", 0),
        }
        for task in tasks[: max(1, int(limit))]
    ]


def open_follow_ups(ledger: DiscoverLedger, *, limit: int = 50) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for task in ledger.list_tasks(kind_prefix="screen"):
        for item in task.get("follow_up", []):
            if len(result) >= max(1, int(limit)):
                return result
            if isinstance(item, dict):
                result.append(
                    {
                        "task_id": task.get("task_id", ""),
                        "paths": item.get("paths", []),
                        "question": item.get("question", ""),
                    }
                )
    return result
