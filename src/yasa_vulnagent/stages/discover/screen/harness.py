from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

from ....agent.runtime import run_coroutine
from ....workflow.state import RunContext
from ..agent import task_tool_store
from ..ledger import DiscoverLedger
from .graph import ScreenBudget, ScreenExecution, run_screen_task
from .mcp import open_yasa_mcp
from .model import ScreenConfigurationError, build_model
from .tools import ReadCache


logger = logging.getLogger(__name__)


def run_wave(
    tasks: list[dict[str, Any]],
    *,
    repository: Path,
    artifact_dir: Path,
    context: RunContext,
    init_context: dict[str, Any],
    ledger: DiscoverLedger,
    budget: ScreenBudget | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Run one bounded screen wave, preserving one result per task."""
    settings = context.settings
    if budget is None:
        budget = ScreenBudget(
            deadline=time.monotonic() + settings.screen_wave_timeout,
            model_calls_limit=settings.screen_wave_model_calls,
        )
    try:
        model = build_model(context)
    except ScreenConfigurationError as exc:
        message = str(exc)
        results = [_deferred_task(task, message, artifact_dir) for task in tasks]
        return results, {"status": "partial", "error": message, "budget": budget.snapshot()}

    async def execute() -> tuple[list[dict[str, Any]], dict[str, Any]]:
        async with open_yasa_mcp(settings, repository) as session:
            execution = ScreenExecution(
                repository=repository,
                artifact_dir=artifact_dir,
                model=model,
                budget=budget,
                init_context=init_context,
                ledger=ledger,
                mcp_session=session,
                settings=settings,
                max_output_chars=settings.screen_tool_output_chars,
                max_rounds=settings.screen_task_max_rounds,
                context_chars=settings.screen_context_chars,
                usage=context.usage,
                store=task_tool_store(artifact_dir),
                cache=ReadCache(),
            )
            task_context = replace(context, screen_runtime=execution)
            results = await asyncio.gather(
                *(run_screen_task(task, execution, task_context) for task in tasks),
                return_exceptions=True,
            )
            normalized: list[dict[str, Any]] = []
            for task, result in zip(tasks, results):
                if isinstance(result, Exception):
                    logger.error(
                        "discover screen task crashed task_id=%s",
                        task.get("task_id"),
                        exc_info=result,
                    )
                    normalized.append(
                        _deferred_task(
                            task,
                            str(result)[:1000],
                            artifact_dir,
                            status="partial",
                            receipts=getattr(result, "screen_receipts", []),
                        )
                    )
                else:
                    normalized.append(dict(result))
            metadata = {
                "status": "complete" if all(item.get("status") == "complete" for item in normalized) else "partial",
                "task_count": len(normalized),
                "budget": budget.snapshot(),
                "yasa_mcp": "available" if session is not None else "unavailable",
                "warnings": []
                if session is not None
                else ["YASA MCP unavailable; screen used source-tool fallback"],
            }
            task_errors = [str(item.get("error")) for item in normalized if item.get("error")]
            if task_errors:
                metadata["error"] = f"screen task deferred: {task_errors[0][:1000]}"
            return normalized, metadata

    return run_coroutine(execute())


def _deferred_task(
    task: dict[str, Any],
    error: str,
    artifact_dir: Path,
    *,
    status: str = "pending",
    receipts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    result = dict(task)
    result["status"] = status
    result["attempts"] = int(result.get("attempts", 0)) + 1
    result["error"] = error
    result["stop_reason"] = "error"
    result["unknowns"] = [error]
    result["deferred"] = [error]
    result["result"] = {
        "parse_status": "deferred",
        "coverage_complete": False,
        "candidates": [],
        "negative_results": [],
        "unknowns": [error],
        "deferred": [error],
        "follow_up": [],
    }
    result["tool_receipts"] = [
        *result.get("tool_receipts", []),
        *(receipts or []),
    ]
    result["read_ranges"] = [
        item for item in result["tool_receipts"] if item.get("tool") == "read_file"
    ]
    artifact = artifact_dir / "screen" / "tasks" / f"{result.get('task_id', 'unknown')}.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    from ..storage import write_json

    write_json(artifact, result)
    logger.warning("discover screen task deferred task_id=%s reason=%s", result.get("task_id"), error)
    return result
