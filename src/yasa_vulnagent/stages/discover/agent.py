from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Iterable

from ...agent.artifacts import ToolResultStore
from ...agent.budget import SharedBudgetAdapter
from ...agent.context import ContextManager
from ...agent.retry import RetryPolicy
from ...agent.runtime import (
    AgentResult,
    ModelFatal,
    ModelRequest,
    run_coroutine,
    run_tool_loop_async,
)
from ...agent.tokens import TokenCounter
from .screen.model import ScreenConfigurationError, ScreenError


def task_tool_store(artifact_dir: Path) -> ToolResultStore:
    """One content-addressed store per stage artifact directory."""
    return ToolResultStore(Path(artifact_dir) / "tool-results")


async def run_task_agent(
    *,
    model: Any,
    system_prompt: str,
    user_prompt: str,
    tools: Iterable[Any] = (),
    budget: Any,
    usage: Any | None,
    stage: str,
    task_id: str,
    store: ToolResultStore,
    settings: Any,
    max_rounds: int,
    notes_provider: Callable[[], str] | None = None,
) -> AgentResult:
    """Run one discover task through the shared agent loop."""
    counter = TokenCounter(settings.model, settings.agent_token_safety)
    context = ContextManager(
        counter,
        max_tokens=settings.discover_context_tokens,
        trigger=settings.agent_compaction_trigger,
        keep_recent_results=settings.agent_keep_recent_results,
    )
    try:
        return await run_tool_loop_async(
            model,
            system_prompt,
            user_prompt,
            tools,
            budget=SharedBudgetAdapter(budget),
            usage=usage,
            stage=stage,
            task_id=task_id,
            max_rounds=max_rounds,
            counter=counter,
            context=context,
            retry=RetryPolicy(
                attempts=settings.agent_model_retries,
                tool_attempts=settings.agent_tool_retries,
            ),
            max_result_tokens=settings.agent_tool_result_tokens,
            request_timeout=settings.discover_request_timeout,
            parallel_tools=True,
            finalize_on_exhaustion=True,
            compaction_hint=notes_provider,
            tool_store=store,
        )
    except ModelFatal as exc:
        raise ScreenConfigurationError(f"discover model configuration failed: {exc}") from exc
    except ModelRequest as exc:
        raise ScreenError(f"discover model request failed: {exc}") from exc
    except TimeoutError as exc:
        raise ScreenError(f"discover model request timed out: {exc}") from exc


def run_task_agent_sync(**kwargs: Any) -> AgentResult:
    """Synchronous wrapper for planner and review nodes."""
    return run_coroutine(run_task_agent(**kwargs))
