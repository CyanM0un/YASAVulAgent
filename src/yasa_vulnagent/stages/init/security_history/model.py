from __future__ import annotations

import logging
from importlib.resources import files
from pathlib import Path
from typing import Any, Iterable

from ....agent.budget import BudgetStop, TaskBudget
from ....agent.context import ContextManager
from ....agent.retry import RetryPolicy
from ....agent.runtime import ModelFatal, ModelRequest, run_tool_loop
from ....agent.tokens import TokenCounter
from ....config import Settings, load_settings
from ....workflow.state import RunContext


logger = logging.getLogger(__name__)


class SecurityHistoryError(RuntimeError):
    """Raised when a required security-history model request cannot finish."""


class SecurityHistoryFatalError(SecurityHistoryError):
    """Raised when the security-history model configuration cannot be used."""


def load_prompt(name: str) -> str:
    return files("yasa_vulnagent.stages.init.security_history").joinpath(
        "prompts", name
    ).read_text(encoding="utf-8")


def load_skill() -> str:
    return files("yasa_vulnagent.stages.init.security_history").joinpath("SKILL.md").read_text(
        encoding="utf-8"
    )


def build_model(context: RunContext) -> Any:
    if context.model is not None:
        return context.model
    settings = context.settings
    if not settings.api_key:
        raise SecurityHistoryFatalError("LLM_API_KEY is required for the security_history stage")
    try:
        from langchain_openai import ChatOpenAI
    except ImportError as exc:
        raise SecurityHistoryFatalError("langchain-openai is required for the security_history stage") from exc
    return ChatOpenAI(
        model=settings.model,
        api_key=settings.api_key,
        base_url=settings.base_url,
        timeout=settings.history_model_timeout,
        max_retries=0,
    )


def invoke_model(
    model: Any,
    system_prompt: str,
    user_prompt: str,
    tools: Iterable[Any] = (),
    max_tool_calls: int | None = None,
    deadline: float | None = None,
    *,
    budget: TaskBudget | None = None,
    usage: Any | None = None,
    settings: Settings | None = None,
    artifact_dir: Path | None = None,
    stage: str = "init.security_history",
    task_id: str = "model",
    json_expected: bool = True,
    max_rounds: int | None = None,
) -> str:
    settings = settings or load_settings()
    rounds = max_rounds or max_tool_calls or settings.agent_max_rounds_per_invocation
    budget = budget or TaskBudget(
        deadline=deadline,
        max_model_calls=rounds + 1,
        max_rounds_per_invocation=rounds,
        hard_task_cap=max(rounds + 1, rounds + 1),
    )
    counter = TokenCounter(settings.model, settings.agent_token_safety)
    context = ContextManager(
        counter,
        max_tokens=settings.agent_context_tokens,
        trigger=settings.agent_compaction_trigger,
        keep_recent_results=settings.agent_keep_recent_results,
    )
    try:
        result = run_tool_loop(
            model,
            system_prompt,
            user_prompt,
            tools,
            budget=budget,
            usage=usage,
            stage=stage,
            task_id=task_id,
            max_rounds=rounds,
            artifact_dir=artifact_dir,
            counter=counter,
            context=context,
            retry=RetryPolicy(
                attempts=settings.agent_model_retries,
                tool_attempts=settings.agent_tool_retries,
            ),
            json_expected=json_expected,
            json_repair_attempts=settings.agent_json_repair_attempts,
            max_result_tokens=settings.agent_tool_result_tokens,
        )
    except BudgetStop as exc:
        if exc.reason == "time_budget":
            raise TimeoutError("security_history model deadline reached") from exc
        raise SecurityHistoryError(
            f"security_history model budget exhausted: {exc.reason}"
        ) from exc
    except ModelFatal as exc:
        raise SecurityHistoryFatalError(
            f"security_history model configuration failed: {exc}"
        ) from exc
    except ModelRequest as exc:
        raise SecurityHistoryError(f"security_history model request failed: {exc}") from exc
    except TimeoutError:
        raise
    except ValueError as exc:
        raise SecurityHistoryError(
            f"security_history model returned invalid JSON: {exc}"
        ) from exc
    return result.content
