"""Model construction and single JSON call support for the report stage."""

from __future__ import annotations

import json
import time
from importlib.resources import files
from pathlib import Path
from typing import Any

from ...agent.budget import BudgetStop, TaskBudget
from ...agent.context import ContextManager
from ...agent.retry import RetryPolicy
from ...agent.runtime import ModelFatal, ModelRequest, run_tool_loop
from ...agent.tokens import TokenCounter
from ...workflow.state import RunContext
from .storage import write_json


class ReportConfigurationError(RuntimeError):
    """Raised when the report stage cannot build or authenticate its model."""


class ReportModelError(RuntimeError):
    """Raised when a report model request fails after retries."""

    def __init__(self, message: str, stop_reason: str = "model_request") -> None:
        super().__init__(message)
        self.stop_reason = stop_reason


class ReportPhaseError(RuntimeError):
    """Raised when an agent finished without a usable result object."""

    def __init__(self, message: str, stop_reason: str = "") -> None:
        super().__init__(message)
        self.stop_reason = stop_reason


def load_prompt(name: str) -> str:
    return files("yasa_vulnagent.stages.report").joinpath(
        "prompts", name
    ).read_text(encoding="utf-8")


def build_model(context: RunContext) -> Any:
    settings = context.settings
    configured = settings.report_model.strip()
    if context.model is not None and (not configured or configured == settings.model):
        return context.model
    if not settings.api_key:
        raise ReportConfigurationError("LLM_API_KEY is required for the report stage")
    try:
        from langchain_openai import ChatOpenAI
    except ImportError as exc:
        raise ReportConfigurationError(
            "langchain-openai is required for the report stage"
        ) from exc
    return ChatOpenAI(
        model=configured or settings.model,
        api_key=settings.api_key,
        base_url=settings.base_url,
        timeout=settings.report_llm_timeout,
        max_retries=0,
    )


def parse_json_object(content: str, label: str) -> dict[str, Any]:
    text = content.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end < start:
        raise ValueError(f"{label} did not return a JSON object")
    try:
        value = json.loads(text[start : end + 1])
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} returned invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} did not return a JSON object")
    return value


def run_json_call(
    context: RunContext,
    *,
    model: Any,
    system_prompt: str,
    user_prompt: str,
    deadline: float,
    stage: str,
    task_id: str,
    receipt_file: Path,
) -> dict[str, Any]:
    settings = context.settings
    counter = TokenCounter(settings.model, settings.agent_token_safety)
    budget = TaskBudget(
        deadline=deadline,
        max_model_calls=16,
        max_rounds_per_invocation=1,
        hard_task_cap=16,
    )
    started = time.monotonic()
    try:
        result = run_tool_loop(
            model,
            system_prompt,
            user_prompt,
            [],
            budget=budget,
            usage=context.usage,
            stage=stage,
            task_id=task_id,
            max_rounds=1,
            counter=counter,
            context=ContextManager(
                counter, max_tokens=settings.agent_context_tokens
            ),
            retry=RetryPolicy(attempts=settings.agent_model_retries),
            json_expected=True,
            json_repair_attempts=settings.agent_json_repair_attempts,
            request_timeout=settings.report_llm_timeout,
            finalize_on_exhaustion=False,
        )
    except ModelFatal as exc:
        raise ReportModelError(str(exc), "model_configuration") from exc
    except ModelRequest as exc:
        raise ReportModelError(str(exc), "model_request") from exc
    except TimeoutError as exc:
        raise ReportModelError(str(exc), "time_budget") from exc
    except BudgetStop as exc:
        raise ReportModelError(str(exc), exc.reason) from exc
    write_json(
        receipt_file,
        {
            "stage": stage,
            "task_id": task_id,
            "model": str(getattr(model, "model_name", "") or ""),
            "stop_reason": result.stop_reason,
            "elapsed_seconds": result.elapsed_seconds or round(time.monotonic() - started, 3),
            "calls": result.calls,
        },
    )
    try:
        return parse_json_object(result.content, stage)
    except ValueError as exc:
        raise ReportPhaseError(str(exc), result.stop_reason) from exc
