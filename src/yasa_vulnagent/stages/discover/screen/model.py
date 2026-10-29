from __future__ import annotations

from importlib.resources import files
from typing import Any

from ....workflow.state import RunContext


class ScreenError(RuntimeError):
    """Raised when one screen task cannot produce a usable result."""


class ScreenConfigurationError(ScreenError):
    """Raised for missing or unusable model configuration."""


def load_prompt(name: str) -> str:
    return files("yasa_vulnagent.stages.discover.screen").joinpath("prompts", name).read_text(
        encoding="utf-8"
    )


def build_model(context: RunContext) -> Any:
    return build_configured_model(context)


def build_configured_model(
    context: RunContext,
    *,
    model_name: str = "",
    timeout: int | None = None,
) -> Any:
    """Build a model for an optional stage-specific configuration."""
    settings = context.settings
    configured = model_name.strip()
    if context.model is not None and (
        not configured or configured == settings.model
    ):
        return context.model
    if not settings.api_key:
        raise ScreenConfigurationError("LLM_API_KEY is required for the discover stage")
    try:
        from langchain_openai import ChatOpenAI
    except ImportError as exc:
        raise ScreenConfigurationError("langchain-openai is required for discover") from exc
    return ChatOpenAI(
        model=configured or settings.model,
        api_key=settings.api_key,
        base_url=settings.base_url,
        timeout=timeout or settings.discover_request_timeout,
        max_retries=0,
    )
