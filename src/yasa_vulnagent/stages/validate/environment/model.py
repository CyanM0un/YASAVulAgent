"""Model construction and JSON parsing for environment agents."""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any

from ....workflow.state import RunContext


class EnvironmentConfigurationError(RuntimeError):
    """Raised when the environment stage cannot build its model."""


def load_prompt(name: str) -> str:
    return files("yasa_vulnagent.stages.validate.environment").joinpath(
        "prompts", name
    ).read_text(encoding="utf-8")


def build_model(context: RunContext) -> Any:
    settings = context.settings
    configured = settings.validate_env_model.strip()
    if context.model is not None and (
        not configured or configured == settings.model
    ):
        return context.model
    if not settings.api_key:
        raise EnvironmentConfigurationError(
            "LLM_API_KEY is required for the validate environment stage"
        )
    try:
        from langchain_openai import ChatOpenAI
    except ImportError as exc:
        raise EnvironmentConfigurationError(
            "langchain-openai is required for the validate environment stage"
        ) from exc
    return ChatOpenAI(
        model=configured or settings.model,
        api_key=settings.api_key,
        base_url=settings.base_url,
        timeout=settings.validate_env_llm_timeout,
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


def model_name(model: Any) -> str:
    return str(getattr(model, "model_name", "") or getattr(model, "model", "") or "")
