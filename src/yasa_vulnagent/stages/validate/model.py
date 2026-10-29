"""Model construction and JSON parsing for validation agents."""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any

from ...workflow.state import RunContext


class ValidationConfigurationError(RuntimeError):
    """Raised when the validate stage cannot build or authenticate its model."""


class ValidationModelError(RuntimeError):
    """Raised when a validate model request fails after retries."""


class ValidationPhaseError(RuntimeError):
    """Raised when an agent finished without a usable result object."""

    def __init__(self, message: str, stop_reason: str = "") -> None:
        super().__init__(message)
        self.stop_reason = stop_reason


def load_prompt(name: str) -> str:
    return files("yasa_vulnagent.stages.validate").joinpath(
        "prompts", name
    ).read_text(encoding="utf-8")


def build_model(context: RunContext) -> Any:
    settings = context.settings
    configured = settings.validate_model.strip()
    if context.model is not None and (not configured or configured == settings.model):
        return context.model
    if not settings.api_key:
        raise ValidationConfigurationError("LLM_API_KEY is required for the validate stage")
    try:
        from langchain_openai import ChatOpenAI
    except ImportError as exc:
        raise ValidationConfigurationError(
            "langchain-openai is required for the validate stage"
        ) from exc
    return ChatOpenAI(
        model=configured or settings.model,
        api_key=settings.api_key,
        base_url=settings.base_url,
        timeout=settings.validate_llm_timeout,
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
