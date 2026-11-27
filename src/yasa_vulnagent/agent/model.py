"""Shared model construction and JSON parsing helpers across workflow stages."""

from __future__ import annotations

import json
from typing import Any, Type


def build_chat_model(
    context: Any,
    *,
    stage_label: str,
    timeout: float | int,
    error_cls: Type[Exception],
    model_override: str = "",
) -> Any:
    """Build or reuse a ChatOpenAI model for a workflow stage."""
    settings = context.settings
    configured = str(model_override or "").strip()
    if context.model is not None and (not configured or configured == settings.model):
        return context.model
    if not settings.api_key:
        raise error_cls(f"LLM_API_KEY is required for the {stage_label} stage")
    try:
        from langchain_openai import ChatOpenAI
    except ImportError as exc:
        raise error_cls(f"langchain-openai is required for the {stage_label} stage") from exc
    return ChatOpenAI(
        model=configured or settings.model,
        api_key=settings.api_key,
        base_url=settings.base_url,
        timeout=timeout,
        max_retries=0,
    )


def model_name(model: Any) -> str:
    """Return a best-effort display name for a LangChain chat model."""
    return str(getattr(model, "model_name", "") or getattr(model, "model", "") or "")


def parse_json_object(
    content: str,
    label: str,
    *,
    error_cls: Type[Exception] = ValueError,
) -> dict[str, Any]:
    """Parse one JSON object from model output, tolerating markdown fences."""
    text = str(content or "").strip()
    if not text:
        raise error_cls(f"{label}: model returned empty content")
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
        raise error_cls(f"{label}: model did not return a JSON object")
    try:
        value = json.loads(text[start : end + 1])
    except json.JSONDecodeError as exc:
        raise error_cls(f"{label}: invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise error_cls(f"{label}: model output must be an object")
    return value
