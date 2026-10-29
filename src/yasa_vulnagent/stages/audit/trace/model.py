"""Model helpers and JSON parsing for audit trace."""

from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path
from typing import Any

from ....config import Settings
from ....workflow.state import RunContext
from .constants import MODEL_TIMEOUT_SECONDS


class TraceError(RuntimeError):
    """Base error for a trace task."""


class TraceConfigurationError(TraceError):
    """Raised when the trace model is not configured."""


class TraceModelError(TraceError):
    """Raised when a trace model call cannot produce usable output."""


def load_prompt(name: str) -> str:
    root = files("yasa_vulnagent.stages.audit.trace")
    candidate = root.joinpath(name)
    if not candidate.is_file():
        candidate = root.joinpath("specialists").joinpath(name)
    try:
        return candidate.read_text(encoding="utf-8")
    except OSError as exc:
        raise TraceConfigurationError(f"trace prompt is missing: {name}") from exc


def build_model(context: RunContext) -> Any:
    if context.model is not None:
        return context.model
    settings = context.settings
    if not settings.api_key:
        raise TraceConfigurationError("LLM_API_KEY is required for the audit trace stage")
    try:
        from langchain_openai import ChatOpenAI
    except ImportError as exc:
        raise TraceConfigurationError(
            "langchain-openai is required for the audit trace stage"
        ) from exc
    return ChatOpenAI(
        model=settings.model,
        api_key=settings.api_key,
        base_url=settings.base_url,
        timeout=MODEL_TIMEOUT_SECONDS,
        max_retries=0,
    )


def model_name(model: Any) -> str:
    return str(getattr(model, "model_name", "") or getattr(model, "model", "") or "")


def parse_json_object(content: str, label: str) -> dict[str, Any]:
    text = content.strip()
    if not text:
        raise TraceModelError(f"{label}: model returned empty content")
    if text.startswith("```"):
        lines = text.splitlines()
        if lines:
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end < start:
        raise TraceModelError(f"{label}: model did not return a JSON object")
    try:
        value = json.loads(text[start : end + 1])
    except json.JSONDecodeError as exc:
        raise TraceModelError(f"{label}: invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise TraceModelError(f"{label}: model output must be an object")
    return value


def prompt_path(name: str) -> Path:
    """Return a filesystem path for diagnostics and tests."""
    return Path(str(files("yasa_vulnagent.stages.audit.trace").joinpath(name)))


def settings_snapshot(settings: Settings) -> dict[str, Any]:
    return {
        "model": settings.model,
        "context_tokens": settings.agent_context_tokens,
        "tool_result_tokens": settings.agent_tool_result_tokens,
    }
