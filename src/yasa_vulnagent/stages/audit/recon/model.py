"""Model helpers and JSON parsing for audit recon."""

from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path
from typing import Any

from ....config import Settings
from ....workflow.state import RunContext
from .constants import MODEL_TIMEOUT_SECONDS


class ReconError(RuntimeError):
    """Base error for audit recon."""


class ReconConfigurationError(ReconError):
    """Raised when recon cannot be configured for the prepared inputs."""


class ReconBudgetError(ReconError):
    """Raised when the stage budget expires before recon can run."""


class ReconModelError(ReconError):
    """Raised when recon cannot produce a complete, valid result."""


def load_prompt() -> str:
    path = files("yasa_vulnagent.stages.audit.recon").joinpath("prompt.md")
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReconConfigurationError("recon prompt is missing") from exc


def build_model(context: RunContext) -> Any:
    if context.model is not None:
        return context.model
    settings = context.settings
    if not settings.api_key:
        raise ReconConfigurationError("LLM_API_KEY is required for the audit recon stage")
    try:
        from langchain_openai import ChatOpenAI
    except ImportError as exc:
        raise ReconConfigurationError(
            "langchain-openai is required for the audit recon stage"
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
        raise ReconModelError(f"{label}: model returned empty content")
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
        raise ReconModelError(f"{label}: model did not return a JSON object")
    try:
        value = json.loads(text[start : end + 1])
    except json.JSONDecodeError as exc:
        raise ReconModelError(f"{label}: invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ReconModelError(f"{label}: model output must be an object")
    return value


def prompt_path() -> Path:
    """Return a filesystem path for diagnostics and tests."""
    return Path(str(files("yasa_vulnagent.stages.audit.recon").joinpath("prompt.md")))


def settings_snapshot(settings: Settings) -> dict[str, Any]:
    return {
        "model": settings.model,
        "context_tokens": settings.agent_context_tokens,
        "tool_result_tokens": settings.agent_tool_result_tokens,
    }
