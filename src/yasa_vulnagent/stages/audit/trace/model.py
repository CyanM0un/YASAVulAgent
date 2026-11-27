"""Model helpers and JSON parsing for audit trace."""

from __future__ import annotations

from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Any

from ....agent.model import (
    build_chat_model,
    model_name,
    parse_json_object as _parse_json_object,
)
from ....config import Settings
from ....workflow.state import RunContext
from .constants import MODEL_TIMEOUT_SECONDS


class TraceError(RuntimeError):
    """Base error for a trace task."""


class TraceConfigurationError(TraceError):
    """Raised when the trace model is not configured."""


class TraceModelError(TraceError):
    """Raised when a trace model call cannot produce usable output."""


@lru_cache(maxsize=64)
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
    return build_chat_model(
        context,
        stage_label="audit trace",
        timeout=MODEL_TIMEOUT_SECONDS,
        error_cls=TraceConfigurationError,
    )


def parse_json_object(content: str, label: str) -> dict[str, Any]:
    return _parse_json_object(content, label, error_cls=TraceModelError)


def prompt_path(name: str) -> Path:
    """Return a filesystem path for diagnostics and tests."""
    return Path(str(files("yasa_vulnagent.stages.audit.trace").joinpath(name)))


def settings_snapshot(settings: Settings) -> dict[str, Any]:
    return {
        "model": settings.model,
        "context_tokens": settings.agent_context_tokens,
        "tool_result_tokens": settings.agent_tool_result_tokens,
    }
