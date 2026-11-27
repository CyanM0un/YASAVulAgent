"""Model helpers and JSON parsing for audit recon."""

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


class ReconError(RuntimeError):
    """Base error for audit recon."""


class ReconConfigurationError(ReconError):
    """Raised when recon cannot be configured for the prepared inputs."""


class ReconBudgetError(ReconError):
    """Raised when the stage budget expires before recon can run."""


class ReconModelError(ReconError):
    """Raised when recon cannot produce a complete, valid result."""


@lru_cache(maxsize=8)
def load_prompt() -> str:
    path = files("yasa_vulnagent.stages.audit.recon").joinpath("prompt.md")
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReconConfigurationError("recon prompt is missing") from exc


def build_model(context: RunContext) -> Any:
    return build_chat_model(
        context,
        stage_label="audit recon",
        timeout=MODEL_TIMEOUT_SECONDS,
        error_cls=ReconConfigurationError,
    )


def parse_json_object(content: str, label: str) -> dict[str, Any]:
    return _parse_json_object(content, label, error_cls=ReconModelError)


def prompt_path() -> Path:
    """Return a filesystem path for diagnostics and tests."""
    return Path(str(files("yasa_vulnagent.stages.audit.recon").joinpath("prompt.md")))


def settings_snapshot(settings: Settings) -> dict[str, Any]:
    return {
        "model": settings.model,
        "context_tokens": settings.agent_context_tokens,
        "tool_result_tokens": settings.agent_tool_result_tokens,
    }
