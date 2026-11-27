"""Model helpers and JSON parsing for audit verify."""

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


class VerifyError(RuntimeError):
    """Base error for audit verify."""


class VerifyConfigurationError(VerifyError):
    """Raised when verify cannot run with the prepared inputs."""


class VerifyBudgetError(VerifyError):
    """Raised when the audit budget expires before verification."""


class VerifyModelError(VerifyError):
    """Raised when a verifier or reviewer cannot produce usable output."""


@lru_cache(maxsize=64)
def load_prompt(name: str) -> str:
    root = files("yasa_vulnagent.stages.audit.verify")
    candidate = root.joinpath(name)
    try:
        return candidate.read_text(encoding="utf-8")
    except OSError as exc:
        raise VerifyConfigurationError(f"verify prompt is missing: {name}") from exc


def build_model(context: RunContext) -> Any:
    return build_chat_model(
        context,
        stage_label="audit verify",
        timeout=MODEL_TIMEOUT_SECONDS,
        error_cls=VerifyConfigurationError,
    )


def parse_json_object(content: str, label: str) -> dict[str, Any]:
    return _parse_json_object(content, label, error_cls=VerifyModelError)


def prompt_path(name: str) -> Path:
    """Return a filesystem path for diagnostics and tests."""
    return Path(str(files("yasa_vulnagent.stages.audit.verify").joinpath(name)))


def settings_snapshot(settings: Settings) -> dict[str, Any]:
    return {
        "model": settings.model,
        "context_tokens": settings.agent_context_tokens,
        "tool_result_tokens": settings.agent_tool_result_tokens,
    }
