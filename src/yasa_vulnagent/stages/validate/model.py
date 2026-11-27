"""Model construction and JSON parsing for validation agents."""

from __future__ import annotations

from functools import lru_cache
from importlib.resources import files
from typing import Any

from ...agent.model import build_chat_model, parse_json_object
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


@lru_cache(maxsize=32)
def load_prompt(name: str) -> str:
    return files("yasa_vulnagent.stages.validate").joinpath(
        "prompts", name
    ).read_text(encoding="utf-8")


def build_model(context: RunContext) -> Any:
    settings = context.settings
    return build_chat_model(
        context,
        stage_label="validate",
        timeout=settings.validate_llm_timeout,
        error_cls=ValidationConfigurationError,
        model_override=settings.validate_model,
    )
