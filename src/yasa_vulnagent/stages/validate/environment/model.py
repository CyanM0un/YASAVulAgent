"""Model construction and JSON parsing for environment agents."""

from __future__ import annotations

from functools import lru_cache
from importlib.resources import files
from typing import Any

from ....agent.model import build_chat_model, model_name, parse_json_object
from ....workflow.state import RunContext


class EnvironmentConfigurationError(RuntimeError):
    """Raised when the environment stage cannot build its model."""


@lru_cache(maxsize=32)
def load_prompt(name: str) -> str:
    return files("yasa_vulnagent.stages.validate.environment").joinpath(
        "prompts", name
    ).read_text(encoding="utf-8")


def build_model(context: RunContext) -> Any:
    settings = context.settings
    return build_chat_model(
        context,
        stage_label="validate environment",
        timeout=settings.validate_env_llm_timeout,
        error_cls=EnvironmentConfigurationError,
        model_override=settings.validate_env_model,
    )
