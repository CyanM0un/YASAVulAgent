"""Model consolidation for one audit planning batch."""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any

from ....agent.retry import RetryPolicy
from ....workflow.state import RunContext

PLAN_MODEL_TIMEOUT_SECONDS = 120
MAX_SEED_TASKS_PER_GROUP = 4
_PRIORITIES = {"high", "normal", "low"}


class PlanConfigurationError(RuntimeError):
    """Raised when the audit plan model is not configured."""


class PlanModelError(RuntimeError):
    """Raised when the audit plan model cannot produce usable output."""


def load_prompt() -> str:
    return files("yasa_vulnagent.stages.audit.plan").joinpath("prompt.md").read_text(
        encoding="utf-8"
    )


def build_model(context: RunContext) -> Any:
    if context.model is not None:
        return context.model
    settings = context.settings
    if not settings.api_key:
        raise PlanConfigurationError("LLM_API_KEY is required for the audit plan stage")
    try:
        from langchain_openai import ChatOpenAI
    except ImportError as exc:
        raise PlanConfigurationError(
            "langchain-openai is required for the audit plan stage"
        ) from exc
    return ChatOpenAI(
        model=settings.model,
        api_key=settings.api_key,
        base_url=settings.base_url,
        timeout=PLAN_MODEL_TIMEOUT_SECONDS,
        max_retries=0,
    )


def run_batch(
    model: Any,
    batch: dict[str, Any],
    seed_tasks: list[dict[str, Any]],
    usage: Any,
    *,
    model_name: str = "",
    retry: RetryPolicy | None = None,
) -> dict[str, Any]:
    """Run one model call (with retries) and validate the batch response."""
    from langchain_core.messages import HumanMessage, SystemMessage

    prompt = (
        "Plan only the seed tasks in this batch:\n"
        f"{json.dumps({'batch_id': batch['id'], 'kind': batch['kind'], 'seed_tasks': seed_tasks}, ensure_ascii=False, indent=2)}"
    )
    if usage is not None and hasattr(usage, "exceeded"):
        reason = str(usage.exceeded() or "")
        if reason:
            raise PlanModelError(f"plan model budget exhausted for {batch['id']}: {reason}")
    system_prompt = load_prompt()
    retry = retry or RetryPolicy()
    attempts = 0

    def invoke() -> Any:
        nonlocal attempts
        attempts += 1
        return model.invoke(
            [SystemMessage(content=system_prompt), HumanMessage(content=prompt)]
        )

    try:
        response = retry.model(invoke)
    except Exception as exc:
        raise PlanModelError(
            f"plan model call failed for {batch['id']} after {max(1, attempts)} attempt(s): {exc}"
        ) from exc

    content = _content_text(getattr(response, "content", ""))
    if usage is not None:
        usage.record(
            stage="audit.plan",
            task_id=str(batch["id"]),
            model=model_name or _model_name(model),
            usage=getattr(response, "usage_metadata", None),
            attempts=max(1, attempts),
            retries=max(0, attempts - 1),
        )
    payload = _parse_json_object(content, str(batch["id"]))
    validate_batch_output(payload, batch, seed_tasks)
    return payload


def validate_batch_output(
    payload: dict[str, Any],
    batch: dict[str, Any],
    seed_tasks: list[dict[str, Any]],
) -> None:
    """Validate one model response against its batch."""
    if not isinstance(payload, dict):
        raise PlanModelError(f"{batch['id']}: model output must be a JSON object")
    groups = payload.get("groups")
    order = payload.get("order")
    if not isinstance(groups, list) or not groups:
        raise PlanModelError(f"{batch['id']}: groups must be a non-empty array")
    if not isinstance(order, list):
        raise PlanModelError(f"{batch['id']}: order must be an array")

    seed_by_id = {str(task["id"]): task for task in seed_tasks}
    seen: set[str] = set()
    for index, group in enumerate(groups):
        if not isinstance(group, dict):
            raise PlanModelError(f"{batch['id']}: group {index} must be an object")
        seed_ids = group.get("seed_task_ids")
        if (
            not isinstance(seed_ids, list)
            or not seed_ids
            or not all(isinstance(item, str) and item for item in seed_ids)
        ):
            raise PlanModelError(f"{batch['id']}: group {index} has invalid seed_task_ids")
        if len(seed_ids) != len(set(seed_ids)):
            raise PlanModelError(f"{batch['id']}: group {index} repeats a seed task")
        if len(seed_ids) > MAX_SEED_TASKS_PER_GROUP:
            raise PlanModelError(f"{batch['id']}: group {index} is too large")
        priority = group.get("priority")
        if priority not in _PRIORITIES:
            raise PlanModelError(f"{batch['id']}: group {index} has invalid priority")
        reason = group.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise PlanModelError(f"{batch['id']}: group {index} has no reason")

        tasks = []
        for seed_id in seed_ids:
            if seed_id not in seed_by_id:
                raise PlanModelError(f"{batch['id']}: unknown seed task {seed_id}")
            if seed_id in seen:
                raise PlanModelError(f"{batch['id']}: seed task {seed_id} appears twice")
            seen.add(seed_id)
            tasks.append(seed_by_id[seed_id])
        kinds = {str(task["kind"]) for task in tasks}
        if len(kinds) != 1:
            raise PlanModelError(f"{batch['id']}: group {index} mixes kinds")
        if len(tasks) > 1:
            if not _common_path(tasks):
                raise PlanModelError(f"{batch['id']}: group {index} has no common path")
            if any(task.get("status") == "blocked" for task in tasks):
                raise PlanModelError(f"{batch['id']}: blocked seed is merged")

    if set(seed_by_id) != seen:
        missing = sorted(set(seed_by_id) - seen)
        raise PlanModelError(f"{batch['id']}: missing seed tasks: {missing}")

    if not all(
        isinstance(item, int) and not isinstance(item, bool) for item in order
    ):
        raise PlanModelError(f"{batch['id']}: order must contain integers")
    if len(order) != len(groups) or set(order) != set(range(len(groups))):
        raise PlanModelError(f"{batch['id']}: order is not a complete permutation")


def _common_path(tasks: list[dict[str, Any]]) -> bool:
    shared = set(tasks[0].get("paths", []))
    for task in tasks[1:]:
        shared &= set(task.get("paths", []))
    return bool(shared)


def _parse_json_object(content: str, label: str) -> dict[str, Any]:
    text = content.strip()
    if not text:
        raise PlanModelError(f"{label}: model returned empty content")
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
        raise PlanModelError(f"{label}: model did not return a JSON object")
    try:
        value = json.loads(text[start : end + 1])
    except json.JSONDecodeError as exc:
        raise PlanModelError(f"{label}: invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise PlanModelError(f"{label}: model output must be a JSON object")
    return value


def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
        return "".join(parts)
    return str(content or "")


def _model_name(model: Any) -> str:
    return str(getattr(model, "model_name", "") or getattr(model, "model", "") or "")
