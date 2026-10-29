"""Bounded validation agents: plan, primary execution, and fresh verifier."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Mapping

from langchain_core.tools import StructuredTool

from ...agent.budget import TaskBudget
from ...agent.context import ContextManager
from ...agent.retry import RetryPolicy
from ...agent.runtime import ModelFatal, ModelRequest, run_tool_loop
from ...agent.tokens import TokenCounter
from ...agent.usage import UsageRecorder
from ...workflow.state import RunContext
from ..discover.screen.tools import SourceToolbox
from .commands import ShellRunner, _redact
from .model import (
    ValidationConfigurationError,
    ValidationModelError,
    ValidationPhaseError,
    build_model,
    load_prompt,
    parse_json_object,
)
from .notes import NoteStore
from .schema import LEVELS, MODES
from .storage import write_json


def _tools(
    repository: Path,
    settings: Any,
    *,
    shell: ShellRunner | None = None,
    notes: NoteStore | None = None,
) -> list[Any]:
    toolbox = SourceToolbox(
        repository,
        allow_all=True,
        max_output_chars=settings.validate_tool_output_chars,
    )
    tools = [tool for tool in toolbox.langchain_tools() if tool.name != "save_note"]
    if shell is not None:
        tools.extend(shell.langchain_tools())
    if notes is not None:
        tools.append(
            StructuredTool.from_function(
                func=notes.add,
                name="save_note",
                description=(
                    "Save a short note (key, text) for this finding. Use it for ports, "
                    "container names, credentials, error signatures and ruled-out paths; "
                    "notes survive context compaction and resume."
                ),
            )
        )
    return tools


def _budget(settings: Any, deadline: float) -> TaskBudget:
    return TaskBudget(
        deadline=deadline,
        max_model_calls=settings.validate_agent_max_calls,
        max_rounds_per_invocation=settings.validate_agent_max_rounds,
        hard_task_cap=settings.validate_agent_max_calls,
    )


def _usage(context: RunContext) -> Any:
    if context.usage is not None:
        return context.usage
    return UsageRecorder(context.settings.usage_price_table)


def _run(
    *,
    context: RunContext,
    system_prompt: str,
    user_prompt: str,
    tools: list[Any],
    artifact_dir: Path,
    stage: str,
    task_id: str,
    deadline: float,
    notes: NoteStore | None = None,
) -> Any:
    settings = context.settings
    counter = TokenCounter(settings.model, settings.agent_token_safety)
    started = time.monotonic()
    try:
        result = _run_loop(
            context=context,
            settings=settings,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            tools=tools,
            artifact_dir=artifact_dir,
            stage=stage,
            task_id=task_id,
            deadline=deadline,
            counter=counter,
            notes=notes,
        )
        result.elapsed_seconds = time.monotonic() - started
        return result
    except ModelFatal as exc:
        raise ValidationConfigurationError(f"validate model configuration failed: {exc}") from exc
    except (ModelRequest, TimeoutError) as exc:
        raise ValidationModelError(f"{stage} model request failed: {exc}") from exc


def _run_loop(
    *,
    context: RunContext,
    settings: Any,
    system_prompt: str,
    user_prompt: str,
    tools: list[Any],
    artifact_dir: Path,
    stage: str,
    task_id: str,
    deadline: float,
    counter: TokenCounter,
    notes: NoteStore | None,
) -> Any:
    return run_tool_loop(
        build_model(context),
        system_prompt,
        user_prompt,
        tools,
        budget=_budget(settings, deadline),
        usage=_usage(context),
        stage=stage,
        task_id=task_id,
        max_rounds=settings.validate_agent_max_rounds,
        artifact_dir=artifact_dir,
        counter=counter,
        context=ContextManager(
            counter,
            max_tokens=settings.agent_context_tokens,
            trigger=settings.agent_compaction_trigger,
            keep_recent_results=settings.agent_keep_recent_results,
        ),
        retry=RetryPolicy(
            attempts=settings.agent_model_retries,
            tool_attempts=settings.agent_tool_retries,
        ),
        json_expected=True,
        json_repair_attempts=settings.agent_json_repair_attempts,
        max_result_tokens=settings.agent_tool_result_tokens,
        request_timeout=settings.validate_llm_timeout,
        finalize_on_exhaustion=True,
        compaction_hint=(lambda: notes.text(3000)) if notes is not None else None,
        # Read-only tools could run in parallel, but validation keeps command
        # ordering deterministic and is intentionally left sequential.
    )


def run_plan(
    *,
    context: RunContext,
    repository: Path,
    paths: Any,
    finding: Mapping[str, Any],
    environment: Mapping[str, Any],
    artifact_dir: Path,
    deadline: float,
) -> dict[str, Any]:
    finding_id = str(finding.get("id", ""))
    prompt = json.dumps(
        {
            "repository": str(repository),
            "finding": finding,
            "environment": environment,
            "validation_dir": str(paths.root),
        },
        ensure_ascii=False,
        indent=2,
    )
    result = _run(
        context=context,
        system_prompt=load_prompt("plan.md"),
        user_prompt="Produce the validation claim and harness for this finding.\n\n" + prompt,
        tools=_tools(repository, context.settings),
        artifact_dir=artifact_dir,
        stage="validate.plan",
        task_id=f"validate-plan-{finding_id}",
        deadline=deadline,
    )
    try:
        value = parse_json_object(result.content, "validation plan")
    except ValueError as exc:
        reason = str(result.stop_reason)
        raise ValidationPhaseError(str(exc), "" if reason == "complete" else reason) from exc
    value["finding_id"] = finding_id
    value["agent_stop_reason"] = str(getattr(result, "stop_reason", ""))
    check_plan(value, finding_id)
    write_json(artifact_dir / "plan.json", value)
    _write_receipts(artifact_dir, result, context)
    return value


def run_execute(
    *,
    context: RunContext,
    repository: Path,
    paths: Any,
    finding: Mapping[str, Any],
    plan: Mapping[str, Any],
    environment: Mapping[str, Any],
    shell: ShellRunner,
    artifact_dir: Path,
    deadline: float,
) -> dict[str, Any]:
    finding_id = str(finding.get("id", ""))
    notes = NoteStore(artifact_dir / "notes.jsonl")
    prompt = json.dumps(
        {
            "repository": str(repository),
            "validation_dir": str(paths.root),
            "finding": finding,
            "plan": plan,
            "environment": environment,
            "host_tools": {"repo": str(repository), "validation_dir": str(paths.root)},
        },
        ensure_ascii=False,
        indent=2,
    )
    saved = notes.text(3000)
    if saved:
        prompt = saved + "\n\n" + prompt
    result = _run(
        context=context,
        system_prompt=load_prompt("execute.md"),
        user_prompt="Validate this finding against the live target.\n\n" + prompt,
        tools=_tools(repository, context.settings, shell=shell, notes=notes),
        artifact_dir=artifact_dir,
        stage="validate.execute",
        task_id=f"validate-execute-{finding_id}",
        deadline=deadline,
        notes=notes,
    )
    try:
        value = parse_json_object(result.content, "validation result")
    except ValueError as exc:
        reason = str(result.stop_reason)
        raise ValidationPhaseError(str(exc), "" if reason == "complete" else reason) from exc
    if isinstance(value.get("result"), dict):
        value = value["result"]
    value["finding_id"] = finding_id
    value["id"] = finding_id
    value["agent_stop_reason"] = str(getattr(result, "stop_reason", ""))
    _merge_claim(value, plan)
    _merge_environment(value, environment)
    write_json(artifact_dir / "result.json", value)
    _write_receipts(artifact_dir, result, context)
    return value


def run_verify(
    *,
    context: RunContext,
    repository: Path,
    paths: Any,
    finding: Mapping[str, Any],
    plan: Mapping[str, Any],
    primary: Mapping[str, Any],
    environment: Mapping[str, Any],
    shell: ShellRunner,
    artifact_dir: Path,
    deadline: float,
) -> dict[str, Any]:
    finding_id = str(finding.get("id", ""))
    notes = NoteStore(artifact_dir / "notes.jsonl")
    prompt = json.dumps(
        {
            "repository": str(repository),
            "validation_dir": str(paths.root),
            "finding": finding,
            "plan": plan,
            "primary_result": primary,
            "environment": environment,
        },
        ensure_ascii=False,
        indent=2,
    )
    saved = notes.text(3000)
    if saved:
        prompt = saved + "\n\n" + prompt
    result = _run(
        context=context,
        system_prompt=load_prompt("verify.md"),
        user_prompt="Independently rerun the decisive validation step.\n\n" + prompt,
        tools=_tools(repository, context.settings, shell=shell, notes=notes),
        artifact_dir=artifact_dir,
        stage="validate.verify",
        task_id=f"validate-verify-{finding_id}",
        deadline=deadline,
        notes=notes,
    )
    try:
        value = parse_json_object(result.content, "verifier result")
    except ValueError as exc:
        reason = str(result.stop_reason)
        raise ValidationPhaseError(str(exc), "" if reason == "complete" else reason) from exc
    if isinstance(value.get("result"), dict):
        value = value["result"]
    value["finding_id"] = finding_id
    value["id"] = finding_id
    value["agent_stop_reason"] = str(getattr(result, "stop_reason", ""))
    _merge_environment(value, environment)
    write_json(artifact_dir / "result.json", value)
    _write_receipts(artifact_dir, result, context)
    return value


def _merge_claim(value: dict[str, Any], plan: Mapping[str, Any]) -> None:
    claim = plan.get("claim") if isinstance(plan.get("claim"), dict) else {}
    behavior = value.get("intended_behavior")
    if not isinstance(behavior, dict):
        behavior = {}
        value["intended_behavior"] = behavior
    for key in (
        "legitimate_actor",
        "legitimate_resource",
        "expected_capability",
        "security_boundary",
    ):
        if not behavior.get(key):
            behavior[key] = str(claim.get(key, "") or "not recorded")
    if not behavior.get("security_boundary_crossed"):
        behavior["security_boundary_crossed"] = "unknown"
    if not value.get("rubric"):
        value["rubric"] = list(claim.get("rubric", [])) or [
            "runtime behavior compared with the finding's intended boundary"
        ]
    if not value.get("validation_method"):
        value["validation_method"] = "runtime validation"
    if not value.get("reproduction_level"):
        harness = plan.get("harness") if isinstance(plan.get("harness"), dict) else {}
        value["reproduction_level"] = str(harness.get("level", "not_attempted"))


def _merge_environment(value: dict[str, Any], environment: Mapping[str, Any]) -> None:
    current = value.get("environment")
    if not isinstance(current, dict):
        current = {}
        value["environment"] = current
    current.setdefault("runtime", "docker")
    if not current.get("dependencies"):
        image = str(environment.get("image", "") or "environment image")
        current["dependencies"] = [image]
    if not current.get("configuration"):
        current["configuration"] = ["environment handle", "agent-declared local fixtures"]


def check_plan(value: Mapping[str, Any], finding_id: str) -> None:
    claim = value.get("claim")
    harness = value.get("harness")
    if not isinstance(claim, dict) or not claim:
        raise ValueError("validation plan is missing its claim")
    if not isinstance(harness, dict):
        raise ValueError("validation plan is missing its harness")
    if str(harness.get("mode", "")) not in MODES:
        raise ValueError("validation plan has an unsupported mode")
    if str(harness.get("level", "")) not in LEVELS:
        raise ValueError("validation plan has an unsupported reproduction level")
    if not harness.get("baseline") or not harness.get("poc"):
        raise ValueError("validation plan needs a baseline and a PoC")
    if not isinstance(harness.get("observations"), list) or not harness["observations"]:
        raise ValueError("validation plan needs observations")
    if str(value.get("finding_id", "")) != finding_id:
        raise ValueError("validation plan has the wrong finding id")


def _write_receipts(artifact_dir: Path, result: Any, context: RunContext) -> None:
    settings = context.settings
    model = str(settings.validate_model or settings.model)
    write_json(
        artifact_dir / "agent.json",
        {
            "model": model,
            "stop_reason": str(getattr(result, "stop_reason", "")),
            "tool_calls": int(getattr(result, "tool_calls", 0)),
            "rounds": int(getattr(result, "rounds", 0)),
            "model_calls": int(getattr(result, "model_calls", 0)),
            "elapsed_seconds": round(float(getattr(result, "elapsed_seconds", 0.0)), 3),
            "last_text": _redact(str(getattr(result, "last_text", "")))[:4000],
            "calls": list(getattr(result, "calls", [])),
            "receipts": list(getattr(result, "receipts", [])),
        },
    )
