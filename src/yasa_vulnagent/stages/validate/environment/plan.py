"""Agent-assisted environment plan generation."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Mapping

from langgraph.runtime import Runtime

from ....agent.budget import BudgetStop, TaskBudget
from ....agent.context import ContextManager
from ....agent.runtime import run_tool_loop
from ....agent.tokens import TokenCounter
from ....workflow.state import RunContext
from ...discover.screen.tools import SourceToolbox
from .model import (
    EnvironmentConfigurationError,
    build_model,
    load_prompt,
    model_name,
    parse_json_object,
)
from .schema import EnvironmentState, plan_hash
from .storage import (
    paths_from_state,
    plan_file,
    plan_receipts_file,
    write_json,
)


def plan_node(
    state: EnvironmentState,
    runtime: Runtime[RunContext] | None = None,
) -> dict[str, Any]:
    context = runtime.context if runtime is not None else None
    if context is None:
        from ....config import load_settings

        context = RunContext(settings=load_settings())
    settings = context.settings
    revision = int(state.get("plan_revision", 0)) + 1
    plan_calls = int(state.get("plan_calls", 0)) + 1
    if plan_calls > settings.validate_env_max_plan_calls or revision > settings.validate_env_max_plan_revisions:
        return {
            **state,
            "status": "blocked",
            "next_action": "classify",
            "stop_reason": "plan_limit",
            "errors": [*state.get("errors", []), "environment plan revision limit reached"],
        }

    try:
        model = build_model(context)
    except EnvironmentConfigurationError as exc:
        return {
            **state,
            "status": "failed",
            "next_action": "classify",
            "stop_reason": "model_configuration",
            "errors": [*state.get("errors", []), str(exc)],
        }

    repository = Path(str(state["repository"]))
    source = SourceToolbox(
        repository,
        allow_all=True,
        max_output_chars=settings.validate_env_tool_output_chars,
        search_max_file_bytes=settings.discover_search_max_file_bytes,
        max_scan_files=settings.discover_search_max_scan_files,
    )
    tools = [tool for tool in source.langchain_tools() if getattr(tool, "name", "") != "save_note"]
    paths = paths_from_state(state)
    paths.work_dir.mkdir(parents=True, exist_ok=True)
    budget = TaskBudget(
        deadline=time.monotonic() + settings.validate_env_llm_timeout,
        max_model_calls=settings.validate_env_agent_max_calls,
        max_rounds_per_invocation=settings.validate_env_agent_max_rounds,
        hard_task_cap=max(settings.validate_env_agent_max_calls, settings.agent_hard_task_cap),
    )
    source_kind = _plan_source(state)
    prompt = _user_prompt(state, context, source_kind)
    counter = TokenCounter(settings.model, settings.agent_token_safety)
    agent_context = ContextManager(
        counter,
        max_tokens=max(1, settings.validate_env_context_chars // 4),
        trigger=settings.agent_compaction_trigger,
        keep_recent_results=settings.agent_keep_recent_results,
    )
    try:
        result = run_tool_loop(
            model,
            load_prompt("plan.md"),
            prompt,
            tools,
            budget=budget,
            usage=context.usage,
            stage="validate.environment.plan",
            task_id=f"environment-plan-{revision}",
            max_rounds=settings.validate_env_agent_max_rounds,
            artifact_dir=paths.work_dir,
            counter=counter,
            context=agent_context,
            json_expected=True,
            json_repair_attempts=settings.agent_json_repair_attempts,
            max_result_tokens=settings.agent_tool_result_tokens,
            request_timeout=settings.validate_env_llm_timeout,
            parallel_tools=True,
        )
    except BudgetStop as exc:
        return {
            **state,
            "status": "blocked",
            "next_action": "classify",
            "stop_reason": f"plan_{exc.reason}",
            "errors": [*state.get("errors", []), f"plan agent stopped: {exc.reason}"],
            "plan_calls": plan_calls,
        }
    except Exception as exc:
        return {
            **state,
            "status": "failed",
            "next_action": "classify",
            "stop_reason": "plan_agent_error",
            "errors": [*state.get("errors", []), f"plan agent failed: {exc}"],
            "plan_calls": plan_calls,
        }

    try:
        plan = parse_json_object(result.content, "environment plan")
    except ValueError as exc:
        return {
            **state,
            "status": "blocked",
            "next_action": "classify",
            "stop_reason": "invalid_plan_json",
            "errors": [*state.get("errors", []), str(exc)],
            "plan_calls": plan_calls,
            "plan_revision": revision,
        }

    plan["status"] = str(plan.get("status") or "ready").lower()
    plan.setdefault("inspection", {})
    plan.setdefault("assumptions", [])
    plan.setdefault("gaps", [])
    plan.setdefault("confidence", "medium")
    plan.setdefault("why", "")
    plan["plan_revision"] = revision
    plan["plan_source"] = source_kind
    plan["source_revision"] = state.get("source_revision", "")
    if source_kind != "initial" and not plan.get("changes"):
        plan["changes"] = ["plan revised from the previous attempt"]
    plan["model"] = model_name(model)

    receipts = list(source.receipts)
    if source_kind == "repair" and plan_hash(plan) == str(state.get("failed_plan_hash", "")):
        return {
            **state,
            "status": "blocked",
            "next_action": "classify",
            "stop_reason": "same_plan",
            "errors": [*state.get("errors", []), "repair produced the plan that already failed"],
            "plan_calls": plan_calls,
            "plan_revision": revision,
        }
    write_json(plan_file(state, revision), plan)
    write_json(plan_receipts_file(state, revision), receipts)
    update: EnvironmentState = {
        **state,
        "plan": plan,
        "plan_receipts": receipts,
        "plan_hash": plan_hash(plan),
        "plan_revision": revision,
        "plan_calls": plan_calls,
        "plan_source": source_kind,
        "gate": {},
        "approved_plan": {},
        "status": "running",
    }
    if plan["status"] == "blocked":
        return {
            **update,
            "status": "blocked",
            "next_action": "classify",
            "stop_reason": "plan_blocked",
            "gaps": _unique([*state.get("gaps", []), *[str(item) for item in plan.get("gaps", [])]]),
        }
    return {**update, "next_action": "plan_gate"}


def _plan_source(state: Mapping[str, Any]) -> str:
    if state.get("diagnosis"):
        return "repair"
    if state.get("gate"):
        return "gate_feedback"
    return "initial"


def _user_prompt(state: Mapping[str, Any], context: RunContext, source_kind: str) -> str:
    settings = context.settings
    payload = {
        "repository": state.get("repository", ""),
        "source_revision": state.get("source_revision", ""),
        "plan_revision": int(state.get("plan_revision", 0)) + 1,
        "plan_source": source_kind,
        "base_image_allowlist": list(settings.validate_env_base_image_allowlist),
        "gate_mode": settings.validate_env_gate_mode,
        "previous_plan": state.get("plan", {}),
        "diagnosis": state.get("diagnosis", {}),
        "gate_feedback": state.get("gate", {}),
        "max_context_chars": settings.validate_env_context_chars,
    }
    return (
        "Inspect the repository with the read-only tools and produce one environment plan. "
        "Cite only files you actually read with read_file. Return only the JSON object.\n\n"
        + _json_text(payload)
    )


def _json_text(value: Any) -> str:
    import json

    return json.dumps(value, ensure_ascii=False, indent=2)


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))
