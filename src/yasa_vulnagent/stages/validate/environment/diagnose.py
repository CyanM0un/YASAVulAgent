"""Agent-assisted diagnosis of build and smoke failures."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any, Mapping

from langchain_core.tools import StructuredTool
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
from .schema import EnvironmentState
from .storage import attempt_dir, paths_from_state, write_json


def diagnose_node(
    state: EnvironmentState,
    runtime: Runtime[RunContext] | None = None,
) -> dict[str, Any]:
    context = runtime.context if runtime is not None else None
    if context is None:
        from ....config import load_settings

        context = RunContext(settings=load_settings())
    settings = context.settings
    calls = int(state.get("diagnose_calls", 0)) + 1
    if calls > settings.validate_env_max_diagnose_calls:
        return _blocked(state, "diagnose_limit", "diagnosis call limit reached")
    try:
        model = build_model(context)
    except EnvironmentConfigurationError as exc:
        return {
            **dict(state),
            "status": "failed",
            "next_action": "classify",
            "stop_reason": "model_configuration",
            "errors": [*state.get("errors", []), str(exc)],
            "diagnose_calls": calls,
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
    tools.append(_read_log_tool(Path(str(state["artifact_dir"]))))
    paths = paths_from_state(state)
    paths.work_dir.mkdir(parents=True, exist_ok=True)
    budget = TaskBudget(
        deadline=time.monotonic() + settings.validate_env_llm_timeout,
        max_model_calls=settings.validate_env_agent_max_calls,
        max_rounds_per_invocation=settings.validate_env_agent_max_rounds,
        hard_task_cap=max(settings.validate_env_agent_max_calls, settings.agent_hard_task_cap),
    )
    prompt = _user_prompt(state)
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
            load_prompt("diagnose.md"),
            prompt,
            tools,
            budget=budget,
            usage=context.usage,
            stage="validate.environment.diagnose",
            task_id=f"environment-diagnose-{state.get('attempt', 0)}-{calls}",
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
        return _blocked(state, f"diagnose_{exc.reason}", f"diagnosis agent stopped: {exc.reason}")
    except Exception as exc:
        return {
            **dict(state),
            "status": "failed",
            "next_action": "classify",
            "stop_reason": "diagnose_agent_error",
            "errors": [*state.get("errors", []), f"diagnosis agent failed: {exc}"],
            "diagnose_calls": calls,
        }
    try:
        diagnosis = parse_json_object(result.content, "environment diagnosis")
    except ValueError as exc:
        return _blocked(state, "invalid_diagnosis_json", str(exc))
    diagnosis["model"] = model_name(model)
    attempt = int(state.get("attempt", 0))
    write_json(attempt_dir(state, attempt) / "diagnosis.json", diagnosis)
    signature = _failure_signature(diagnosis, state.get("failure", {}))
    signatures = list(state.get("failure_signatures", []))
    if signature in signatures:
        update = {
            **dict(state),
            "diagnosis": diagnosis,
            "diagnose_calls": calls,
            "failure_signatures": signatures,
        }
        return _blocked(update, "failure_stagnation", "the same failure repeated")
    signatures.append(signature)
    retryable = _truthy(diagnosis.get("retryable"))
    needs_human = _truthy(diagnosis.get("needs_human"))
    update = {
        **dict(state),
        "diagnosis": diagnosis,
        "diagnose_calls": calls,
        "failure_signatures": signatures,
    }
    if not retryable or needs_human:
        return _blocked(update, "unrepairable_failure", str(diagnosis.get("root_cause", ""))[:1000])
    if int(state.get("attempt", 0)) >= settings.validate_env_max_build_attempts:
        return _blocked(update, "build_attempt_limit", "no build attempts remain")
    if int(state.get("plan_revision", 0)) >= settings.validate_env_max_plan_revisions:
        return _blocked(update, "plan_revision_limit", "no plan revisions remain")
    return {
        **update,
        "status": "running",
        "next_action": "plan",
    }


def _blocked(state: Mapping[str, Any], reason: str, message: str) -> dict[str, Any]:
    return {
        **dict(state),
        "status": "blocked",
        "next_action": "classify",
        "stop_reason": reason,
        "gaps": [*state.get("gaps", []), message],
    }


def _failure_signature(diagnosis: Mapping[str, Any], failure: Mapping[str, Any]) -> str:
    payload = "|".join(
        [
            str(diagnosis.get("category", "")),
            str(diagnosis.get("failed_step", "")),
            str(failure.get("exit_code", "")),
            str(failure.get("timed_out", "")),
            str(diagnosis.get("root_cause", ""))[:1000],
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _read_log_tool(root: Path) -> StructuredTool:
    def read_log(path: str, max_chars: int = 12000) -> dict[str, Any]:
        candidate = Path(str(path))
        if not candidate.is_absolute():
            candidate = root / candidate
        resolved = candidate.expanduser().resolve()
        try:
            resolved.relative_to(root.resolve())
        except ValueError:
            return {"error": "log path is outside the environment artifact directory"}
        if not resolved.is_file():
            return {"error": f"log file is unavailable: {resolved}"}
        try:
            text = resolved.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return {"error": str(exc)}
        limit = max(1000, min(int(max_chars), 40000))
        return {
            "path": str(resolved),
            "text": text[-limit:],
            "truncated": len(text) > limit,
            "original_chars": len(text),
        }

    return StructuredTool.from_function(
        func=read_log,
        name="read_log",
        description="Read the tail of a build or smoke log inside this environment artifact directory.",
    )


def _user_prompt(state: Mapping[str, Any]) -> str:
    import json

    failure = dict(state.get("failure") or {})
    log_excerpt = ""
    log_file = str(failure.get("log_file", "") or "")
    if log_file:
        log_excerpt = _summarize_log(Path(log_file))
    payload = {
        "failure": failure,
        "log_excerpt": log_excerpt,
        "plan": state.get("approved_plan") or state.get("plan") or {},
        "attempt": state.get("attempt", 0),
        "repository": state.get("repository", ""),
    }
    return (
        "Diagnose the failed environment build or smoke run. Do not change the plan; "
        "return only the JSON diagnosis object.\n\n" + json.dumps(payload, ensure_ascii=False, indent=2)
    )


def _summarize_log(path: Path, max_lines: int = 160) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    lines = text.splitlines()
    interesting = [
        line
        for line in lines
        if any(
            marker in line.lower()
            for marker in (
                "error",
                "failed",
                "fatal",
                "not found",
                "no such file",
                "permission denied",
                "exit code",
                "traceback",
                "modulenotfound",
            )
        )
    ]
    selected = _unique([*interesting[-80:], *lines[-80:]])
    return "\n".join(selected[-max_lines:])[-16000:]


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}
