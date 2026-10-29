"""Recon stage harness: model, tools, validation, and durable merging."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from ....agent.artifacts import ToolResultStore
from ....agent.budget import BudgetStop, SharedBudgetAdapter
from ....agent.context import ContextManager
from ....agent.retry import RetryPolicy
from ....agent.runtime import run_tool_loop_async
from ....agent.tokens import TokenCounter
from ....storage import utc_now
from ....workflow.state import RunContext
from ...discover.screen.mcp import open_yasa_mcp
from ...discover.screen.tools import ReadCache, SourceToolbox
from ..budget import AuditBudget, AuditTaskBudget
from ..prepare.inventory import current_revision
from ..storage import (
    AuditPaths,
    load_json,
    paths_from_state,
    write_recon_checkpoint,
)
from ..trace.result import EvidenceIndex
from ..trace.tools import TraceYasaToolbox
from .constants import (
    RECON_MAX_ROUNDS,
    REQUEST_TIMEOUT_SECONDS,
)
from .inputs import ReconInputs, load_inputs
from .model import (
    ReconBudgetError,
    ReconConfigurationError,
    ReconModelError,
    build_model,
    load_prompt,
    model_name,
    parse_json_object,
)
from .result import validate_payload


@dataclass
class ReconExecution:
    repository: Path
    model: Any
    settings: Any
    scope_files: list[str]
    revision: str
    task_budget: AuditTaskBudget
    usage: Any | None = None
    store: ToolResultStore | None = None
    mcp_session: Any | None = None
    cache: ReadCache | None = None
    tool_receipts: list[dict[str, Any]] = field(default_factory=list)
    model_semaphore: Any | None = None

    def source_toolbox(self) -> SourceToolbox:
        return SourceToolbox(
            self.repository,
            allowed_paths=self.scope_files,
            task_id="recon",
            max_output_chars=12000,
            cache=self.cache,
        )

    def yasa_toolbox(self) -> TraceYasaToolbox | None:
        if self.mcp_session is None:
            return None
        return TraceYasaToolbox(
            self.mcp_session,
            self.repository,
            max_output_chars=12000,
            budget=self.task_budget,
        )

    def tools(self) -> tuple[list[Any], list[dict[str, Any]]]:
        source = self.source_toolbox()
        source.receipts = self.tool_receipts
        tools = [
            tool for tool in source.langchain_tools()
            if getattr(tool, "name", "") != "save_note"
        ]
        yasa = self.yasa_toolbox()
        if yasa is not None:
            yasa.receipts = self.tool_receipts
            tools.extend(yasa.langchain_tools())
        if _commit_id(self.revision):
            from ...init.security_history.git_tools import GitToolbox

            git = GitToolbox(self.repository, captured_head=self.revision)
            tools.extend(git.langchain_tools())
        return tools, self.tool_receipts

    async def run_json_agent(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        tools: list[Any],
        max_rounds: int,
        stage: str,
        task_id: str,
    ) -> dict[str, Any]:
        counter = TokenCounter(self.settings.model, self.settings.agent_token_safety)
        context = ContextManager(
            counter,
            max_tokens=self.settings.agent_context_tokens,
            trigger=self.settings.agent_compaction_trigger,
            keep_recent_results=self.settings.agent_keep_recent_results,
        )
        try:
            result = await run_tool_loop_async(
                self.model,
                system_prompt,
                user_prompt,
                tools,
                budget=SharedBudgetAdapter(self.task_budget),
                usage=self.usage,
                stage=stage,
                task_id=task_id,
                max_rounds=max_rounds,
                counter=counter,
                context=context,
                retry=RetryPolicy(
                    attempts=self.settings.agent_model_retries,
                    tool_attempts=self.settings.agent_tool_retries,
                ),
                json_expected=True,
                json_repair_attempts=1,
                max_result_tokens=self.settings.agent_tool_result_tokens,
                request_timeout=REQUEST_TIMEOUT_SECONDS,
                parallel_tools=True,
                finalize_on_exhaustion=False,
                tool_store=self.store,
                model_semaphore=self.model_semaphore,
            )
        except BudgetStop as exc:
            raise ReconBudgetError(f"{stage} budget exhausted: {exc.reason}") from exc
        except Exception as exc:
            raise ReconModelError(f"{stage} failed: {exc}") from exc
        return parse_json_object(result.content, f"{stage}:{task_id}")


async def run_recon_stage(
    state: Mapping[str, Any],
    context: RunContext,
) -> dict[str, Any]:
    paths = paths_from_state(state)
    paths.root.mkdir(parents=True, exist_ok=True)
    inputs = load_inputs(state, paths)
    tasks = _merge_tasks(state.get("tasks") or [], inputs.tasks)
    scope_files = [str(path) for path in inputs.scope.get("files", []) if isinstance(path, str)]
    business_tasks = [
        task for task in tasks
        if task.get("entry_ids") or task.get("patch_ids") or task.get("paths")
    ]
    if not business_tasks:
        if _reusable(inputs.existing):
            return _existing_result(state, inputs, paths, tasks, inputs.existing)
        return _empty_result(state, inputs, paths, tasks, scope_files)

    repository = Path(str(state.get("repository") or inputs.audit.get("repo") or ""))
    revision = current_revision(repository)
    prepare_revision = _prepare_revision(state, paths)
    if (
        prepare_revision
        and prepare_revision != "working-tree"
        and prepare_revision != revision
    ):
        raise ReconConfigurationError(
            "source revision changed since prepare; start a new audit run"
        )

    existing = inputs.existing
    if _reusable(existing):
        return _existing_result(state, inputs, paths, tasks, existing)

    audit_budget = context.audit_budget or AuditBudget.create(context.settings.audit_timeout)
    if audit_budget.expired():
        raise ReconBudgetError("audit budget exhausted before business recon")
    model = build_model(context)
    task_budget = AuditTaskBudget(
        deadline=audit_budget.deadline,
        max_model_calls=max(1, int(context.settings.agent_hard_task_cap)),
    )
    evidence = EvidenceIndex(repository, scope_files)
    store = ToolResultStore(paths.root / "tool-results")
    cache = ReadCache()

    async with open_yasa_mcp(context.settings, repository) as session:
        execution = ReconExecution(
            repository=repository,
            model=model,
            settings=context.settings,
            scope_files=scope_files,
            revision=revision,
            task_budget=task_budget,
            usage=context.usage,
            store=store,
            mcp_session=session,
            cache=cache,
            model_semaphore=asyncio.Semaphore(
                max(1, int(context.settings.audit_model_concurrency))
            ),
        )
        tools, _ = execution.tools()
        payload = await execution.run_json_agent(
            system_prompt=load_prompt(),
            user_prompt=json.dumps(inputs.seed(), ensure_ascii=False, indent=2),
            tools=tools,
            max_rounds=RECON_MAX_ROUNDS,
            stage="audit.recon",
            task_id="recon",
        )

    validated = validate_payload(
        payload,
        tasks=tasks,
        entries=inputs.entries,
        patches=inputs.patches,
        scope_files=scope_files,
        evidence_index=evidence,
        traces=inputs.traces,
    )
    if not (
        validated["constraints"]
        or validated["operations"]
        or validated["investigations"]
    ):
        raise ReconModelError("recon produced no business records")

    merged = _merge_business(existing, validated)
    merged_tasks = _merge_logic_tasks(tasks, validated["logic_tasks"])
    status = _status(merged, merged_tasks)
    model_summary = {
        "status": "used",
        "model": model_name(model),
        **task_budget.snapshot(),
    }
    business = _business(
        state,
        inputs,
        merged,
        scope_files=scope_files,
        status=status,
        model=model_summary,
    )
    summary = _summary(
        inputs,
        merged,
        merged_tasks,
        status=status,
        model=model_summary,
        stop_reason="recon_complete" if status == "complete" else "recon_partial",
    )
    updated = {
        **dict(state),
        "tasks": merged_tasks,
        "recon": summary,
        "framework": {
            **(dict(state.get("framework") or {})),
            "recon_done": True,
        },
        "gaps": list(summary["gaps"]),
    }
    write_recon_checkpoint(updated, business)
    return {
        "status": "running",
        "stop_reason": summary["stop_reason"],
        "next_action": "trace",
        "tasks": merged_tasks,
        "recon": summary,
        "gaps": updated["gaps"],
        "framework": updated["framework"],
    }


def _empty_result(
    state: Mapping[str, Any],
    inputs: ReconInputs,
    paths: AuditPaths,
    tasks: list[dict[str, Any]],
    scope_files: list[str],
) -> dict[str, Any]:
    stop_reason = str(state.get("stop_reason") or "no_business_tasks")
    summary = _summary(
        inputs,
        {
            "constraints": [],
            "operations": [],
            "investigations": [],
            "gaps": [],
            "warnings": list(inputs.warnings),
            "limitations": [*inputs.limitations, "no business tasks in scope"],
        },
        tasks,
        status="complete",
        model={"status": "not_run", "model": "", "calls": 0},
        stop_reason=stop_reason,
    )
    business = _business(
        state,
        inputs,
        {
            "constraints": [],
            "operations": [],
            "investigations": [],
            "gaps": [],
            "warnings": list(inputs.warnings),
            "limitations": [*inputs.limitations, "no business tasks in scope"],
        },
        scope_files=scope_files,
        status="complete",
        model={"status": "not_run", "model": "", "calls": 0},
    )
    updated = {
        **dict(state),
        "tasks": tasks,
        "recon": summary,
        "framework": {
            **(dict(state.get("framework") or {})),
            "recon_done": True,
        },
        "gaps": [],
    }
    write_recon_checkpoint(updated, business)
    return {
        "status": "running",
        "stop_reason": summary["stop_reason"],
        "next_action": "trace",
        "tasks": tasks,
        "recon": summary,
        "gaps": updated["gaps"],
        "framework": updated["framework"],
    }


def _existing_result(
    state: Mapping[str, Any],
    inputs: ReconInputs,
    paths: AuditPaths,
    tasks: list[dict[str, Any]],
    business: dict[str, Any],
) -> dict[str, Any]:
    validated = {
        "constraints": _records(business.get("constraints")),
        "operations": _records(business.get("operations")),
        "investigations": _records(business.get("investigations")),
        "gaps": [str(item) for item in business.get("gaps", []) if str(item)]
        if isinstance(business.get("gaps"), list)
        else [],
        "warnings": [str(item) for item in business.get("warnings", []) if str(item)]
        if isinstance(business.get("warnings"), list)
        else [],
        "limitations": [str(item) for item in business.get("limitations", []) if str(item)]
        if isinstance(business.get("limitations"), list)
        else [],
    }
    merged_tasks = _merge_logic_tasks(tasks, [])
    summary = _summary(
        inputs,
        validated,
        merged_tasks,
        status="complete",
        model={"status": "existing", "model": "", "calls": 0},
        stop_reason="recon_complete",
    )
    updated = {
        **dict(state),
        "tasks": merged_tasks,
        "recon": summary,
        "framework": {
            **(dict(state.get("framework") or {})),
            "recon_done": True,
        },
        "gaps": [],
    }
    write_recon_checkpoint(updated, {**dict(business), "status": summary["status"]})
    return {
        "status": "running",
        "stop_reason": summary["stop_reason"],
        "next_action": "trace",
        "tasks": merged_tasks,
        "recon": summary,
        "gaps": updated["gaps"],
        "framework": updated["framework"],
    }


def _business(
    state: Mapping[str, Any],
    inputs: ReconInputs,
    validated: Mapping[str, Any],
    *,
    scope_files: list[str],
    status: str,
    model: Mapping[str, Any],
) -> dict[str, Any]:
    scope = {
        "files": list(scope_files),
        "entry_ids": [str(item.get("id", "")) for item in inputs.entries if item.get("id")],
        "patch_ids": [str(item.get("id", "")) for item in inputs.patches if item.get("id")],
        "limitations": list(inputs.limitations),
    }
    return {
        "run_id": str(state.get("run_id") or inputs.audit.get("run_id") or ""),
        "repo": str(state.get("repository") or inputs.audit.get("repo") or ""),
        "mode": inputs.mode,
        "status": status,
        "scope": scope,
        "constraints": list(validated.get("constraints", [])),
        "operations": list(validated.get("operations", [])),
        "investigations": list(validated.get("investigations", [])),
        "gaps": list(validated.get("gaps", [])),
        "warnings": list(dict.fromkeys([*inputs.warnings, *validated.get("warnings", [])])),
        "limitations": list(
            dict.fromkeys([*inputs.limitations, *validated.get("limitations", [])])
        ),
        "model": dict(model),
        "written_at": utc_now(),
    }


def _summary(
    inputs: ReconInputs,
    validated: Mapping[str, Any],
    tasks: list[dict[str, Any]],
    *,
    status: str,
    model: Mapping[str, Any],
    stop_reason: str,
) -> dict[str, Any]:
    logic_tasks = [task for task in tasks if task.get("kind") == "logic"]
    gaps = [str(item) for item in validated.get("gaps", []) if str(item)]
    if status == "complete" and (
        gaps
        or logic_tasks
        or any(
            str(item.get("outcome", "")) in {"unknown", "deferred"}
            for item in validated.get("investigations", [])
            if isinstance(item, dict)
        )
    ):
        status = "partial"
        stop_reason = "recon_partial"
    return {
        "status": status,
        "mode": inputs.mode,
        "constraint_count": len(validated.get("constraints", [])),
        "operation_count": len(validated.get("operations", [])),
        "investigation_count": len(validated.get("investigations", [])),
        "logic_task_count": len(logic_tasks),
        "trace_count": len(inputs.traces),
        "scope_file_count": len(inputs.scope.get("files", [])),
        "source_revision": inputs.source_revision,
        "model": dict(model),
        "gaps": gaps,
        "warnings": list(dict.fromkeys([*inputs.warnings, *validated.get("warnings", [])])),
        "limitations": list(
            dict.fromkeys([*inputs.limitations, *validated.get("limitations", [])])
        ),
        "stop_reason": stop_reason,
        "written_at": utc_now(),
    }


def _status(validated: Mapping[str, Any], tasks: list[dict[str, Any]]) -> str:
    if validated.get("gaps") or any(task.get("kind") == "logic" for task in tasks):
        return "partial"
    if any(
        str(item.get("outcome", "")) in {"unknown", "deferred"}
        for item in validated.get("investigations", [])
        if isinstance(item, dict)
    ):
        return "partial"
    return "complete"


def _merge_business(
    existing: Mapping[str, Any],
    validated: Mapping[str, Any],
) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for key in ("constraints", "operations", "investigations"):
        records = _merge_records(existing.get(key), validated.get(key))
        merged[key] = records
    for key in ("gaps", "warnings", "limitations"):
        existing_values = (
            [str(item) for item in existing.get(key, []) if str(item)]
            if isinstance(existing.get(key), list)
            else []
        )
        merged[key] = list(dict.fromkeys([*existing_values, *validated.get(key, [])]))
    return merged


def _merge_records(existing: Any, incoming: Any) -> list[dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for source in (existing, incoming):
        for item in _records(source):
            result[str(item.get("id", ""))] = item
    return list(result.values())


def _records(raw: Any) -> list[dict[str, Any]]:
    return [dict(item) for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []


def _merge_tasks(existing: Any, updates: Any) -> list[dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for source in (existing, updates):
        if not isinstance(source, list):
            continue
        for item in source:
            if isinstance(item, dict) and item.get("id"):
                result[str(item["id"])] = dict(item)
    return list(result.values())


def _merge_logic_tasks(
    tasks: list[dict[str, Any]],
    generated: Any,
) -> list[dict[str, Any]]:
    result = {str(task.get("id", "")): task for task in tasks if task.get("id")}
    for item in generated if isinstance(generated, list) else []:
        if not isinstance(item, dict) or not item.get("id"):
            continue
        task_id = str(item["id"])
        result.setdefault(task_id, dict(item))
    return list(result.values())


def _reusable(business: Mapping[str, Any]) -> bool:
    return (
        str(business.get("status", "")) == "complete"
        and all(
            isinstance(business.get(key), list)
            for key in ("constraints", "operations", "investigations")
        )
    )


def _prepare_revision(state: Mapping[str, Any], paths: AuditPaths) -> str:
    prepare = state.get("prepare") if isinstance(state.get("prepare"), dict) else {}
    value = str(prepare.get("source_revision", ""))
    if value:
        return value
    if paths.prepare_file.is_file():
        try:
            value = load_json(paths.prepare_file)
        except (OSError, ValueError):
            return ""
        return str(value.get("source_revision", "")) if isinstance(value, dict) else ""
    return ""


def _commit_id(value: str) -> bool:
    return len(value) == 40 and all(char in "0123456789abcdef" for char in value.lower())
