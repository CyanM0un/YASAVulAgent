"""Trace stage harness: model, tools, batches, and durable merging."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

from langchain_core.tools import StructuredTool

from ....agent.artifacts import ToolResultStore
from ....agent.budget import SharedBudgetAdapter
from ....agent.context import ContextManager
from ....agent.retry import RetryPolicy
from ....agent.runtime import run_tool_loop_async
from ....agent.tokens import TokenCounter
from ....storage import utc_now
from ....workflow.state import RunContext
from ...discover.screen.mcp import open_yasa_mcp
from ...discover.screen.tools import ReadCache, SourceToolbox
from ..budget import AuditBudget, AuditTaskBudget
from ..categories import CategoryManifest, load_category_manifest
from ..framework import MAX_NODE_VISITS
from ..prepare.inventory import current_revision
from ..storage import (
    AuditPaths,
    load_json,
    paths_from_state,
    read_business_logic,
    write_trace_checkpoint,
)
from .constants import REQUEST_TIMEOUT_SECONDS
from .model import TraceConfigurationError, TraceModelError, build_model, model_name, parse_json_object
from .registry import SpecialistRegistry, SpecialistSpec, load_specialist_registry
from .rejections import RejectionIndex
from .result import EvidenceIndex
from .summaries import SummaryIndex, build_index
from .tools import TraceYasaToolbox


TraceTaskBudget = AuditTaskBudget


@dataclass
class TraceExecution:
    repository: Path
    audit_dir: Path
    model: Any
    settings: Any
    registry: SpecialistRegistry
    manifest: CategoryManifest
    category_details: dict[str, Any]
    scope_files: list[str]
    revision: str
    run_id: str
    audit_state: dict[str, Any]
    entries_by_id: dict[str, dict[str, Any]]
    patches_by_id: dict[str, dict[str, Any]]
    evidence: EvidenceIndex
    summary_index: SummaryIndex
    audit_budget: AuditBudget
    task_budget: TraceTaskBudget
    usage: Any | None = None
    store: ToolResultStore | None = None
    mcp_session: Any | None = None
    cache: ReadCache | None = None
    tool_receipts: list[dict[str, Any]] = field(default_factory=list)
    business: dict[str, Any] = field(default_factory=dict)
    model_semaphore: Any | None = None
    repair_by_task: dict[str, dict[str, Any]] = field(default_factory=dict)
    rejections: RejectionIndex = field(default_factory=RejectionIndex)

    @property
    def category_ids(self) -> set[str]:
        return {category.id for category in self.manifest.categories}

    def source_toolbox(self) -> SourceToolbox:
        return SourceToolbox(
            self.repository,
            allowed_paths=self.scope_files,
            task_id="",
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

    def tools_for(self, spec: SpecialistSpec) -> tuple[list[Any], list[dict[str, Any]]]:
        receipts: list[dict[str, Any]] = []
        source = self.source_toolbox()
        source.receipts = receipts
        tools = [
            tool for tool in source.langchain_tools()
            if getattr(tool, "name", "") != "save_note"
        ]
        if spec.tools in {"source_yasa", "source_yasa_git"}:
            yasa = self.yasa_toolbox()
            if yasa is not None:
                yasa.receipts = receipts
                tools.extend(yasa.langchain_tools())
        if spec.tools == "source_yasa_git" and _commit_id(self.revision):
            from ...init.security_history.git_tools import GitToolbox

            git = GitToolbox(self.repository, captured_head=self.revision)
            tools.extend(git.langchain_tools())
        return tools, receipts

    def tools_for_task(self, task: Mapping[str, Any]) -> tuple[list[Any], list[dict[str, Any]]]:
        receipts: list[dict[str, Any]] = []
        source = self.source_toolbox()
        source.receipts = receipts
        tools = [
            tool for tool in source.langchain_tools()
            if getattr(tool, "name", "") != "save_note"
        ]
        yasa = self.yasa_toolbox()
        if yasa is not None:
            yasa.receipts = receipts
            tools.extend(yasa.langchain_tools())
        if str(task.get("kind", "")) == "patch" and _commit_id(self.revision):
            from ...init.security_history.git_tools import GitToolbox

            git = GitToolbox(self.repository, captured_head=self.revision)
            tools.extend(git.langchain_tools())
        if self.category_details:
            tools.append(self._category_details_tool(receipts))
        return tools, receipts

    def _category_details_tool(self, receipts: list[dict[str, Any]]) -> StructuredTool:
        details_map = self._raw_category_details()
        titles = {category.id: category.title for category in self.manifest.categories}

        def get_category_details(
            categories: list[str] | None = None,
            category: str = "",
        ) -> dict[str, Any]:
            requested: list[str] = []
            if isinstance(category, str) and category.strip():
                requested.append(category.strip())
            if isinstance(categories, list):
                for item in categories:
                    value = str(item or "").strip()
                    if value and value not in requested:
                        requested.append(value)
            if not requested:
                return {
                    "error": "specify at least one category ID",
                    "available_categories": sorted(details_map),
                }
            found: dict[str, Any] = {}
            unknown: list[str] = []
            for item in requested:
                detail = details_map.get(item)
                if detail is None:
                    unknown.append(item)
                else:
                    found[item] = {
                        "title": titles.get(item, item),
                        **(detail if isinstance(detail, dict) else {}),
                    }
            receipts.append(
                {
                    "tool": "get_category_details",
                    "categories": requested,
                    "status": "ok" if found else "error",
                }
            )
            payload: dict[str, Any] = {"categories": found}
            if unknown:
                payload["unknown_categories"] = unknown
                payload["available_categories"] = sorted(details_map)
            return payload

        return StructuredTool.from_function(
            func=get_category_details,
            name="get_category_details",
            description=(
                "Fetch the full CWE IDs and check items for one or more audit category IDs "
                "on demand when you need details beyond category_catalog."
            ),
        )

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
                finalize_on_exhaustion=True,
                tool_store=self.store,
                model_semaphore=self.model_semaphore,
            )
        except TraceModelError:
            raise
        except Exception as exc:
            raise TraceModelError(f"{stage} failed: {exc}") from exc
        return parse_json_object(result.content, f"{stage}:{task_id}")

    def repair_for(self, task: Mapping[str, Any]) -> dict[str, Any]:
        return dict(self.repair_by_task.get(str(task.get("id", ""))) or {})

    def category_checks_for(self, task: Mapping[str, Any]) -> list[dict[str, Any]]:
        task_id = str(task.get("id", ""))
        return [
            dict(item)
            for item in self.audit_state.get("category_checks", [])
            if isinstance(item, dict) and str(item.get("task_id", "")) == task_id
        ]

    def mechanism_checks_for(self, task: Mapping[str, Any]) -> list[dict[str, Any]]:
        task_id = str(task.get("id", ""))
        return [
            dict(item)
            for item in self.audit_state.get("mechanism_checks", [])
            if isinstance(item, dict) and str(item.get("task_id", "")) == task_id
        ]

    def _raw_category_details(self) -> dict[str, Any]:
        details = self.category_details
        if isinstance(details.get("categories"), dict):
            return details["categories"]
        return details if isinstance(details, dict) else {}

    def category_catalog_for(self, task: Mapping[str, Any]) -> list[dict[str, Any]]:
        titles = {category.id: category.title for category in self.manifest.categories}
        details = self._raw_category_details()
        catalog: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in self.category_checks_for(task):
            category_id = str(item.get("category", "")).strip()
            if not category_id or category_id in seen:
                continue
            seen.add(category_id)
            detail = details.get(category_id)
            cwe_ids = detail.get("cwe_ids", []) if isinstance(detail, dict) else []
            catalog.append(
                {
                    "id": category_id,
                    "title": titles.get(category_id, category_id),
                    "cwe_count": len(cwe_ids) if isinstance(cwe_ids, list) else 0,
                }
            )
        return catalog

    def category_details_for(
        self,
        task: Mapping[str, Any],
        *,
        only: Iterable[str] | None = None,
    ) -> dict[str, Any]:
        ids = {
            str(item.get("category", ""))
            for item in self.category_checks_for(task)
        }
        if only is not None:
            requested = {str(item).strip() for item in only if str(item).strip()}
            ids &= requested
        details = self._raw_category_details()
        return {
            key: value
            for key, value in details.items()
            if key in ids
        }

    def business_view(self, task: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(self.business, dict) or not self.business:
            return {}
        if str(task.get("kind", "")) == "logic":
            refs = task.get("business_refs")
            refs = refs if isinstance(refs, dict) else {}
            constraints = {
                str(item.get("id", "")): item
                for item in self.business.get("constraints", [])
                if isinstance(item, dict)
            }
            operations = {
                str(item.get("id", "")): item
                for item in self.business.get("operations", [])
                if isinstance(item, dict)
            }
            investigations = {
                str(item.get("id", "")): item
                for item in self.business.get("investigations", [])
                if isinstance(item, dict)
            }
            return {
                "question": str(task.get("question", "")),
                "constraints": [
                    constraints[str(item)]
                    for item in refs.get("constraint_ids", [])
                    if str(item) in constraints
                ],
                "operations": [
                    operations[str(item)]
                    for item in refs.get("operation_ids", [])
                    if str(item) in operations
                ],
                "investigations": [
                    investigations[str(item)]
                    for item in refs.get("investigation_ids", [])
                    if str(item) in investigations
                ],
            }
        return _compact_business_for_task(self.business, task)

    def entry_view(self, task: Mapping[str, Any]) -> dict[str, Any]:
        values = [
            self.entries_by_id.get(str(entry_id), {})
            for entry_id in task.get("entry_ids", [])
        ]
        values = [value for value in values if isinstance(value, dict)]
        return values[0] if len(values) == 1 else {"entries": values}

    def patch_view(self, task: Mapping[str, Any]) -> dict[str, Any]:
        values = [
            self.patches_by_id.get(str(patch_id), {})
            for patch_id in task.get("patch_ids", [])
        ]
        values = [value for value in values if isinstance(value, dict)]
        return values[0] if len(values) == 1 else {"patches": values}


async def run_trace_stage(state: Mapping[str, Any], context: RunContext) -> dict[str, Any]:
    paths = paths_from_state(state)
    paths.root.mkdir(parents=True, exist_ok=True)
    paths.trace_dir.mkdir(parents=True, exist_ok=True)
    audit = _load_audit(paths)
    tasks = [dict(item) for item in audit.get("tasks", []) if isinstance(item, dict)]
    if not tasks:
        tasks = [
            dict(item)
            for item in state.get("tasks", [])
            if isinstance(item, dict)
        ]
    if not tasks:
        return _empty_result(state, audit)
    all_tasks = _merge_tasks(state.get("tasks") or [], tasks)
    pending = _prioritize_pending_tasks(
        [
            task for task in all_tasks
            if str(task.get("status", "planned")) in {
                "planned", "deferred", "partial", "failed"
            }
        ]
    )
    if not pending:
        return _completed_result(state, audit, all_tasks)
    audit_budget = context.audit_budget or AuditBudget.create(context.settings.audit_timeout)
    if audit_budget.expired():
        for task in pending:
            _set_task_status(all_tasks, str(task.get("id", "")), "deferred")
        return _deferred_result(state, audit, all_tasks)

    runnable = any(
        task.get("entry_ids") or task.get("patch_ids") or task.get("paths")
        for task in tasks
    )
    if not runnable:
        return _empty_result(state, audit)
    manifest = load_category_manifest()
    registry = load_specialist_registry(manifest)
    model = build_model(context)
    repository = Path(str(state.get("repository") or audit.get("repo") or ""))
    revision = current_revision(repository)
    prepare_revision = str((state.get("prepare") or {}).get("source_revision", ""))
    if not prepare_revision and paths.prepare_file.is_file():
        try:
            prepare_revision = str(
                load_json(paths.prepare_file).get("source_revision", "")
            )
        except (OSError, ValueError):
            prepare_revision = ""
    if prepare_revision and prepare_revision != "working-tree" and prepare_revision != revision:
        raise TraceConfigurationError(
            "source revision changed since prepare; start a new audit run"
        )
    scope = state.get("scope") if isinstance(state.get("scope"), dict) else {}
    if not scope and isinstance(audit.get("scope"), dict):
        scope = audit["scope"]
    scope_files = [str(path) for path in scope.get("files", []) if isinstance(path, str)]
    run_id = str(state.get("run_id") or audit.get("run_id") or "")
    entries = [
        dict(item)
        for item in (audit.get("entries") or state.get("entries") or [])
        if isinstance(item, dict) and item.get("id")
    ]
    patches = [
        dict(item)
        for item in (audit.get("patches") or state.get("patches") or [])
        if isinstance(item, dict) and item.get("id")
    ]
    entries_by_id = {str(item["id"]): item for item in entries}
    patches_by_id = {str(item["id"]): item for item in patches}
    evidence = EvidenceIndex(repository, scope_files)
    summary_index = build_index(
        audit.get("summaries") or state.get("summaries"),
        repository=repository,
        revision=revision,
    )
    store = ToolResultStore(paths.root / "tool-results")
    cache = ReadCache()
    details = _load_category_details()
    traces = [
        dict(item)
        for item in (audit.get("traces") or state.get("traces") or [])
        if isinstance(item, dict)
    ]
    summaries = summary_index.all()
    business = read_business_logic(paths)
    category_checks = [
        dict(item)
        for item in (
            audit.get("category_checks") or state.get("category_checks") or []
        )
        if isinstance(item, dict)
    ]
    mechanism_checks = [
        dict(item)
        for item in (
            audit.get("mechanism_checks") or state.get("mechanism_checks") or []
        )
        if isinstance(item, dict)
    ]
    deferred: list[str] = []
    trace_gaps: list[str] = []

    gate = audit.get("gate") if isinstance(audit.get("gate"), dict) else state.get("gate")
    repair_by_task = _repair_contexts(
        gate if isinstance(gate, dict) else {},
        traces,
    )
    rejections = RejectionIndex.from_audit(
        [
            dict(item)
            for item in (audit.get("findings") or state.get("findings") or [])
            if isinstance(item, dict)
        ],
        [
            dict(item)
            for item in (audit.get("reviews") or state.get("reviews") or [])
            if isinstance(item, dict)
        ],
        revision=revision,
    )
    model_semaphore = asyncio.Semaphore(
        max(1, int(context.settings.audit_model_concurrency))
    )
    verify_reserve = int(getattr(context.settings, "audit_verify_reserve", 0) or 0)
    trace_deadline = audit_budget.trace_deadline(verify_reserve)
    wave_size = int(getattr(context.settings, "audit_trace_wave_size", 0) or 0)
    trace_visits = int(((state.get("framework") or {}).get("visits") or {}).get("trace", 0) or 0)
    wave_limited = wave_size > 0 and trace_visits < MAX_NODE_VISITS - 2 and len(pending) > wave_size
    wave_pending = pending[:wave_size] if wave_limited else pending
    async with open_yasa_mcp(context.settings, repository) as session:
        for batch in _batches(wave_pending, max(1, int(context.settings.audit_max_agents))):
            if audit_budget.trace_expired(verify_reserve):
                for task in batch:
                    deferred.append(str(task.get("id", "")))
                    _set_task_status(all_tasks, str(task.get("id", "")), "deferred")
                continue
            batch_index = SummaryIndex(summaries)
            batch_state = {
                **audit,
                "tasks": all_tasks,
                "category_checks": category_checks,
                "mechanism_checks": mechanism_checks,
            }
            runs = []
            for task in batch:
                budget = TraceTaskBudget(
                    deadline=trace_deadline,
                    max_model_calls=max(1, int(context.settings.agent_hard_task_cap)),
                )
                runs.append(
                    _run_one(task, {
                        "repository": repository,
                        "audit_dir": paths.root,
                        "model": model,
                        "settings": context.settings,
                        "registry": registry,
                        "manifest": manifest,
                        "category_details": details,
                        "scope_files": scope_files,
                        "revision": revision,
                        "run_id": run_id,
                        "audit_state": batch_state,
                        "entries_by_id": entries_by_id,
                        "patches_by_id": patches_by_id,
                        "evidence": evidence,
                        "summary_index": batch_index,
                        "audit_budget": audit_budget,
                        "task_budget": budget,
                        "usage": context.usage,
                        "store": store,
                        "mcp_session": session,
                        "cache": cache,
                        "business": business,
                        "paths": paths,
                        "model_semaphore": model_semaphore,
                        "repair_by_task": repair_by_task,
                        "rejections": rejections,
                    })
                )
            results = await asyncio.gather(*runs, return_exceptions=True)
            for task, outcome in zip(batch, results):
                if isinstance(outcome, Exception):
                    deferred.append(str(task.get("id", "")))
                    _set_task_status(all_tasks, str(task.get("id", "")), "deferred")
                    trace_gaps.append(f"{task.get('id', '')}: {outcome}")
                    continue
                _merge_outcome(
                    all_tasks,
                    category_checks,
                    mechanism_checks,
                    traces,
                    summaries,
                    task,
                    outcome,
                )
                if str(outcome.get("status")) != "complete":
                    trace_gaps.extend(str(item) for item in outcome.get("gaps", []))
            merged = {
                **dict(state),
                "tasks": all_tasks,
                "category_checks": category_checks,
                "mechanism_checks": mechanism_checks,
                "traces": traces,
                "summaries": summaries,
                "trace": _stage_summary(all_tasks, traces, deferred, trace_gaps),
                "framework": {
                    **dict(state.get("framework") or {}),
                    "trace_done": True,
                },
            }
            write_trace_checkpoint(merged)

    has_remaining_pending = any(
        str(item.get("status", "planned")) in {"planned", "deferred", "partial", "failed"}
        for item in all_tasks
    )
    status = "complete"
    if (
        deferred
        or has_remaining_pending
        or any(str(item.get("status")) != "complete" for item in traces)
    ):
        status = "partial"
    if status == "complete":
        stop_reason = "trace_complete"
    elif wave_limited and not deferred:
        stop_reason = "trace_wave_complete"
    else:
        stop_reason = "trace_partial"
    trace_summary = _stage_summary(all_tasks, traces, deferred, trace_gaps)
    trace_summary["status"] = status
    trace_summary["model"] = model_name(model)
    trace_summary["usage"] = _usage_snapshot(context.usage)
    write_trace_checkpoint(
        {
            **dict(state),
            "tasks": all_tasks,
            "category_checks": category_checks,
            "mechanism_checks": mechanism_checks,
            "traces": traces,
            "summaries": summaries,
            "trace": trace_summary,
            "framework": {
                **dict(state.get("framework") or {}),
                "trace_done": True,
            },
        }
    )
    return {
        "status": status,
        "stop_reason": stop_reason,
        "next_action": "verify",
        "tasks": all_tasks,
        "category_checks": category_checks,
        "mechanism_checks": mechanism_checks,
        "trace": trace_summary,
        "traces": traces,
        "summaries": summaries,
        "framework": {
            **dict(state.get("framework") or {}),
            "trace_done": True,
        },
        "gaps": list(trace_gaps),
    }


def _repair_contexts(
    gate: Mapping[str, Any],
    traces: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Translate blocking trace debts into bounded per-task repair context."""
    contexts: dict[str, dict[str, Any]] = {}
    for debt in gate.get("debts", []) or []:
        if not isinstance(debt, dict):
            continue
        if not bool(debt.get("blocking", True)):
            continue
        if str(debt.get("action", "")) != "trace":
            continue
        target = str(debt.get("target_id", "")).strip()
        if not target:
            continue
        context = contexts.setdefault(
            target,
            {"debt_ids": [], "debts": [], "prior_trace_id": "", "prior_gaps": [], "truncated": False},
        )
        if len(context["debts"]) >= 12:
            context["truncated"] = True
            continue
        debt_id = str(debt.get("id", ""))
        if debt_id:
            context["debt_ids"].append(debt_id)
        context["debts"].append(
            {
                "id": debt_id,
                "kind": str(debt.get("kind", "")),
                "reason": str(debt.get("reason", ""))[:300],
                "action": "trace",
                "paths": [str(path) for path in (debt.get("paths") or [])[:6]],
            }
        )
    prior_by_task: dict[str, dict[str, Any]] = {}
    for trace in traces:
        if isinstance(trace, dict) and trace.get("task_id"):
            prior_by_task[str(trace["task_id"])] = trace
    for task_id, context in contexts.items():
        trace = prior_by_task.get(task_id) or {}
        context["prior_trace_id"] = str(trace.get("id", ""))
        context["prior_gaps"] = [
            str(item)[:300] for item in (trace.get("gaps") or [])[:8]
        ]
    return contexts


async def _run_one(task: Mapping[str, Any], values: dict[str, Any]) -> dict[str, Any]:
    from .graph import run_trace_task

    paths = values.pop("paths")
    execution = TraceExecution(
        repository=values["repository"],
        audit_dir=values["audit_dir"],
        model=values["model"],
        settings=values["settings"],
        registry=values["registry"],
        manifest=values["manifest"],
        category_details=values["category_details"],
        scope_files=values["scope_files"],
        revision=values["revision"],
        run_id=values["run_id"],
        audit_state=values["audit_state"],
        entries_by_id=values["entries_by_id"],
        patches_by_id=values["patches_by_id"],
        evidence=values["evidence"],
        summary_index=values["summary_index"],
        audit_budget=values["audit_budget"],
        task_budget=values["task_budget"],
        usage=values["usage"],
        store=values["store"],
        mcp_session=values["mcp_session"],
        cache=values["cache"],
        business=values["business"],
        model_semaphore=values.get("model_semaphore"),
        repair_by_task=values.get("repair_by_task") or {},
        rejections=values.get("rejections") or RejectionIndex(),
    )
    return await run_trace_task(task, execution, paths)


def _merge_outcome(
    tasks: list[dict[str, Any]],
    category_checks: list[dict[str, Any]],
    mechanism_checks: list[dict[str, Any]],
    traces: list[dict[str, Any]],
    summaries: list[dict[str, Any]],
    task: dict[str, Any],
    outcome: dict[str, Any],
) -> None:
    task_id = str(task.get("id", ""))
    for item in tasks:
        if str(item.get("id", "")) == task_id:
            item["status"] = str(outcome.get("status", "failed"))
            break
    replacements = {
        str(item.get("id", "")): item
        for item in outcome.get("category_checks", [])
        if isinstance(item, dict)
    }
    for index, item in enumerate(category_checks):
        if str(item.get("id", "")) in replacements:
            category_checks[index] = replacements[str(item["id"])]
    known_categories = {str(item.get("id", "")) for item in category_checks}
    category_checks.extend(
        item for key, item in replacements.items() if key not in known_categories
    )
    replacements = {
        str(item.get("id", "")): item
        for item in outcome.get("mechanism_checks", [])
        if isinstance(item, dict)
    }
    for index, item in enumerate(mechanism_checks):
        if str(item.get("id", "")) in replacements:
            mechanism_checks[index] = replacements[str(item["id"])]
    known_mechanisms = {str(item.get("id", "")) for item in mechanism_checks}
    mechanism_checks.extend(
        item for key, item in replacements.items() if key not in known_mechanisms
    )
    traces[:] = [item for item in traces if str(item.get("id", "")) != str(outcome.get("trace", {}).get("id", ""))]
    if outcome.get("trace"):
        traces.append(dict(outcome["trace"]))
    summaries[:] = _merge_summaries(summaries, outcome.get("summaries", []))


def _merge_summaries(existing: list[dict[str, Any]], incoming: Any) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {str(item.get("id", "")): item for item in existing}
    if isinstance(incoming, list):
        for item in incoming:
            if isinstance(item, dict) and item.get("id"):
                merged[str(item["id"])] = item
    return list(merged.values())


def _stage_summary(
    tasks: list[dict[str, Any]],
    traces: list[dict[str, Any]],
    deferred: list[str],
    gaps: list[str],
) -> dict[str, Any]:
    return {
        "status": "partial",
        "task_count": len(tasks),
        "trace_count": len(traces),
        "complete_count": sum(1 for item in traces if item.get("status") == "complete"),
        "deferred_count": len(deferred),
        "flow_count": sum(int(item.get("flow_count", 0)) for item in traces),
        "complete_flow_count": sum(int(item.get("complete_flow_count", 0)) for item in traces),
        "partial_flow_count": sum(int(item.get("partial_flow_count", 0)) for item in traces),
        "reachable_flow_count": sum(int(item.get("reachable_flow_count", 0)) for item in traces),
        "summary_count": sum(int(item.get("summary_count", 0)) for item in traces),
        "gaps": list(dict.fromkeys(gaps)),
        "written_at": utc_now(),
    }


def _deferred_result(
    state: Mapping[str, Any],
    audit: Mapping[str, Any],
    tasks: list[dict[str, Any]],
) -> dict[str, Any]:
    traces = [dict(item) for item in audit.get("traces", []) if isinstance(item, dict)]
    deferred = [
        str(task.get("id", ""))
        for task in tasks
        if str(task.get("status", "")) == "deferred"
    ]
    summary = _stage_summary(tasks, traces, deferred, [])
    summary["status"] = "partial"
    write_trace_checkpoint(
        {
            **dict(state),
            "tasks": tasks,
            "trace": summary,
            "traces": traces,
            "summaries": list(audit.get("summaries", [])),
            "framework": {
                **dict(state.get("framework") or {}),
                "trace_done": True,
            },
        }
    )
    return {
        "status": "partial",
        "stop_reason": "audit_budget_exhausted",
        "next_action": "verify",
        "tasks": tasks,
        "category_checks": list(
            audit.get("category_checks") or state.get("category_checks") or []
        ),
        "mechanism_checks": list(
            audit.get("mechanism_checks") or state.get("mechanism_checks") or []
        ),
        "trace": summary,
        "traces": traces,
        "summaries": list(audit.get("summaries") or state.get("summaries") or []),
        "gaps": [],
        "framework": {**dict(state.get("framework") or {}), "trace_done": True},
    }


def _completed_result(
    state: Mapping[str, Any],
    audit: Mapping[str, Any],
    tasks: list[dict[str, Any]],
) -> dict[str, Any]:
    traces = [
        dict(item)
        for item in (audit.get("traces") or state.get("traces") or [])
        if isinstance(item, dict)
    ]
    status = "complete" if traces and all(
        str(item.get("status", "")) == "complete" for item in traces
    ) else "partial"
    summary = _stage_summary(tasks, traces, [], [])
    summary["status"] = status
    return {
        "status": status,
        "stop_reason": "trace_complete" if status == "complete" else "trace_partial",
        "next_action": "verify",
        "tasks": tasks,
        "category_checks": list(
            audit.get("category_checks") or state.get("category_checks") or []
        ),
        "mechanism_checks": list(
            audit.get("mechanism_checks") or state.get("mechanism_checks") or []
        ),
        "trace": summary,
        "traces": traces,
        "summaries": list(audit.get("summaries") or state.get("summaries") or []),
        "gaps": [],
        "framework": {**dict(state.get("framework") or {}), "trace_done": True},
    }


def _empty_result(state: Mapping[str, Any], audit: Mapping[str, Any]) -> dict[str, Any]:
    tasks = list(audit.get("tasks") or state.get("tasks") or [])
    traces = [
        dict(item)
        for item in (audit.get("traces") or state.get("traces") or [])
        if isinstance(item, dict)
    ]
    return {
        "status": "complete",
        "stop_reason": str(state.get("stop_reason") or "inputs_unavailable"),
        "next_action": "verify",
        "trace": {
            "status": "complete",
            "task_count": len(tasks),
            "trace_count": len(traces),
            "complete_count": sum(
                1 for item in traces if item.get("status") == "complete"
            ),
            "deferred_count": 0,
            "flow_count": sum(int(item.get("flow_count", 0)) for item in traces),
            "complete_flow_count": sum(
                int(item.get("complete_flow_count", 0)) for item in traces
            ),
            "partial_flow_count": sum(
                int(item.get("partial_flow_count", 0)) for item in traces
            ),
            "reachable_flow_count": sum(
                int(item.get("reachable_flow_count", 0)) for item in traces
            ),
            "summary_count": len(audit.get("summaries") or state.get("summaries") or []),
            "gaps": [],
            "written_at": utc_now(),
        },
        "tasks": tasks,
        "category_checks": list(
            audit.get("category_checks") or state.get("category_checks") or []
        ),
        "mechanism_checks": list(
            audit.get("mechanism_checks") or state.get("mechanism_checks") or []
        ),
        "traces": traces,
        "summaries": list(audit.get("summaries") or state.get("summaries") or []),
        "gaps": [],
        "framework": {**dict(state.get("framework") or {}), "trace_done": True},
    }


def _batches(tasks: list[dict[str, Any]], size: int) -> list[list[dict[str, Any]]]:
    return [tasks[index : index + size] for index in range(0, len(tasks), size)]


_TASK_PRIORITY_RANK = {"high": 0, "normal": 1, "low": 2}
_TASK_KIND_RANK = {"logic": 0, "patch": 1, "entry": 2}


def _prioritize_pending_tasks(tasks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    indexed = list(enumerate(tasks))
    indexed.sort(
        key=lambda item: (
            _TASK_PRIORITY_RANK.get(str(item[1].get("priority", "normal")).lower(), 1),
            _TASK_KIND_RANK.get(str(item[1].get("kind", "entry")).lower(), 2),
            item[0],
        )
    )
    return [task for _, task in indexed]


def _evidence_anchors(items: Any, limit: int = 4) -> list[str]:
    anchors: list[str] = []
    if not isinstance(items, list):
        return anchors
    for item in items:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path", "")).strip()
        if not path:
            continue
        start = item.get("start_line")
        end = item.get("end_line")
        anchor = f"{path}:{start}-{end}" if start and end else path
        if anchor not in anchors:
            anchors.append(anchor)
        if len(anchors) >= limit:
            break
    return anchors


def _evidence_paths(items: Any) -> set[str]:
    if not isinstance(items, list):
        return set()
    return {
        str(item.get("path", "")).strip()
        for item in items
        if isinstance(item, dict) and str(item.get("path", "")).strip()
    }


def _compact_business_for_task(
    business: Mapping[str, Any],
    task: Mapping[str, Any],
) -> dict[str, Any]:
    task_id = str(task.get("id", ""))
    entry_ids = {str(item) for item in (task.get("entry_ids") or []) if item}
    patch_ids = {str(item) for item in (task.get("patch_ids") or []) if item}
    task_paths = {str(item) for item in (task.get("paths") or []) if item}

    matched_operations: list[dict[str, Any]] = []
    matched_op_ids: set[str] = set()
    for op in business.get("operations", []):
        if not isinstance(op, dict):
            continue
        op_entries = {str(item) for item in (op.get("entry_ids") or []) if item}
        op_patches = {str(item) for item in (op.get("patch_ids") or []) if item}
        op_paths = _evidence_paths(op.get("locations")) | _evidence_paths(op.get("evidence"))
        if (
            (entry_ids and entry_ids & op_entries)
            or (patch_ids and patch_ids & op_patches)
            or (task_paths and task_paths & op_paths)
        ):
            op_id = str(op.get("id", ""))
            if op_id:
                matched_op_ids.add(op_id)
            matched_operations.append(
                {
                    "id": op_id,
                    "name": str(op.get("name", ""))[:160],
                    "actor": str(op.get("actor", ""))[:120],
                    "resource": str(op.get("resource", ""))[:120],
                    "guards": list(op.get("guards", []) or [])[:6],
                    "effects": list(op.get("effects", []) or [])[:4],
                    "anchors": _evidence_anchors(op.get("locations") or op.get("evidence")),
                }
            )
            if len(matched_operations) >= 6:
                break

    matched_investigations: list[dict[str, Any]] = []
    referenced_constraint_ids: set[str] = set()
    for inv in business.get("investigations", []):
        if not isinstance(inv, dict):
            continue
        inv_entries = {str(item) for item in (inv.get("entry_ids") or []) if item}
        inv_ops = {str(item) for item in (inv.get("operation_ids") or []) if item}
        if (
            (task_id and str(inv.get("task_id", "")) == task_id)
            or (entry_ids and entry_ids & inv_entries)
            or (matched_op_ids and matched_op_ids & inv_ops)
        ):
            for cid in inv.get("constraint_ids", []) or []:
                if cid:
                    referenced_constraint_ids.add(str(cid))
            matched_investigations.append(
                {
                    "id": str(inv.get("id", "")),
                    "question": str(inv.get("question", ""))[:240],
                    "outcome": str(inv.get("outcome", "")),
                    "reason": str(inv.get("reason", ""))[:240],
                    "anchors": _evidence_anchors(inv.get("evidence")),
                }
            )
            if len(matched_investigations) >= 4:
                break

    direct_constraints: list[dict[str, Any]] = []
    global_constraints: list[dict[str, Any]] = []
    for constraint in business.get("constraints", []):
        if not isinstance(constraint, dict):
            continue
        cid = str(constraint.get("id", ""))
        c_paths = _evidence_paths(constraint.get("supporting_evidence")) | _evidence_paths(
            constraint.get("counterevidence")
        )
        compact = {
            "id": cid,
            "description": str(constraint.get("description", ""))[:240],
            "source_kind": str(constraint.get("source_kind", "")),
            "applicability": str(constraint.get("applicability", "")),
            "reason": str(constraint.get("reason", ""))[:200],
            "anchors": _evidence_anchors(constraint.get("supporting_evidence")),
        }
        if cid in referenced_constraint_ids or (task_paths and task_paths & c_paths):
            direct_constraints.append(compact)
        elif str(constraint.get("applicability", "")) == "applicable":
            global_constraints.append(compact)
    constraints = [*direct_constraints, *global_constraints][:6]

    if not (constraints or matched_operations or matched_investigations):
        return {}
    return {
        "constraints": constraints,
        "operations": matched_operations,
        "investigations": matched_investigations,
    }


def _set_task_status(tasks: list[dict[str, Any]], task_id: str, status: str) -> None:
    for item in tasks:
        if str(item.get("id", "")) == task_id:
            item["status"] = status
            return


def _merge_tasks(existing: list[dict[str, Any]], updates: Any) -> list[dict[str, Any]]:
    result = {str(item.get("id", "")): dict(item) for item in existing if isinstance(item, dict)}
    if isinstance(updates, list):
        for item in updates:
            if isinstance(item, dict) and item.get("id"):
                result[str(item["id"])] = {**result.get(str(item["id"]), {}), **item}
    return list(result.values())


def _load_audit(paths: AuditPaths) -> dict[str, Any]:
    if not paths.audit_file.is_file():
        return {}
    try:
        return load_json(paths.audit_file)
    except (OSError, ValueError):
        return {}


def _load_category_details() -> dict[str, Any]:
    from importlib.resources import files

    path = files("yasa_vulnagent.stages.audit").joinpath("category_details.json")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    categories = payload.get("categories")
    return categories if isinstance(categories, dict) else {}


def _commit_id(value: str) -> bool:
    return len(value) == 40 and all(char in "0123456789abcdef" for char in value.lower())


def _usage_snapshot(usage: Any) -> dict[str, Any]:
    if usage is None or not hasattr(usage, "snapshot"):
        return {}
    try:
        return usage.snapshot("audit")["totals"]
    except Exception:
        return {}
