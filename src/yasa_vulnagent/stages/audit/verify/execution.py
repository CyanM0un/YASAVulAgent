"""Audit verify harness: candidate materialization, verification, and reviews."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterable, Mapping

from ....agent.artifacts import ToolResultStore
from ....agent.budget import BudgetStop, SharedBudgetAdapter
from ....agent.context import ContextManager
from ....agent.retry import RetryPolicy
from ....agent.runtime import run_tool_loop_async
from ....agent.tokens import TokenCounter
from ....config import Settings
from ....storage import utc_now
from ....workflow.state import RunContext
from ...discover.screen.mcp import open_yasa_mcp
from ...discover.screen.tools import ReadCache, SourceToolbox
from ..budget import AuditBudget, AuditTaskBudget
from ..prepare.inventory import current_revision
from ..storage import paths_from_state, write_verify_checkpoint
from ..trace.result import EvidenceIndex
from ..trace.tools import TraceYasaToolbox
from .constants import (
    REVIEW_MAX_ROUNDS,
    SECOND_VERIFIER_MAX_ROUNDS,
    REQUEST_TIMEOUT_SECONDS,
    VERIFIER_MAX_ROUNDS,
)
from .inputs import VerifyInputs, load_inputs
from .model import (
    VerifyBudgetError,
    VerifyConfigurationError,
    VerifyModelError,
    build_model,
    load_prompt,
    model_name,
    parse_json_object,
)
from .result import (
    build_candidate,
    build_review,
    compact_finding,
    verdict_counts,
    verify_update,
)


@dataclass
class VerifyExecution:
    repository: Path
    model: Any
    model_label: str
    settings: Settings
    scope_files: list[str]
    run_id: str
    inputs: VerifyInputs
    evidence: EvidenceIndex
    task_budget: AuditTaskBudget
    usage: Any | None = None
    store: ToolResultStore | None = None
    mcp_session: Any | None = None
    cache: ReadCache | None = None
    model_semaphore: Any | None = None

    async def run_agent(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        receipts: list[dict[str, Any]],
        max_rounds: int,
        stage: str,
        task_id: str,
    ) -> dict[str, Any]:
        source = SourceToolbox(
            self.repository,
            allowed_paths=self.scope_files,
            task_id=task_id,
            max_output_chars=12000,
            cache=self.cache,
        )
        source.receipts = receipts
        tools = [
            tool
            for tool in source.langchain_tools()
            if getattr(tool, "name", "") != "save_note"
        ]
        if self.mcp_session is not None:
            yasa = TraceYasaToolbox(
                self.mcp_session,
                self.repository,
                max_output_chars=12000,
                budget=self.task_budget,
            )
            yasa.receipts = receipts
            tools.extend(yasa.langchain_tools())
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
            raise VerifyBudgetError(f"{stage} budget exhausted: {exc.reason}") from exc
        except Exception as exc:
            raise VerifyModelError(f"{stage} failed: {exc}") from exc
        return parse_json_object(result.content, f"{stage}:{task_id}")


async def run_verify_stage(state: Mapping[str, Any], context: RunContext) -> dict[str, Any]:
    paths = paths_from_state(state)
    paths.root.mkdir(parents=True, exist_ok=True)
    inputs = load_inputs(state, paths)
    repository = Path(str(state.get("repository") or inputs.audit.get("repo") or ""))
    revision = current_revision(repository)
    if (
        inputs.source_revision
        and inputs.source_revision != "working-tree"
        and inputs.source_revision != revision
    ):
        raise VerifyConfigurationError(
            "source revision changed since prepare; start a new audit run"
        )
    scope_files = [
        str(path) for path in inputs.scope.get("files", []) if isinstance(path, str)
    ]
    tasks = {str(item.get("id", "")): item for item in inputs.tasks if item.get("id")}
    findings = {
        str(item.get("id", "")): dict(item)
        for item in inputs.findings
        if item.get("id")
    }
    reviews = {
        str(item.get("id", "")): dict(item)
        for item in inputs.reviews
        if item.get("id")
    }
    gaps = list(inputs.gaps)
    evidence = EvidenceIndex(repository, scope_files)

    # A confirmed finding without its complete review is not a settled result.
    for finding in findings.values():
        if str(finding.get("verdict", "")) != "confirmed":
            continue
        if _complete_review(finding, reviews) is None:
            finding["verdict"] = "candidate"
            gaps.append(f"{finding.get('id', '')}: confirmed finding had no complete review")

    for trace in inputs.traces:
        trace_id = str(trace.get("id", ""))
        full = inputs.trace_artifacts.get(trace_id)
        if full is None:
            continue
        for flow in full.get("flows", []):
            if not isinstance(flow, dict):
                continue
            task = tasks.get(str(flow.get("task_id") or trace.get("task_id") or ""))
            if task is None:
                gaps.append(f"candidate flow has no task: {flow.get('id', '')}")
                continue
            candidate, candidate_gaps = build_candidate(
                flow, task, full, evidence, inputs.run_id
            )
            gaps.extend(candidate_gaps)
            if candidate is None:
                continue
            existing = findings.get(str(candidate["id"]))
            if existing:
                _merge_refs(existing, candidate)
                continue
            findings[str(candidate["id"])] = candidate

    # Persist candidates before a model call so a crash cannot hide open work.
    _write_checkpoint(
        state,
        findings=findings,
        reviews=reviews,
        inputs=inputs,
        gaps=gaps,
        status="partial",
        stop_reason="verify_pending",
        model={"status": "not_run", "model": ""},
        deferred=0,
    )

    budget = context.audit_budget or AuditBudget.create(context.settings.audit_timeout)
    pending = [item for item in findings.values() if item.get("verdict") == "candidate"]
    review_pending = [
        item for item in findings.values() if _needs_review(item, reviews)
    ]
    open_items = [*pending, *review_pending]
    model: Any | None = None
    model_status = "not_run"
    model_label = ""
    if open_items:
        if budget.expired():
            model_status = "budget_exhausted"
        else:
            try:
                model = build_model(context)
                model_label = model_name(model)
                model_status = "used"
            except VerifyConfigurationError as exc:
                model_status = "unavailable"
                gaps.append(str(exc))

    if not open_items or model is None:
        return _finish(
            state,
            findings=findings,
            reviews=reviews,
            inputs=inputs,
            gaps=gaps,
            status="complete" if not open_items else "partial",
            stop_reason="no_candidates" if not open_items else "verify_model_unavailable",
            model={"status": model_status, "model": model_label},
            deferred=len(open_items) if model is None else 0,
        )

    task_budget = AuditTaskBudget(
        deadline=budget.deadline,
        max_model_calls=max(1, int(context.settings.agent_hard_task_cap)),
    )
    execution = VerifyExecution(
        repository=repository,
        model=model,
        model_label=model_label,
        settings=context.settings,
        scope_files=scope_files,
        run_id=inputs.run_id,
        inputs=inputs,
        evidence=evidence,
        task_budget=task_budget,
        usage=context.usage,
        store=ToolResultStore(paths.root / "tool-results"),
        cache=ReadCache(),
        model_semaphore=asyncio.Semaphore(
            max(1, int(context.settings.audit_model_concurrency))
        ),
    )
    deferred = 0
    async with open_yasa_mcp(context.settings, repository) as session:
        execution.mcp_session = session
        for batch in _batches(open_items, max(1, int(context.settings.audit_max_agents))):
            if budget.expired():
                deferred += len(batch)
                continue
            runs = [
                _run_one(item, execution)
                if str(item.get("verdict", "")) == "candidate"
                else _review_only(item, execution)
                for item in batch
            ]
            results = await asyncio.gather(*runs, return_exceptions=True)
            for item, outcome in zip(batch, results):
                if isinstance(outcome, Exception):
                    deferred += 1
                    gaps.append(f"{item.get('id', '')}: {outcome}")
                    continue
                updated, review, outcome_gaps = outcome
                gaps.extend(outcome_gaps)
                if updated is not None:
                    findings[str(updated["id"])] = updated
                if review is not None:
                    reviews[str(review["id"])] = review
            _write_checkpoint(
                state,
                findings=findings,
                reviews=reviews,
                inputs=inputs,
                gaps=gaps,
                status="partial",
                stop_reason="verify_partial",
                model={"status": model_status, "model": model_label},
                deferred=deferred,
            )

    pending = [item for item in findings.values() if item.get("verdict") == "candidate"]
    review_pending = [
        item for item in findings.values() if _needs_review(item, reviews)
    ]
    open_items = [*pending, *review_pending]
    status = "complete" if not open_items else "partial"
    stop_reason = "verify_complete" if status == "complete" else "verify_partial"
    return _finish(
        state,
        findings=findings,
        reviews=reviews,
        inputs=inputs,
        gaps=gaps,
        status=status,
        stop_reason=stop_reason,
        model={"status": model_status, "model": model_label},
        deferred=deferred,
    )


async def _run_one(
    finding: dict[str, Any],
    execution: VerifyExecution,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, list[str]]:
    candidate_execution = _candidate_execution(execution)
    receipts: list[dict[str, Any]] = []
    task = _task_for(finding, execution.inputs)
    seed = _seed(finding, task, execution.inputs)
    payload = await candidate_execution.run_agent(
        system_prompt=load_prompt("prompt.md"),
        user_prompt=json.dumps(seed, ensure_ascii=False, indent=2),
        receipts=receipts,
        max_rounds=VERIFIER_MAX_ROUNDS,
        stage="audit.verify",
        task_id=str(finding["id"]),
    )
    updated, gaps = verify_update(payload, finding, candidate_execution.evidence, receipts)
    if updated is None:
        return None, None, gaps
    verdict = str(updated.get("verdict", ""))
    if verdict not in {"confirmed", "rejected"}:
        return updated, None, gaps

    review, review_gaps = await _independent_review(
        updated, candidate_execution, seed
    )
    gaps.extend(review_gaps)
    if review.get("status") != "complete":
        updated["verdict"] = "candidate"
        return updated, review, gaps
    if str(review.get("verdict", "")) == verdict:
        updated["review"] = review
        return updated, review, gaps
    return await _adjudicate(updated, candidate_execution, seed, review)


async def _review_only(
    finding: dict[str, Any],
    execution: VerifyExecution,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, list[str]]:
    """Review a previously rejected finding without re-running the verifier."""
    candidate_execution = _candidate_execution(execution)
    task = _task_for(finding, execution.inputs)
    seed = _seed(finding, task, execution.inputs)
    review, gaps = await _independent_review(finding, candidate_execution, seed)
    if review.get("status") != "complete":
        return finding, review, gaps
    if str(review.get("verdict", "")) == "rejected":
        finding["review"] = review
        return finding, review, gaps
    return await _adjudicate(finding, candidate_execution, seed, review)


def _candidate_execution(execution: VerifyExecution) -> VerifyExecution:
    """Verification, review, and adjudication share one per-candidate budget."""
    return replace(
        execution,
        task_budget=AuditTaskBudget(
            deadline=execution.task_budget.deadline,
            max_model_calls=max(1, int(execution.settings.agent_hard_task_cap)),
        ),
    )


async def _independent_review(
    finding: dict[str, Any],
    execution: VerifyExecution,
    seed: Mapping[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    review_receipts: list[dict[str, Any]] = []
    try:
        review_payload = await execution.run_agent(
            system_prompt=load_prompt("review.md"),
            user_prompt=json.dumps(
                {
                    "mode": "independent_finding_review",
                    "finding": compact_finding(finding),
                    "candidate": _candidate_view(seed.get("candidate")),
                },
                ensure_ascii=False,
                indent=2,
            ),
            receipts=review_receipts,
            max_rounds=REVIEW_MAX_ROUNDS,
            stage="audit.verify.review",
            task_id=str(finding["id"]),
        )
    except Exception as exc:
        return _blocked_review(finding, str(exc), mode="independent"), [
            f"independent review failed: {exc}"
        ]
    review, gaps = build_review(
        review_payload,
        finding,
        execution.evidence,
        review_receipts,
        review_id_value=str(finding.get("review_id") or f"review-{finding['id']}"),
        mode="independent",
        model=getattr(execution, "model_label", ""),
    )
    return review, gaps


async def _adjudicate(
    finding: dict[str, Any],
    execution: VerifyExecution,
    seed: Mapping[str, Any],
    review: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, list[str]]:
    gaps: list[str] = []
    second_receipts: list[dict[str, Any]] = []
    try:
        second_payload = await execution.run_agent(
            system_prompt=load_prompt("prompt.md"),
            user_prompt=json.dumps(
                {
                    **seed,
                    "mode": "second_verifier",
                    "prior_review": review,
                    "prior_finding": compact_finding(finding),
                },
                ensure_ascii=False,
                indent=2,
            ),
            receipts=second_receipts,
            max_rounds=SECOND_VERIFIER_MAX_ROUNDS,
            stage="audit.verify.second",
            task_id=str(finding["id"]),
        )
        second, second_gaps = verify_update(
            second_payload, finding, execution.evidence, second_receipts
        )
    except Exception as exc:
        gaps.append(f"second verifier failed: {exc}")
        finding["verdict"] = "candidate"
        review["status"] = "deferred"
        return finding, review, gaps
    gaps.extend(second_gaps)
    if second is None:
        finding["verdict"] = "candidate"
        review["status"] = "deferred"
        return finding, review, gaps
    final_review, final_gaps = build_review(
        second_payload,
        second,
        execution.evidence,
        second_receipts,
        review_id_value=str(review["id"]),
        mode="second_verifier",
        model=getattr(execution, "model_label", ""),
    )
    gaps.extend(final_gaps)
    if final_review.get("status") != "complete":
        second["verdict"] = "candidate"
        final_review["status"] = "deferred"
        return second, final_review, gaps
    second["review"] = final_review
    return second, final_review, gaps


def _complete_review(
    finding: Mapping[str, Any], reviews: Mapping[str, dict[str, Any]]
) -> dict[str, Any] | None:
    for review in reviews.values():
        if (
            str(review.get("target_id", "")) == str(finding.get("id", ""))
            and review.get("type") == "finding"
            and review.get("status") == "complete"
        ):
            return review
    return None


def _needs_review(
    finding: Mapping[str, Any], reviews: Mapping[str, dict[str, Any]]
) -> bool:
    return (
        str(finding.get("verdict", "")) == "rejected"
        and _complete_review(finding, reviews) is None
    )


def _blocked_review(
    finding: Mapping[str, Any], reason: str, *, mode: str
) -> dict[str, Any]:
    return {
        "id": str(finding.get("review_id") or f"review-{finding.get('id', '')}"),
        "type": "finding",
        "target_id": str(finding.get("id", "")),
        "status": "blocked",
        "verdict": "",
        "mode": mode,
        "reason": reason,
        "evidence": [],
        "counterevidence": [],
        "missing_facts": [],
        "limitations": [],
        "second_verifier_used": False,
        "model": "",
        "created_at": utc_now(),
    }


def _task_for(finding: Mapping[str, Any], inputs: VerifyInputs) -> dict[str, Any]:
    for task in inputs.tasks:
        if str(task.get("id", "")) == str(finding.get("task_id", "")):
            return task
    return {}


def _seed(
    finding: Mapping[str, Any],
    task: Mapping[str, Any],
    inputs: VerifyInputs,
) -> dict[str, Any]:
    return {
        "run_id": inputs.run_id,
        "mode": inputs.mode,
        "source_revision": inputs.source_revision,
        "candidate": _candidate_view(finding),
        "task": {
            "id": task.get("id", ""),
            "kind": task.get("kind", ""),
            "paths": list(task.get("paths", []) or []),
            "entry_ids": list(task.get("entry_ids", []) or []),
            "patch_ids": list(task.get("patch_ids", []) or []),
            "repair_unit_refs": list(task.get("repair_unit_refs", []) or []),
            "business_refs": dict(task.get("business_refs", {}) or {}),
        },
        "entry": inputs.entry_for(task),
        "patch": inputs.patch_for(task),
        "business": inputs.business_for(task),
    }


def _candidate_view(finding: Any) -> dict[str, Any]:
    if not isinstance(finding, dict):
        return {}
    return {
        key: finding.get(key)
        for key in (
            "id",
            "task_id",
            "task_ids",
            "trace_id",
            "candidate_key",
            "verdict",
            "reason",
            "title",
            "category",
            "kind",
            "cwe_ids",
            "patch_ids",
            "repair_unit_refs",
            "business_refs",
            "entry_point",
            "impact",
            "source_to_sink",
            "prerequisites",
            "missing_facts",
            "completeness",
            "reachability",
            "triggerability",
            "evidence",
        )
    }


def _merge_refs(existing: dict[str, Any], incoming: Mapping[str, Any]) -> None:
    for key in ("task_ids", "trace_ids", "patch_ids"):
        values = list(existing.get(key, []) or [])
        for item in incoming.get(key, []) or []:
            if item not in values:
                values.append(item)
        existing[key] = values
    units = list(existing.get("repair_unit_refs", []) or [])
    for item in incoming.get("repair_unit_refs", []) or []:
        if item not in units:
            units.append(item)
    existing["repair_unit_refs"] = units
    if incoming.get("business_refs"):
        merged = dict(existing.get("business_refs") or {})
        for key, values in dict(incoming.get("business_refs") or {}).items():
            merged[key] = list(dict.fromkeys([*(merged.get(key, []) or []), *(values or [])]))
        existing["business_refs"] = merged


def _batches(values: list[dict[str, Any]], size: int) -> Iterable[list[dict[str, Any]]]:
    size = max(1, int(size))
    for index in range(0, len(values), size):
        yield values[index : index + size]


def _finish(
    state: Mapping[str, Any],
    *,
    findings: Mapping[str, dict[str, Any]],
    reviews: Mapping[str, dict[str, Any]],
    inputs: VerifyInputs,
    gaps: list[str],
    status: str,
    stop_reason: str,
    model: Mapping[str, Any],
    deferred: int,
) -> dict[str, Any]:
    summary = _summary(
        findings,
        reviews,
        inputs=inputs,
        gaps=gaps,
        status=status,
        stop_reason=stop_reason,
        model=model,
        deferred=deferred,
    )
    updated = {
        **dict(state),
        "status": status,
        "stop_reason": stop_reason,
        "next_action": "gate",
        "findings": list(findings.values()),
        "reviews": list(reviews.values()),
        "verify": summary,
        "gaps": list(gaps),
        "framework": {**dict(state.get("framework") or {}), "verify_done": True},
    }
    write_verify_checkpoint(updated)
    return updated


def _write_checkpoint(
    state: Mapping[str, Any],
    *,
    findings: Mapping[str, dict[str, Any]],
    reviews: Mapping[str, dict[str, Any]],
    inputs: VerifyInputs,
    gaps: list[str],
    status: str,
    stop_reason: str,
    model: Mapping[str, Any],
    deferred: int,
) -> None:
    summary = _summary(
        findings,
        reviews,
        inputs=inputs,
        gaps=gaps,
        status=status,
        stop_reason=stop_reason,
        model=model,
        deferred=deferred,
    )
    write_verify_checkpoint(
        {
            **dict(state),
            "findings": list(findings.values()),
            "reviews": list(reviews.values()),
            "verify": summary,
            "gaps": list(gaps),
            "framework": {**dict(state.get("framework") or {}), "verify_done": True},
        }
    )


def _summary(
    findings: Mapping[str, dict[str, Any]],
    reviews: Mapping[str, dict[str, Any]],
    *,
    inputs: VerifyInputs,
    gaps: list[str],
    status: str,
    stop_reason: str,
    model: Mapping[str, Any],
    deferred: int,
) -> dict[str, Any]:
    counts = verdict_counts(findings.values())
    candidate = sum(1 for item in findings.values() if item.get("verdict") == "candidate")
    complete_reviews = {
        str(item.get("target_id", ""))
        for item in reviews.values()
        if item.get("status") == "complete" and item.get("type") == "finding"
    }
    pending_review = sum(
        1
        for item in findings.values()
        if item.get("verdict") == "confirmed"
        and str(item.get("id", "")) not in complete_reviews
    )
    return {
        "status": status,
        "mode": inputs.mode,
        "source_revision": inputs.source_revision,
        "candidate_count": sum(counts.values()),
        "finding_count": len(findings),
        "confirmed_count": counts["confirmed"],
        "rejected_count": counts["rejected"],
        "needs_validation_count": counts["needs_validation"],
        "unverified_count": candidate,
        "review_count": len(reviews),
        "complete_review_count": len(complete_reviews),
        "pending_review_count": pending_review,
        "second_verifier_count": sum(
            1 for item in reviews.values() if item.get("second_verifier_used")
        ),
        "deferred_count": deferred,
        "gaps": list(dict.fromkeys(str(item) for item in [*inputs.gaps, *gaps])),
        "warnings": [],
        "limitations": [
            "verify checks candidate findings only; audit closure is gate-owned"
        ],
        "stop_reason": stop_reason,
        "model": dict(model),
        "written_at": utc_now(),
    }
