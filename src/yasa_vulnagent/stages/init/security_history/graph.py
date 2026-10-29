from __future__ import annotations

import json
import logging
import time
from concurrent.futures import Future, ThreadPoolExecutor, wait
from pathlib import Path
from typing import Any

from langgraph.graph import END, START, StateGraph
from langgraph.runtime import Runtime

from ....agent.budget import TaskBudget
from ....workflow.state import RunContext
from ....observability import trace_node
from ..index import InitIndex, retrieval_tools
from .git_tools import GitToolbox
from .model import (
    SecurityHistoryError,
    SecurityHistoryFatalError,
    build_model,
    invoke_model,
    load_prompt,
    load_skill,
)
from .patch_graph import build_patch_graph
from .schema import SecurityHistoryState, parse_json_object
from .validation import normalize_candidate, normalize_review


logger = logging.getLogger(__name__)


def build_security_history_graph():
    workflow = StateGraph(SecurityHistoryState, context_schema=RunContext)
    workflow.add_node("snapshot", snapshot)
    workflow.add_node("discover", discover)
    workflow.add_node("process", process)
    workflow.add_node("summarize", summarize)
    workflow.add_edge(START, "snapshot")
    workflow.add_edge("snapshot", "discover")
    workflow.add_edge("discover", "process")
    workflow.add_edge("process", "summarize")
    workflow.add_edge("summarize", END)
    return workflow.compile()


@trace_node("init.security_history.snapshot")
def snapshot(state: SecurityHistoryState, runtime: Runtime[RunContext]) -> dict[str, Any]:
    artifact_dir = Path(state["artifact_dir"])
    _prepare_artifacts(artifact_dir)
    toolbox = GitToolbox(
        Path(state["repository"]),
        diff_chars=runtime.context.settings.history_diff_chars,
        command_timeout=runtime.context.settings.tools_git_timeout,
        cache_bytes=runtime.context.settings.agent_cache_bytes,
    )
    result = toolbox.snapshot()
    if result.get("available") and result.get("shallow"):
        result.setdefault("warnings", []).append("repository history is shallow")
    elif not result.get("available"):
        result.setdefault("warnings", []).append("Git history is unavailable")
    _write_json(artifact_dir / "snapshot.json", result)
    logger.info(
        "history snapshot available=%s commits=%s shallow=%s",
        result.get("available"),
        result.get("commit_count"),
        result.get("shallow"),
    )
    deadline = float(state.get("deadline", 0.0)) or time.monotonic() + runtime.context.settings.history_timeout
    discovery_deadline = min(
        deadline,
        time.monotonic() + runtime.context.settings.history_discovery_timeout,
    )
    return {
        "snapshot": result,
        "deadline": deadline,
        "discovery_deadline": discovery_deadline,
        "warnings": list(result.get("warnings", [])),
    }


@trace_node("init.security_history.discover")
def discover(state: SecurityHistoryState, runtime: Runtime[RunContext]) -> dict[str, Any]:
    artifact_dir = Path(state["artifact_dir"])
    snapshot_data = state.get("snapshot", {})
    if not snapshot_data.get("available"):
        _write_json(artifact_dir / "candidates.json", {"candidates": [], "warnings": state.get("warnings", [])})
        return {
            "candidates": [],
            "warnings": state.get("warnings", []),
            "discovery_unknowns": [],
            "discovery_truncated": False,
        }
    discovery_deadline = float(state.get("discovery_deadline", 0.0))
    if (
        _remaining(state) <= runtime.context.settings.history_summary_reserve
        or (discovery_deadline and time.monotonic() >= discovery_deadline)
    ):
        warning = "history discovery skipped because its time budget was reached"
        warnings = [*state.get("warnings", []), warning]
        _write_json(artifact_dir / "candidates.json", {"candidates": [], "warnings": warnings})
        return {
            "candidates": [],
            "warnings": warnings,
            "discovery_unknowns": [warning],
            "discovery_truncated": True,
        }
    toolbox = GitToolbox(
        Path(state["repository"]),
        captured_head=str(snapshot_data["head"]),
        diff_chars=runtime.context.settings.history_diff_chars,
        command_timeout=runtime.context.settings.tools_git_timeout,
        cache_bytes=runtime.context.settings.agent_cache_bytes,
    )
    model = build_model(runtime.context)
    retrieval = None
    tools = toolbox.langchain_tools()
    index_path = artifact_dir.parent / "index.sqlite"
    if index_path.is_file():
        try:
            retrieval = InitIndex(index_path, reset=False)
            tools = [*tools, *retrieval_tools(retrieval)]
        except Exception as exc:
            logger.warning("history retrieval index unavailable reason=%s", exc)
    try:
        response = invoke_model(
            model,
            load_skill() + "\n\n" + load_prompt("discover.md"),
            _discovery_prompt(state, snapshot_data),
            tools,
            deadline=discovery_deadline,
            budget=TaskBudget(
                deadline=discovery_deadline,
                max_model_calls=runtime.context.settings.history_discovery_max_model_calls,
                max_rounds_per_invocation=runtime.context.settings.agent_max_rounds_per_invocation,
                hard_task_cap=runtime.context.settings.agent_hard_task_cap,
            ),
            usage=runtime.context.usage,
            settings=runtime.context.settings,
            artifact_dir=artifact_dir,
            stage="init.security_history.discover",
            task_id="discover",
        )
    except SecurityHistoryFatalError:
        raise
    except (SecurityHistoryError, TimeoutError) as exc:
        warning = f"history discovery stopped: {exc}"
        warnings = [*state.get("warnings", []), warning]
        _write_json(
            artifact_dir / "candidates.json",
            {
                "candidates": [],
                "unknowns": [str(exc)],
                "warnings": warnings,
                "truncated": True,
            },
        )
        return {
            "candidates": [],
            "warnings": warnings,
            "discovery_unknowns": [str(exc)],
            "discovery_truncated": True,
        }
    finally:
        if retrieval is not None:
            retrieval.close()
    try:
        payload = parse_json_object(response, "security-history discovery")
    except ValueError as exc:
        warning = f"history discovery returned invalid JSON: {exc}"
        warnings = [*state.get("warnings", []), warning]
        _write_json(
            artifact_dir / "candidates.json",
            {"candidates": [], "unknowns": [str(exc)], "warnings": warnings, "truncated": True},
        )
        return {
            "candidates": [],
            "warnings": warnings,
            "discovery_unknowns": [str(exc)],
            "discovery_truncated": True,
        }
    warnings = [*state.get("warnings", []), *_string_list(payload.get("warnings"))]
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    raw_candidates = payload.get("candidates", [])
    if not isinstance(raw_candidates, list):
        warning = "history discovery returned a non-array candidates field"
        warnings.append(warning)
        unknowns = [warning, *_string_list(payload.get("unknowns"))]
        _write_json(
            artifact_dir / "candidates.json",
            {
                "captured_head": snapshot_data["head"],
                "parent_policy": "first_parent",
                "candidates": [],
                "strategy": str(payload.get("strategy", "")).strip(),
                "unknowns": unknowns,
                "warnings": warnings,
                "truncated": True,
            },
        )
        return {
            "candidates": [],
            "warnings": warnings,
            "discovery_unknowns": unknowns,
            "discovery_truncated": True,
        }
    truncated = bool(payload.get("truncated", False)) or len(raw_candidates) > 200
    if len(raw_candidates) > 200:
        warnings.append("history candidates truncated at 200")
    for raw in raw_candidates[:200]:
        if not isinstance(raw, dict):
            warnings.append("ignored non-object history candidate")
            continue
        try:
            candidate = normalize_candidate(raw, toolbox)
        except (ValueError, RuntimeError) as exc:
            warnings.append(f"ignored invalid history candidate: {exc}")
            continue
        if candidate["commit"] in seen:
            continue
        candidate["captured_head"] = snapshot_data["head"]
        seen.add(candidate["commit"])
        candidates.append(candidate)
    _write_json(
        artifact_dir / "candidates.json",
        {
            "captured_head": snapshot_data["head"],
            "parent_policy": "first_parent",
            "candidates": candidates,
            "strategy": str(payload.get("strategy", "")).strip(),
            "unknowns": _string_list(payload.get("unknowns")),
            "warnings": warnings,
            "truncated": truncated,
        },
    )
    logger.info(
        "history discovery candidates=%s truncated=%s warnings=%s",
        len(candidates),
        truncated,
        len(warnings),
    )
    return {
        "candidates": candidates,
        "warnings": warnings,
        "discovery_unknowns": _string_list(payload.get("unknowns")),
        "discovery_truncated": truncated,
    }


@trace_node("init.security_history.process")
def process(state: SecurityHistoryState, runtime: Runtime[RunContext]) -> dict[str, Any]:
    candidates = state.get("candidates", [])
    if not candidates:
        logger.info("history process skipped candidates=0")
        return {"reviews": [], "patch_results": []}
    settings = runtime.context.settings
    workers = max(1, min(settings.history_max_agents, len(candidates)))
    logger.info("history process work_items=%s workers=%s", len(candidates), workers)
    executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="security-history")
    futures: dict[Future[dict[str, Any]], dict[str, Any]] = {
        executor.submit(_process_candidate, state, candidate, runtime.context): candidate
        for candidate in candidates
    }
    pending = dict(futures)
    results: list[dict[str, Any]] = []
    try:
        while pending:
            if _remaining(state) <= 0:
                for future, candidate in list(pending.items()):
                    future.cancel()
                    result = _timeout_result(candidate, "history total timeout")
                    results.append(result)
                    _persist_task_result(Path(state["artifact_dir"]), result)
                    pending.pop(future, None)
                break
            done, _ = wait(list(pending), timeout=min(0.25, _remaining(state)))
            for future in done:
                candidate = pending.pop(future)
                try:
                    result = future.result()
                    results.append(result)
                    _persist_task_result(Path(state["artifact_dir"]), result)
                    patch = result.get("patch") if isinstance(result, dict) else None
                    logger.info(
                        "history work item finished commit=%s status=%s",
                        candidate.get("commit"),
                        patch.get("status") if isinstance(patch, dict) else "unknown",
                    )
                except SecurityHistoryFatalError:
                    for remaining in pending:
                        remaining.cancel()
                    raise
                except SecurityHistoryError as exc:
                    logger.warning(
                        "history task model failed commit=%s reason=%s",
                        candidate["commit"],
                        exc,
                    )
                    result = _failure_result(candidate, str(exc))
                    results.append(result)
                    _persist_task_result(Path(state["artifact_dir"]), result)
                except TimeoutError:
                    result = _timeout_result(candidate, "per-commit task timeout")
                    results.append(result)
                    _persist_task_result(Path(state["artifact_dir"]), result)
                except Exception as exc:
                    logger.warning("history task failed commit=%s reason=%s", candidate["commit"], exc)
                    result = _failure_result(candidate, str(exc))
                    results.append(result)
                    _persist_task_result(Path(state["artifact_dir"]), result)
    finally:
        executor.shutdown(wait=True, cancel_futures=True)
    results.sort(key=lambda item: str(item.get("commit", "")))
    reviews = [item["review"] for item in results if isinstance(item.get("review"), dict)]
    patches = [item["patch"] for item in results if isinstance(item.get("patch"), dict)]
    _write_json(Path(state["artifact_dir"]) / "tasks.json", {"tasks": results})
    logger.info(
        "history process finished reviews=%s patches=%s",
        len(reviews),
        len(patches),
    )
    return {"reviews": reviews, "patch_results": patches}


@trace_node("init.security_history.summarize")
def summarize(state: SecurityHistoryState, runtime: Runtime[RunContext]) -> dict[str, Any]:
    artifact_dir = Path(state["artifact_dir"])
    results = state.get("patch_results", [])
    warnings = list(state.get("warnings", []))
    graphs: list[dict[str, Any]] = []
    for result in results:
        warnings.extend(_string_list(result.get("warnings")))
        graph = result.get("graph")
        if isinstance(graph, dict):
            graphs.append(graph)
    warnings = _unique(warnings)
    gaps = _gaps(state)
    status = "partial" if gaps else "complete"
    unknowns = _unknowns(state)
    _write_json(artifact_dir / "patch_graphs.json", {"graphs": graphs, "warnings": warnings})
    logger.info(
        "history summary status=%s candidates=%s graphs=%s gaps=%s",
        status,
        len(state.get("candidates", [])),
        len(graphs),
        len(gaps),
    )
    summary = {
        "schema": "security-history",
        "schema_version": 1,
        "status": status,
        "captured_head": state.get("snapshot", {}).get("head"),
        "parent_policy": "first_parent",
        "snapshot": state.get("snapshot", {}),
        "candidate_count": len(state.get("candidates", [])),
        "reviews": state.get("reviews", []),
        "patches": results,
        "warnings": warnings,
        "gaps": gaps,
        "unknowns": unknowns,
        "discovery_truncated": bool(state.get("discovery_truncated", False)),
        "config": runtime.context.settings.safe_dict(),
    }
    _write_json(artifact_dir / "summary.json", summary)
    report_path = artifact_dir / "report.md"
    report_path.write_text(_report(summary), encoding="utf-8")
    run_root = artifact_dir.parents[2]
    index = {
        "status": status,
        "captured_head": summary["captured_head"],
        "candidate_count": summary["candidate_count"],
        "security_fix_count": sum(
            1 for review in summary["reviews"] if review.get("decision") == "security_fix"
        ),
        "patch_graph_count": len(graphs),
        "warnings": warnings,
        "gaps": summary["gaps"],
        "unknowns": unknowns,
        "discovery_truncated": summary["discovery_truncated"],
        "artifact_dir": str(artifact_dir.relative_to(run_root)),
        "summary_file": str((artifact_dir / "summary.json").relative_to(run_root)),
        "report_file": str(report_path.relative_to(run_root)),
        "parent_policy": "first_parent",
    }
    return {"security_history": index}


def _process_candidate(
    state: SecurityHistoryState,
    candidate: dict[str, Any],
    context: RunContext,
) -> dict[str, Any]:
    task_deadline = min(
        float(state.get("deadline", time.monotonic())),
        time.monotonic() + context.settings.history_task_timeout,
    )
    toolbox = GitToolbox(
        Path(state["repository"]),
        captured_head=str(candidate.get("captured_head") or "") or None,
        diff_chars=context.settings.history_diff_chars,
        command_timeout=context.settings.tools_git_timeout,
        cache_bytes=context.settings.agent_cache_bytes,
    )
    details = toolbox.commit_details(candidate["commit"])
    diff = toolbox.read_diff(candidate["commit"], candidate.get("parent"), max_chars=context.settings.history_diff_chars)
    _ensure_task_time(task_deadline)
    model = build_model(context)
    response = invoke_model(
        model,
        load_skill() + "\n\n" + load_prompt("review.md"),
        _review_prompt(candidate, details, diff),
        toolbox.langchain_tools(),
        deadline=task_deadline,
        budget=TaskBudget(
            deadline=task_deadline,
            max_model_calls=context.settings.history_max_model_calls,
            max_rounds_per_invocation=context.settings.agent_max_rounds_per_invocation,
            hard_task_cap=context.settings.agent_hard_task_cap,
        ),
        usage=context.usage,
        settings=context.settings,
        artifact_dir=Path(state["artifact_dir"]),
        stage="init.security_history.review",
        task_id=f"commit:{candidate['commit']}",
    )
    _ensure_task_time(task_deadline)
    review = normalize_review(parse_json_object(response, "security-history review"), candidate, toolbox)
    if review["decision"] != "security_fix":
        return {
            "commit": candidate["commit"],
            "review": review,
            "patch": {
                "commit": candidate["commit"],
                "status": "skipped",
                "reason": "review decision is not security_fix",
                "decision": review["decision"],
            },
        }
    patch_state = {
        "repository": state["repository"],
        "artifact_dir": state["artifact_dir"],
        "candidate": candidate,
        "review": review,
        "deadline": task_deadline,
        "correction_attempted": False,
        "correction_log": [],
    }
    patch_state_result = build_patch_graph().invoke(patch_state, context=context)
    _ensure_task_time(task_deadline)
    status = str(patch_state_result.get("status", "failed"))
    graph = patch_state_result.get("graph")
    validation = patch_state_result.get("validation", {})
    if status == "complete" and isinstance(graph, dict) and graph.get("status") == "not_applicable":
        status = "not_applicable"
    patch_result = {
        "commit": candidate["commit"],
        "parent": candidate.get("parent"),
        "status": status,
        "decision": review["decision"],
        "graph": graph if isinstance(graph, dict) and status in {"complete", "not_applicable"} else None,
        "validation": validation,
        "diff_segments": [
            {
                "start_char": item.get("start_char"),
                "end_char": item.get("end_char"),
                "total_chars": item.get("total_chars"),
                "truncated": item.get("truncated", False),
            }
            for item in patch_state_result.get("diff_chunks", [])
            if isinstance(item, dict)
        ],
        "notes": _string_list(patch_state_result.get("notes")),
        "warnings": _string_list(validation.get("warnings")) if isinstance(validation, dict) else [],
        "error": str(patch_state_result.get("error", "")),
        "correction_log": patch_state_result.get("correction_log", []),
    }
    return {"commit": candidate["commit"], "review": review, "patch": patch_result}


def _discovery_prompt(state: SecurityHistoryState, snapshot_data: dict[str, Any]) -> str:
    return (
        f"Repository root: {state['repository']}\n"
        f"Captured HEAD: {snapshot_data.get('head')}\n"
        f"Commit count: {snapshot_data.get('commit_count')}\n"
        f"Shallow: {snapshot_data.get('shallow')}\n"
        "Use the structured Git tools to find candidate historical security repairs.\n"
        "Return the requested JSON object only."
    )


def _review_prompt(candidate: dict[str, Any], details: dict[str, Any], diff: dict[str, Any]) -> str:
    return (
        f"Candidate: {json.dumps(candidate, ensure_ascii=False)}\n"
        f"Commit details: {json.dumps(details, ensure_ascii=False)}\n"
        f"Changed paths: {json.dumps(diff.get('changed_paths', []), ensure_ascii=False)}\n"
        f"Diff chunk ({diff.get('start_char')}..{diff.get('end_char')} / {diff.get('total_chars')}):\n"
        f"{diff.get('text', '')}\n"
        "Use tools for missing evidence and return the requested JSON object only."
    )


def _timeout_result(candidate: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "commit": candidate["commit"],
        "review": {"commit": candidate["commit"], "decision": "uncertain", "status": "timeout"},
        "patch": {"commit": candidate["commit"], "status": "timeout", "error": reason},
    }


def _failure_result(candidate: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "commit": candidate["commit"],
        "review": {"commit": candidate["commit"], "decision": "uncertain", "status": "failed", "error": reason},
        "patch": {"commit": candidate["commit"], "status": "failed", "error": reason},
    }


def _ensure_task_time(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise TimeoutError("per-commit task timeout")


def _prepare_artifacts(artifact_dir: Path) -> None:
    (artifact_dir / "reviews").mkdir(parents=True, exist_ok=True)
    (artifact_dir / "patches").mkdir(parents=True, exist_ok=True)


def _persist_task_result(artifact_dir: Path, result: dict[str, Any]) -> None:
    """Persist failed and skipped items so the current-run ledger is complete."""
    commit = str(result.get("commit", "")).strip()
    if not commit:
        return
    review = result.get("review")
    if isinstance(review, dict):
        _write_json(artifact_dir / "reviews" / f"{commit}.json", review)
    patch = result.get("patch")
    if isinstance(patch, dict):
        graph = patch.get("graph")
        if patch.get("status") in {"complete", "not_applicable"} and isinstance(graph, dict):
            _write_json(artifact_dir / "patches" / commit / "graph.json", graph)
        _write_json(artifact_dir / "patches" / commit / "result.json", patch)


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _remaining(state: SecurityHistoryState) -> float:
    deadline = float(state.get("deadline", 0.0))
    return deadline - time.monotonic() if deadline else 1e12


def _gaps(state: SecurityHistoryState) -> list[str]:
    gaps = list(state.get("warnings", []))
    snapshot_data = state.get("snapshot", {})
    if snapshot_data.get("shallow"):
        gaps.append("shallow Git history may omit older fixes")
    if not snapshot_data.get("available"):
        gaps.append("Git history is unavailable")
    if state.get("discovery_truncated"):
        gaps.append("history discovery was truncated")
    gaps.extend(state.get("discovery_unknowns", []))
    for review in state.get("reviews", []):
        if review.get("decision") == "uncertain":
            gaps.append(f"{review.get('commit')}: review is uncertain")
        for unknown in _string_list(review.get("unknowns")):
            gaps.append(f"{review.get('commit')}: {unknown}")
    for patch in state.get("patch_results", []):
        if patch.get("status") in {"failed", "timeout", "partial"}:
            gaps.append(f"{patch.get('commit')}: {patch.get('status')} ({patch.get('error', '')})")
        for note in _string_list(patch.get("notes")):
            gaps.append(f"{patch.get('commit')}: {note}")
        for warning in _string_list(patch.get("warnings")):
            gaps.append(f"{patch.get('commit')}: {warning}")
    return _unique(gaps)


def _unknowns(state: SecurityHistoryState) -> list[str]:
    unknowns = list(state.get("discovery_unknowns", []))
    for review in state.get("reviews", []):
        unknowns.extend(_string_list(review.get("unknowns")))
    return _unique(unknowns)


def _report(summary: dict[str, Any]) -> str:
    lines = [
        "# Security history",
        "",
        f"- Captured HEAD: `{summary.get('captured_head') or 'unavailable'}`",
        f"- Candidates: {summary.get('candidate_count', 0)}",
        f"- Security-fix reviews: {sum(1 for item in summary.get('reviews', []) if item.get('decision') == 'security_fix')}",
        f"- Validated patch graphs: {sum(1 for item in summary.get('patches', []) if item.get('status') == 'complete')}",
        "",
        "This artifact is historical evidence. Model-inferred graph relations are not static-analysis proof.",
    ]
    if summary.get("warnings"):
        lines.extend(["", "## Warnings", "", *[f"- {item}" for item in summary["warnings"]]])
    if summary.get("gaps"):
        lines.extend(["", "## Gaps", "", *[f"- {item}" for item in summary["gaps"]]])
    return "\n".join(lines) + "\n"


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(item for item in values if item))
