from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any

from langgraph.graph import END, START, StateGraph
from langgraph.runtime import Runtime

from ....agent.budget import TaskBudget
from ....agent.tokens import TokenCounter
from ....workflow.state import RunContext
from ....observability import trace_node
from .git_tools import GitToolbox
from .model import build_model, invoke_model, load_prompt, load_skill
from .schema import PatchState, parse_json_object
from .validation import validate_patch_graph


logger = logging.getLogger(__name__)


def build_patch_graph():
    workflow = StateGraph(PatchState, context_schema=RunContext)
    workflow.add_node("extract_units", extract_units)
    workflow.add_node("build_graph", build_graph)
    workflow.add_node("validate", validate)
    workflow.add_edge(START, "extract_units")
    workflow.add_edge("extract_units", "build_graph")
    workflow.add_conditional_edges("build_graph", _after_build, {"end": END, "validate": "validate"})
    workflow.add_edge("validate", END)
    return workflow.compile()


@trace_node("init.security_history.patch_graph.extract_units")
def extract_units(state: PatchState, runtime: Runtime[RunContext]) -> dict[str, Any]:
    candidate = state["candidate"]
    artifact_dir = Path(state["artifact_dir"])
    patch_dir = artifact_dir / "patches" / candidate["commit"]
    sources_dir = patch_dir / "sources"
    sources_dir.mkdir(parents=True, exist_ok=True)
    toolbox = _toolbox(state, runtime)
    changed_paths = toolbox.changed_paths(candidate["commit"], candidate.get("parent"))
    chunks = _read_diff_chunks(toolbox, candidate, runtime.context.settings.history_diff_chars)
    logger.info(
        "patch graph extraction commit=%s changed_paths=%s chunks=%s",
        candidate["commit"],
        len(changed_paths),
        len(chunks),
    )
    if not chunks:
        raise ValueError("commit diff is empty or unavailable")
    _write_json(
        patch_dir / "sources" / "manifest.json",
        {
            "commit": candidate["commit"],
            "parent": candidate.get("parent"),
            "segments": [
                {
                    "start_char": chunk.get("start_char"),
                    "end_char": chunk.get("end_char"),
                    "total_chars": chunk.get("total_chars"),
                    "truncated": chunk.get("truncated", False),
                    "file": f"diff-{index:04d}.patch",
                }
                for index, chunk in enumerate(chunks, start=1)
            ],
        },
    )
    units: list[dict[str, Any]] = []
    notes: list[str] = []
    model = build_model(runtime.context)
    budget = TaskBudget(
        deadline=float(state.get("deadline", 0.0)) or None,
        max_model_calls=runtime.context.settings.patch_max_model_calls,
        max_rounds_per_invocation=runtime.context.settings.agent_max_rounds_per_invocation,
        hard_task_cap=runtime.context.settings.agent_hard_task_cap,
    )
    for index, chunk in enumerate(chunks, start=1):
        if _expired(state):
            notes.append("patch extraction stopped at task deadline")
            break
        source_path = sources_dir / f"diff-{index:04d}.patch"
        source_path.write_text(str(chunk["text"]), encoding="utf-8")
        response = invoke_model(
            model,
            load_skill() + "\n\n" + load_prompt("extract_units.md"),
            _units_prompt(candidate, state.get("review", {}), changed_paths, chunk),
            deadline=float(state.get("deadline", 0.0)) or None,
            budget=budget,
            usage=runtime.context.usage,
            settings=runtime.context.settings,
            artifact_dir=patch_dir,
            stage="init.security_history.patch.extract_units",
            task_id=f"patch:{candidate['commit']}",
        )
        payload = parse_json_object(response, "patch unit extraction")
        for unit in payload.get("units", []) if isinstance(payload.get("units", []), list) else []:
            if isinstance(unit, dict):
                units.append(unit)
        notes.extend(_string_list(payload.get("notes")))
    logger.info(
        "patch graph units extracted commit=%s units=%s",
        candidate["commit"],
        len(units),
    )
    return {
        "changed_paths": changed_paths,
        "diff_chunks": chunks,
        "units": _deduplicate_units(units),
        "notes": notes,
    }


@trace_node("init.security_history.patch_graph.build_graph")
def build_graph(state: PatchState, runtime: Runtime[RunContext]) -> dict[str, Any]:
    if _expired(state):
        raise TimeoutError("per-commit task timeout")
    candidate = state["candidate"]
    prompt = _graph_prompt(candidate, state.get("review", {}), state.get("changed_paths", []), state.get("units", []))
    settings = runtime.context.settings
    counter = TokenCounter(settings.model, settings.agent_token_safety)
    if counter.count_text(prompt) > int(settings.agent_context_tokens * settings.agent_compaction_trigger):
        logger.warning("patch graph prompt too large commit=%s", candidate["commit"])
        return {
            "status": "partial",
            "error": "patch_graph_prompt_too_large",
            "validation": {
                "valid": False,
                "errors": ["patch graph prompt exceeds the configured context budget"],
            },
            "correction_log": [{"event": "prompt_too_large", "chars": len(prompt)}],
        }
    model = build_model(runtime.context)
    patch_dir = Path(state["artifact_dir"]) / "patches" / candidate["commit"]
    response = invoke_model(
        model,
        load_skill() + "\n\n" + load_prompt("build_graph.md"),
        prompt,
        deadline=float(state.get("deadline", 0.0)) or None,
        budget=TaskBudget(
            deadline=float(state.get("deadline", 0.0)) or None,
            max_model_calls=runtime.context.settings.patch_max_model_calls,
            max_rounds_per_invocation=runtime.context.settings.agent_max_rounds_per_invocation,
            hard_task_cap=runtime.context.settings.agent_hard_task_cap,
        ),
        usage=runtime.context.usage,
        settings=runtime.context.settings,
        artifact_dir=patch_dir,
        stage="init.security_history.patch.build_graph",
        task_id=f"patch:{candidate['commit']}",
    )
    payload = parse_json_object(response, "patch graph synthesis")
    graph = payload.get("graph") if isinstance(payload.get("graph"), dict) else payload
    if not isinstance(graph, dict):
        raise ValueError("patch graph synthesis did not return a graph object")
    logger.info("patch graph synthesized commit=%s", candidate["commit"])
    return {"graph": graph}


@trace_node("init.security_history.patch_graph.validate")
def validate(state: PatchState, runtime: Runtime[RunContext]) -> dict[str, Any]:
    if _expired(state):
        raise TimeoutError("per-commit task timeout")
    candidate = state["candidate"]
    toolbox = _toolbox(state, runtime)
    first = validate_patch_graph(toolbox, candidate, state.get("graph", {}))
    logger.info(
        "patch graph validation commit=%s valid=%s errors=%s",
        candidate["commit"],
        first["valid"],
        len(first.get("errors", [])),
    )
    if first["valid"]:
        return {"validation": first, "status": "complete"}
    correction_log = list(state.get("correction_log", []))
    correction_log.append({"event": "correction_started", "errors": first["errors"]})
    if state.get("correction_attempted"):
        correction_log.append({"event": "correction_failed", "errors": first["errors"]})
        return {
            "validation": first,
            "status": "failed",
            "error": "; ".join(first["errors"]),
            "correction_log": correction_log,
        }
    if _expired(state):
        raise TimeoutError("per-commit task timeout")
    model = build_model(runtime.context)
    response = invoke_model(
        model,
        load_skill() + "\n\n" + load_prompt("validate.md"),
        _correction_prompt(candidate, state.get("graph", {}), first),
        deadline=float(state.get("deadline", 0.0)) or None,
        budget=TaskBudget(
            deadline=float(state.get("deadline", 0.0)) or None,
            max_model_calls=runtime.context.settings.patch_max_model_calls,
            max_rounds_per_invocation=runtime.context.settings.agent_max_rounds_per_invocation,
            hard_task_cap=runtime.context.settings.agent_hard_task_cap,
        ),
        usage=runtime.context.usage,
        settings=runtime.context.settings,
        artifact_dir=Path(state["artifact_dir"]) / "patches" / candidate["commit"],
        stage="init.security_history.patch.validate",
        task_id=f"patch:{candidate['commit']}",
    )
    corrected_payload = parse_json_object(response, "patch graph correction")
    corrected = corrected_payload.get("graph") if isinstance(corrected_payload.get("graph"), dict) else corrected_payload
    second = validate_patch_graph(toolbox, candidate, corrected)
    logger.info(
        "patch graph correction commit=%s valid=%s errors=%s",
        candidate["commit"],
        second["valid"],
        len(second.get("errors", [])),
    )
    correction_log.append(
        {
            "event": "correction_finished",
            "valid": second["valid"],
            "errors": second["errors"],
        }
    )
    return {
        "graph": corrected,
        "validation": second,
        "correction_attempted": True,
        "correction_log": correction_log,
        "status": "complete" if second["valid"] else "failed",
        "error": "; ".join(second["errors"]) if not second["valid"] else "",
    }


def _after_build(state: PatchState) -> str:
    return "end" if state.get("status") == "partial" else "validate"


def _toolbox(state: PatchState, runtime: Runtime[RunContext]) -> GitToolbox:
    candidate = state["candidate"]
    return GitToolbox(
        Path(state["repository"]),
        captured_head=str(candidate.get("captured_head") or "") or None,
        diff_chars=runtime.context.settings.history_diff_chars,
        command_timeout=runtime.context.settings.tools_git_timeout,
        cache_bytes=runtime.context.settings.agent_cache_bytes,
    )


def _read_diff_chunks(toolbox: GitToolbox, candidate: dict[str, Any], chunk_chars: int) -> list[dict[str, Any]]:
    pages: list[dict[str, Any]] = []
    cursor = 0
    while True:
        payload = toolbox.read_diff(
            candidate["commit"],
            candidate.get("parent"),
            start_char=cursor,
            max_chars=chunk_chars,
        )
        text = str(payload.get("text", ""))
        if not text:
            break
        pages.append(payload)
        next_cursor = payload.get("next_char")
        if next_cursor is None or next_cursor <= cursor:
            break
        cursor = int(next_cursor)
        if len(pages) >= 128:
            break
    if not pages:
        return []
    full_text = "".join(str(page.get("text", "")) for page in pages)
    total_chars = int(pages[0].get("total_chars", len(full_text)))
    changed_paths = pages[0].get("changed_paths", [])
    return _split_diff_by_boundaries(full_text, chunk_chars, total_chars, changed_paths)


def _split_diff_by_boundaries(
    text: str,
    limit: int,
    total_chars: int,
    changed_paths: Any,
) -> list[dict[str, Any]]:
    """Prefer file/hunk boundaries and only cut inside an oversized hunk."""
    if len(text) <= limit:
        boundaries = [0, len(text)]
    else:
        boundaries = [match.start() for match in re.finditer(r"(?m)^(?:diff --git |@@ )", text)]
        boundaries = sorted(set([0, *boundaries, len(text)]))
    chunks: list[dict[str, Any]] = []
    start = 0
    while start < len(text):
        target = min(len(text), start + max(1000, limit))
        choices = [boundary for boundary in boundaries if start < boundary <= target]
        end = max(choices) if choices else target
        if end <= start:
            end = min(len(text), start + max(1000, limit))
        if end < len(text) and not choices:
            newline = text.rfind("\n", start, end)
            if newline > start:
                end = newline + 1
        segment = text[start:end]
        chunks.append(
            {
                "text": segment,
                "start_char": start,
                "end_char": end,
                "total_chars": total_chars,
                "next_char": end if end < len(text) else None,
                "truncated": end < len(text) or len(text) < total_chars,
                "changed_paths": changed_paths,
            }
        )
        start = end
    return chunks


def _units_prompt(
    candidate: dict[str, Any],
    review: dict[str, Any],
    changed_paths: list[dict[str, Any]],
    chunk: dict[str, Any],
) -> str:
    return (
        f"Commit: {candidate['commit']}\n"
        f"Fixed first parent: {candidate.get('parent')}\n"
        f"Review: {json.dumps(review, ensure_ascii=False)}\n"
        f"Changed paths: {json.dumps(changed_paths, ensure_ascii=False)}\n"
        f"Diff range: {chunk.get('start_char')}..{chunk.get('end_char')} / {chunk.get('total_chars')}\n"
        "Diff chunk follows. Extract only semantically atomic repair units from this chunk.\n"
        f"{chunk.get('text', '')}\n"
        "Return the requested JSON object only."
    )


def _graph_prompt(
    candidate: dict[str, Any],
    review: dict[str, Any],
    changed_paths: list[dict[str, Any]],
    units: list[dict[str, Any]],
) -> str:
    return (
        f"Commit: {candidate['commit']}\n"
        f"Fixed first parent: {candidate.get('parent')}\n"
        f"Review: {json.dumps(review, ensure_ascii=False)}\n"
        f"Changed paths: {json.dumps(changed_paths, ensure_ascii=False)}\n"
        f"Candidate repair units: {json.dumps(units, ensure_ascii=False)}\n"
        "Synthesize one patch graph. Relations are evidence-bounded model inferences, not static-analysis proof.\n"
        "Return the requested JSON object only."
    )


def _correction_prompt(candidate: dict[str, Any], graph: Any, validation: dict[str, Any]) -> str:
    return (
        f"Commit: {candidate['commit']}\n"
        f"Fixed first parent: {candidate.get('parent')}\n"
        f"Invalid graph: {json.dumps(graph, ensure_ascii=False)}\n"
        f"Validation errors: {json.dumps(validation.get('errors', []), ensure_ascii=False)}\n"
        "Correct only the schema/evidence errors. Preserve supported claims and return the full graph object.\n"
        "Return the requested JSON object only."
    )


def _deduplicate_units(units: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, unit in enumerate(units, start=1):
        item = dict(unit)
        identifier = str(item.get("id", "")).strip() or f"unit-{index}"
        if identifier in seen:
            identifier = f"{identifier}-{index}"
        item["id"] = identifier
        seen.add(identifier)
        result.append(item)
    return result


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _expired(state: PatchState) -> bool:
    return float(state.get("deadline", 0.0)) > 0 and time.monotonic() >= float(state["deadline"])


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)
