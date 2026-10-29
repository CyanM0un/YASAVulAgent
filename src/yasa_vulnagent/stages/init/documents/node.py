from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from pathlib import Path
from typing import Any

from langgraph.runtime import Runtime

from ....agent.budget import TaskBudget
from ....agent.tokens import TokenCounter
from ....config import load_settings
from ....observability import safe_reference, trace_node
from ....workflow.state import RunContext, RunState
from .model import (
    DocumentsError,
    DocumentsFatalError,
    build_model,
    invoke_model,
    load_prompt,
    load_skill,
)
from .chunks import (
    CoverageTracker,
    DocumentReadSession,
    build_manifest,
    write_coverage,
    write_manifest,
)
from ..index import InitIndex
from .schema import DocumentsState, parse_json_object
from .tools import DocumentToolbox


logger = logging.getLogger(__name__)

MAX_AGENT_CHUNKS = 12


@trace_node("init.documents")
def run(
    state: RunState,
    runtime: Runtime[RunContext] | None = None,
) -> dict[str, object]:
    """Run the documents subgraph and return its durable state index."""
    from .graph import build_documents_graph

    context = runtime.context if runtime is not None else RunContext(settings=load_settings())
    artifact_dir = Path(state["stages_dir"]) / "init" / "documents"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    document_state: DocumentsState = {
        "repository": state["repository"],
        "artifact_dir": str(artifact_dir),
        "deadline": time.monotonic() + context.settings.documents_timeout,
        "inventory": [],
        "notes": [],
        "unknowns": [],
        "document_index": 0,
    }
    result = build_documents_graph().invoke(document_state, context=context)
    if context.usage is not None:
        context.usage.write(artifact_dir / "usage.json", "init.documents")
    index_path = artifact_dir.parent / "index.sqlite"
    try:
        index = InitIndex(index_path)
        try:
            index.rebuild_documents(artifact_dir / "notes")
        finally:
            index.close()
    except Exception as exc:
        logger.warning("documents index build failed reason=%s", exc)
    return {"documents": result.get("documents", {})}


@trace_node("init.documents.discover")
def discover(state: DocumentsState, runtime: Runtime[RunContext]) -> dict[str, Any]:
    context = getattr(runtime, "context", runtime)
    settings = context.settings
    artifact_dir = Path(state["artifact_dir"])
    _prepare_artifacts(artifact_dir)
    toolbox = DocumentToolbox(
        Path(state["repository"]),
        artifact_dir,
        chunk_chars=settings.documents_chunk_chars,
        fetch_timeout=settings.documents_fetch_timeout,
        read_timeout=settings.tools_fs_read_timeout,
        search_timeout=settings.tools_fs_search_timeout,
        http_timeout=settings.tools_http_timeout,
        http_max_bytes=settings.tools_http_max_bytes,
        max_text_bytes=settings.documents_max_text_bytes,
        max_pdf_bytes=settings.documents_max_pdf_bytes,
        max_pdf_pages=settings.documents_max_pdf_pages,
        max_docx_bytes=settings.documents_max_docx_bytes,
        max_docx_blocks=settings.documents_max_docx_blocks,
        cache_bytes=settings.agent_cache_bytes,
    )
    seed_candidates = toolbox.seed_candidates()
    logger.info("documents discovery seed_candidates=%s", len(seed_candidates))
    seed_text = "\n".join(seed_candidates[:500])
    user_prompt = (
        f"Repository root: {state['repository']}\n"
        "The controller found these candidate project-owned paths. Verify and classify them; use tools for more context.\n"
        f"{seed_text}\n"
        "Return the requested JSON object only."
    )
    model = build_model(context)
    try:
        response = invoke_model(
            model,
            load_skill() + "\n\n" + load_prompt("discover.md"),
            user_prompt,
            toolbox.langchain_tools(),
            deadline=state["deadline"],
            budget=TaskBudget(
                deadline=state["deadline"],
                max_model_calls=settings.documents_discovery_max_model_calls,
                max_rounds_per_invocation=settings.agent_max_rounds_per_invocation,
                hard_task_cap=settings.agent_hard_task_cap,
            ),
            usage=context.usage,
            settings=settings,
            artifact_dir=artifact_dir,
            stage="init.documents.discover",
            task_id="discover",
        )
    except DocumentsFatalError:
        raise
    except (DocumentsError, TimeoutError) as exc:
        warning = f"documents discovery stopped: {exc}"
        warnings = [warning]
        _write_inventory(artifact_dir, [], warnings)
        return {
            "inventory": [],
            "notes": [],
            "unknowns": [],
            "document_index": 0,
            "warnings": warnings,
            "stop_reason": "model_error",
            "chunk_chars": settings.documents_chunk_chars,
            "context_chars": settings.documents_context_chars,
            "fetch_timeout": settings.documents_fetch_timeout,
            "summary_reserve": settings.documents_summary_reserve,
        }
    try:
        payload = parse_json_object(response, "documents discovery")
    except ValueError as exc:
        warning = f"documents discovery returned invalid JSON: {exc}"
        warnings = [warning]
        _write_inventory(artifact_dir, [], warnings)
        return {
            "inventory": [],
            "notes": [],
            "unknowns": [],
            "document_index": 0,
            "warnings": warnings,
            "stop_reason": "model_error",
            "chunk_chars": settings.documents_chunk_chars,
            "context_chars": settings.documents_context_chars,
            "fetch_timeout": settings.documents_fetch_timeout,
            "summary_reserve": settings.documents_summary_reserve,
        }
    warnings: list[str] = _string_list(payload.get("warnings"))
    unknowns = _string_list(payload.get("unknowns"))
    inventory = _normalize_inventory(payload, toolbox, seed_candidates, warnings)
    _write_inventory(artifact_dir, inventory, warnings, unknowns)
    logger.info(
        "documents discovery inventory=%s warnings=%s unknowns=%s",
        len(inventory),
        len(warnings),
        len(unknowns),
    )
    return {
        "inventory": inventory,
        "notes": [],
        "unknowns": unknowns,
        "document_index": 0,
        "warnings": warnings,
        "chunk_chars": settings.documents_chunk_chars,
        "context_chars": settings.documents_context_chars,
        "fetch_timeout": settings.documents_fetch_timeout,
        "summary_reserve": settings.documents_summary_reserve,
    }


@trace_node("init.documents.read")
def read_document(state: DocumentsState, runtime: Runtime[RunContext]) -> dict[str, Any]:
    context = getattr(runtime, "context", runtime)
    settings = context.settings
    inventory = [dict(item) for item in state.get("inventory", [])]
    index = state.get("document_index", 0)
    artifact_dir = Path(state["artifact_dir"])
    if index >= len(inventory):
        return {"document_index": index}
    if _remaining(state) <= state.get("summary_reserve", 180):
        logger.warning("documents reading stopped at total time limit")
        warnings = [*state.get("warnings", []), "documents reading stopped at total time limit"]
        unknowns = list(state.get("unknowns", []))
        for remaining in inventory[index:]:
            if remaining.get("status") == "pending":
                remaining["status"] = "unread"
        _write_inventory(artifact_dir, inventory, warnings, unknowns)
        return {
            "document_index": len(inventory),
            "inventory": inventory,
            "unknowns": unknowns,
            "warnings": warnings,
            "stop_reason": "time_budget",
        }

    item = inventory[index]
    logger.info(
        "documents work item start index=%s total=%s source=%s",
        index + 1,
        len(inventory),
        safe_reference(item.get("reference", "")),
    )
    allowed_urls = {
        str(candidate["reference"]): int(candidate.get("url_depth", 0))
        for candidate in inventory
        if candidate.get("source") == "external"
    }
    toolbox = DocumentToolbox(
        Path(state["repository"]),
        artifact_dir,
        chunk_chars=state.get("chunk_chars", 12000),
        fetch_timeout=state.get("fetch_timeout", 30),
        allowed_urls=allowed_urls,
        read_timeout=settings.tools_fs_read_timeout,
        search_timeout=settings.tools_fs_search_timeout,
        http_timeout=settings.tools_http_timeout,
        http_max_bytes=settings.tools_http_max_bytes,
        max_text_bytes=settings.documents_max_text_bytes,
        max_pdf_bytes=settings.documents_max_pdf_bytes,
        max_pdf_pages=settings.documents_max_pdf_pages,
        max_docx_bytes=settings.documents_max_docx_bytes,
        max_docx_blocks=settings.documents_max_docx_blocks,
        cache_bytes=settings.agent_cache_bytes,
    )
    model = build_model(context)
    cursor = int(item.get("cursor", 1))
    notes = [dict(note) for note in state.get("notes", [])]
    unknowns = list(state.get("unknowns", []))
    warnings = list(state.get("warnings", []))
    read_any = False
    budget = TaskBudget(
        deadline=state["deadline"],
        max_model_calls=settings.documents_max_model_calls,
        max_rounds_per_invocation=settings.agent_max_rounds_per_invocation,
        hard_task_cap=settings.agent_hard_task_cap,
    )
    agent_chunks = _agent_chunks(settings, item, toolbox)
    if agent_chunks:
        agent_result = _read_document_agent(
            state=state,
            item=item,
            inventory=inventory,
            index=index,
            notes=notes,
            unknowns=unknowns,
            warnings=warnings,
            toolbox=toolbox,
            model=model,
            budget=budget,
            settings=settings,
            artifact_dir=artifact_dir,
            chunks=agent_chunks,
            usage=context.usage,
        )
        if agent_result is not None:
            return agent_result
    while cursor is not None and _remaining(state) > state.get("summary_reserve", 180):
        result = toolbox.read_reference(item, cursor)
        if "error" in result:
            logger.warning(
                "documents read failed source=%s reason=%s",
                safe_reference(item["reference"]),
                result["error"],
            )
            item["status"] = "unavailable"
            item["stop_reason"] = "read_error"
            warnings.append(f"document read failed for {item['reference']}: {result['error']}")
            break
        if result.get("status") == "too_large":
            item["status"] = "partial"
            item["stop_reason"] = "too_large"
            warnings.append(f"document is too large for {item['reference']}: {result.get('reason', '')}")
            break
        text = str(result.get("text", ""))
        if not text.strip():
            logger.warning(
                "documents source has no extractable text source=%s",
                safe_reference(item["reference"]),
            )
            item["status"] = "unavailable"
            item["stop_reason"] = "empty_source"
            warnings.append(f"document source has no extractable text: {item['reference']}")
            break
        read_any = True
        source_location = _source_location(result)
        try:
            response = invoke_model(
                model,
                load_skill() + "\n\n" + load_prompt("read.md"),
                _reading_prompt(item, source_location, text),
                toolbox.langchain_tools(),
                deadline=state["deadline"],
                budget=budget,
                usage=context.usage,
                settings=settings,
                artifact_dir=artifact_dir,
                stage="init.documents.read",
                task_id=f"doc:{item['id']}",
            )
            note_payload = parse_json_object(response, "document reading")
        except DocumentsFatalError:
            raise
        except (DocumentsError, TimeoutError, ValueError) as exc:
            logger.warning(
                "documents note failed source=%s reason=%s",
                safe_reference(item["reference"]),
                exc,
            )
            item["status"] = "partial" if read_any else "unavailable"
            item["stop_reason"] = "time_budget" if isinstance(exc, TimeoutError) else "model_error"
            note_payload = None
        if note_payload is not None:
            note = {
                "document_id": item["id"],
                "source": item["reference"],
                "source_file": result.get("source_file"),
                "location": source_location,
                "summary": str(note_payload.get("summary", "")).strip(),
                "facts": note_payload.get("facts", []),
                "unknowns": note_payload.get("unknowns", []),
                "follow_up": note_payload.get("follow_up", []),
            }
            notes.append(note)
            unknowns.extend(_string_list(note["unknowns"]))
            _write_note(artifact_dir, item["id"], len(notes), note)
        if note_payload is None:
            break
        cursor = _next_cursor(result)
        if cursor is None:
            break
    item["cursor"] = cursor
    if item.get("status") not in {"unavailable", "partial"}:
        item["status"] = "read" if cursor is None else "partial"
    if item.get("stop_reason") == "model_error":
        warnings.append(f"document model failed for {item['reference']}")
    _write_inventory(artifact_dir, inventory, warnings, unknowns)
    logger.info(
        "documents work item finish index=%s status=%s notes=%s",
        index + 1,
        item.get("status", "unknown"),
        len(notes),
    )
    return {
        "inventory": inventory,
        "notes": notes,
        "unknowns": _unique(unknowns),
        "document_index": index + 1,
        "warnings": warnings,
        "stop_reason": item.get("stop_reason", state.get("stop_reason", "")),
    }


@trace_node("init.documents.summarize")
def summarize(state: DocumentsState, runtime: Runtime[RunContext]) -> dict[str, Any]:
    context = getattr(runtime, "context", runtime)
    artifact_dir = Path(state["artifact_dir"])
    notes = state.get("notes", [])
    logger.info("documents summary notes=%s", len(notes))
    if not notes:
        logger.warning("documents summary skipped because no reading notes were produced")
        index = _documents_index(state, overview_file=None)
        _write_inventory(
            artifact_dir,
            state.get("inventory", []),
            state.get("warnings", []),
            state.get("unknowns", []),
        )
        return {"documents": index}
    if _remaining(state) <= 0:
        logger.warning("documents summary skipped after total time limit")
        return {
            "documents": _documents_index(state, overview_file=None),
            "stop_reason": "time_budget",
        }

    model = build_model(context)
    settings = context.settings
    budget = TaskBudget(
        deadline=state["deadline"],
        max_model_calls=settings.documents_summary_max_model_calls,
        max_rounds_per_invocation=settings.agent_max_rounds_per_invocation,
        hard_task_cap=settings.agent_hard_task_cap,
    )
    summaries: list[dict[str, Any]] = []
    unknowns = list(state.get("unknowns", []))
    warnings = list(state.get("warnings", []))
    token_counter = TokenCounter(settings.model, settings.agent_token_safety)
    for batch in _token_batches(notes, int(settings.agent_context_tokens * 0.6), token_counter):
        if _remaining(state) <= 0:
            logger.warning("documents summary stopped at total time limit")
            state = {**state, "stop_reason": "time_budget"}
            break
        try:
            response = invoke_model(
                model,
                load_skill() + "\n\n" + load_prompt("summarize.md"),
                _summary_prompt(batch),
                deadline=state["deadline"],
                budget=budget,
                usage=context.usage,
                settings=settings,
                artifact_dir=artifact_dir,
                stage="init.documents.summarize",
                task_id="summary",
            )
            summary = parse_json_object(response, "documents summary")
            summaries.append(summary)
            unknowns.extend(_string_list(summary.get("unknowns")))
            warnings.extend(_string_list(summary.get("warnings")))
        except DocumentsFatalError:
            raise
        except (DocumentsError, TimeoutError, ValueError) as exc:
            logger.warning("documents summary response was invalid reason=%s", exc)
            state = {
                **state,
                "warnings": [*warnings, str(exc)],
                "unknowns": unknowns,
                "stop_reason": "time_budget" if isinstance(exc, TimeoutError) else "model_error",
            }
            warnings = list(state["warnings"])
            if isinstance(exc, TimeoutError):
                break
    overview: str | None = None
    if summaries:
        if len(summaries) == 1:
            overview = str(summaries[0].get("overview", "")).strip()
        elif _remaining(state) > 0:
            try:
                response = invoke_model(
                    model,
                    load_skill() + "\n\n" + load_prompt("summarize.md"),
                    _summary_prompt(summaries),
                    deadline=state["deadline"],
                    budget=budget,
                    usage=context.usage,
                    settings=settings,
                    artifact_dir=artifact_dir,
                    stage="init.documents.summarize",
                    task_id="summary",
                )
                final_summary = parse_json_object(response, "documents final summary")
                overview = final_summary.get("overview")
                unknowns.extend(_string_list(final_summary.get("unknowns")))
                warnings.extend(_string_list(final_summary.get("warnings")))
            except DocumentsFatalError:
                raise
            except (DocumentsError, TimeoutError, ValueError) as exc:
                logger.warning("documents final summary response was invalid reason=%s", exc)
                state = {
                    **state,
                    "warnings": [*warnings, str(exc)],
                    "unknowns": unknowns,
                    "stop_reason": "time_budget" if isinstance(exc, TimeoutError) else "model_error",
                }
                warnings = list(state["warnings"])
        else:
            state = {**state, "stop_reason": "time_budget"}
    state = {
        **state,
        "warnings": _unique(warnings),
        "unknowns": _unique(unknowns),
    }
    overview_file = None
    if isinstance(overview, str) and overview.strip():
        overview_path = artifact_dir / "overview.md"
        overview_path.write_text(overview.strip() + "\n", encoding="utf-8")
        overview_file = str(overview_path.relative_to(artifact_dir.parents[2]))
    index = _documents_index(state, overview_file=overview_file)
    _write_inventory(
        artifact_dir,
        state.get("inventory", []),
        state.get("warnings", []),
        state.get("unknowns", []),
    )
    logger.info(
        "documents summary finished batches=%s warnings=%s unknowns=%s",
        len(summaries),
        len(state.get("warnings", [])),
        len(state.get("unknowns", [])),
    )
    return {
        "overview": overview or "",
        "documents": index,
        "warnings": list(state.get("warnings", [])),
        "unknowns": list(state.get("unknowns", [])),
        "stop_reason": state.get("stop_reason", ""),
    }


def _normalize_inventory(
    payload: dict[str, Any],
    toolbox: DocumentToolbox,
    seed_candidates: list[str],
    warnings: list[str],
) -> list[dict[str, Any]]:
    inventory: list[dict[str, Any]] = []
    seen: set[str] = set()
    model_documents = payload.get("documents", [])
    if not isinstance(model_documents, list):
        warnings.append("documents discovery returned a non-array documents field")
        model_documents = []
    for raw in model_documents:
        if not isinstance(raw, dict):
            continue
        source = raw.get("source", "local")
        reference = raw.get("reference", raw.get("path", raw.get("url")))
        if not isinstance(reference, str) or source not in {"local", "external"}:
            warnings.append("discovery returned a document without a valid source or reference")
            continue
        if source == "local":
            safe = toolbox._safe_path(reference)
            if safe is None or not safe.is_file() or not toolbox._candidate(safe):
                warnings.append(f"discovery excluded local reference: {reference}")
                continue
            reference = toolbox._relative(safe)
        else:
            reference = toolbox._normalize_url(reference)
            if not reference or reference not in toolbox.allowed_urls:
                warnings.append(f"discovery excluded external reference: {reference}")
                continue
        key = f"{source}:{reference}"
        if key in seen:
            continue
        seen.add(key)
        inventory.append(
            {
                "id": _document_id(source, reference),
                "source": source,
                "reference": reference,
                "title": str(raw.get("title", reference)),
                "role": str(raw.get("role", "project documentation or configuration")),
                "format": str(raw.get("format", Path(reference).suffix.lstrip(".") or "html")),
                "url_depth": int(raw.get("url_depth", toolbox.allowed_urls.get(reference, 0))),
                "status": "pending",
                "cursor": 0 if source == "external" else 1,
            }
        )
    for reference in seed_candidates:
        key = f"local:{reference}"
        if key in seen:
            continue
        seen.add(key)
        inventory.append(
            {
                "id": _document_id("local", reference),
                "source": "local",
                "reference": reference,
                "title": Path(reference).name,
                "role": "project-owned documentation or build/deployment configuration",
                "format": Path(reference).suffix.lstrip(".") or "text",
                "url_depth": 0,
                "status": "pending",
                "cursor": 1,
            }
        )
    return inventory


def _documents_index(state: DocumentsState, overview_file: str | None) -> dict[str, Any]:
    artifact_dir = Path(state["artifact_dir"])
    run_root = artifact_dir.parents[2]
    inventory = state.get("inventory", [])
    statuses = {str(item.get("status", "pending")) for item in inventory}
    incomplete = statuses.intersection({"partial", "unavailable", "unread", "pending"})
    unknowns = list(state.get("unknowns", []))
    for note in state.get("notes", []):
        unknowns.extend(_string_list(note.get("unknowns")))
    unknowns = _unique(unknowns)
    gaps = list(state.get("warnings", []))
    if incomplete:
        gaps.append("document inventory contains unread or partially read materials")
    if unknowns:
        gaps.append("document understanding contains unresolved unknowns")
    status = "partial" if incomplete or gaps or (inventory and not overview_file) else "complete"
    return {
        "status": status,
        "inventory_file": str((artifact_dir / "inventory.json").relative_to(run_root)),
        "overview_file": overview_file,
        "notes_dir": str((artifact_dir / "notes").relative_to(run_root)),
        "sources_dir": str((artifact_dir / "sources").relative_to(run_root)),
        "document_count": len(inventory),
        "read_count": sum(item.get("status") == "read" for item in inventory),
        "unread_count": sum(item.get("status") in {"unread", "pending"} for item in inventory),
        "partial_count": sum(item.get("status") in {"partial", "unavailable"} for item in inventory),
        "warnings": list(state.get("warnings", [])),
        "gaps": list(dict.fromkeys(gaps)),
        "unknowns": unknowns,
        "stop_reason": state.get("stop_reason", ""),
    }


def _prepare_artifacts(artifact_dir: Path) -> None:
    (artifact_dir / "sources").mkdir(parents=True, exist_ok=True)
    (artifact_dir / "notes").mkdir(parents=True, exist_ok=True)


def _write_inventory(
    artifact_dir: Path,
    inventory: list[dict[str, Any]],
    warnings: list[str],
    unknowns: list[str] | None = None,
) -> None:
    _prepare_artifacts(artifact_dir)
    payload = {
        "documents": inventory,
        "warnings": list(warnings),
        "unknowns": list(unknowns or []),
    }
    (artifact_dir / "inventory.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def _agent_chunks(settings: Any, item: dict[str, Any], toolbox: DocumentToolbox) -> list[Any]:
    mode = str(settings.documents_read_mode).lower()
    if mode == "map" or item.get("source") == "external":
        return []
    chunks = build_manifest(
        toolbox,
        item,
        max_tokens=settings.documents_agent_chunk_tokens,
        counter=TokenCounter(settings.model, settings.agent_token_safety),
    )
    if not chunks or len(chunks) > MAX_AGENT_CHUNKS:
        return []
    return chunks


def _read_document_agent(
    *,
    state: DocumentsState,
    item: dict[str, Any],
    inventory: list[dict[str, Any]],
    index: int,
    notes: list[dict[str, Any]],
    unknowns: list[str],
    warnings: list[str],
    toolbox: DocumentToolbox,
    model: Any,
    budget: TaskBudget,
    settings: Any,
    artifact_dir: Path,
    chunks: list[Any],
    usage: Any | None = None,
) -> dict[str, Any] | None:
    _prepare_artifacts(artifact_dir)
    tracker = CoverageTracker(chunks)
    session = DocumentReadSession(toolbox=toolbox, item=item, chunks=chunks, tracker=tracker)
    document_id = str(item["id"])
    chunks_dir = artifact_dir / "chunks"
    chunks_dir.mkdir(parents=True, exist_ok=True)
    safe_id = re.sub(r"[^A-Za-z0-9_.-]+", "_", document_id)
    write_manifest(chunks_dir / f"{safe_id}.json", document_id, str(item["reference"]), chunks)
    prompt = (
        f"Document: {item['reference']}\nTitle: {item.get('title', '')}\nRole: {item.get('role', '')}\n\n"
        f"Chunk manifest:\n{json.dumps([chunk.manifest() for chunk in chunks], ensure_ascii=False, indent=2)}\n\n"
        "Read the document through the provided chunk tools, then return the requested JSON object."
    )
    try:
        response = invoke_model(
            model,
            load_skill() + "\n\n" + load_prompt("read_agent.md"),
            prompt,
            session.langchain_tools(),
            deadline=state["deadline"],
            budget=budget,
            usage=usage,
            settings=settings,
            artifact_dir=artifact_dir,
            stage="init.documents.read_agent",
            task_id=f"doc:{document_id}",
        )
        payload = parse_json_object(response, "document reading")
    except DocumentsFatalError:
        raise
    except (DocumentsError, TimeoutError, ValueError) as exc:
        logger.warning("documents agent read failed source=%s reason=%s", safe_reference(item["reference"]), exc)
        warnings.append(f"document agent read failed for {item['reference']}: {exc}")
        item["status"] = "partial"
        item["stop_reason"] = "time_budget" if isinstance(exc, TimeoutError) else "model_error"
        write_coverage(artifact_dir / "coverage.json", tracker.payload(document_id, str(item["reference"])))
        _write_inventory(artifact_dir, inventory, warnings, unknowns)
        return {
            "inventory": inventory,
            "notes": notes,
            "unknowns": _unique(unknowns),
            "document_index": index + 1,
            "warnings": warnings,
            "stop_reason": item["stop_reason"],
        }

    skip_reasons = payload.get("skip_reasons")
    if isinstance(skip_reasons, dict):
        for chunk_id, reason in skip_reasons.items():
            tracker.mark_skipped(str(chunk_id), str(reason))
    if not any(status == "read" for status in tracker.status.values()) and not any(
        status == "skipped" for status in tracker.status.values()
    ):
        logger.warning("documents agent read no chunks source=%s; falling back to map", safe_reference(item["reference"]))
        return None
    coverage = tracker.payload(document_id, str(item["reference"]))
    write_coverage(artifact_dir / "coverage.json", coverage)
    facts = payload.get("facts") if isinstance(payload.get("facts"), list) else []
    note = {
        "document_id": document_id,
        "source": item["reference"],
        "source_file": None,
        "location": "; ".join(chunk.location for chunk in chunks[:1] + chunks[-1:]) if chunks else "",
        "summary": str(payload.get("summary", "")).strip(),
        "facts": facts,
        "unknowns": _string_list(payload.get("unknowns")),
        "follow_up": _string_list(payload.get("follow_up")),
    }
    notes.append(note)
    unknowns.extend(_string_list(note["unknowns"]))
    _write_note(artifact_dir, document_id, len(notes), note)
    item["cursor"] = None
    if tracker.complete():
        item["status"] = "read"
        item["stop_reason"] = ""
    else:
        unread = [chunk_id for chunk_id, status in tracker.status.items() if status == "unread"]
        item["status"] = "partial"
        item["stop_reason"] = "coverage_gap"
        warnings.append(f"document agent left unread chunks for {item['reference']}: {', '.join(unread)}")
    _write_inventory(artifact_dir, inventory, warnings, unknowns)
    logger.info("documents agent read source=%s status=%s chunks=%s", safe_reference(item["reference"]), item["status"], len(chunks))
    return {
        "inventory": inventory,
        "notes": notes,
        "unknowns": _unique(unknowns),
        "document_index": index + 1,
        "warnings": warnings,
        "stop_reason": item.get("stop_reason", ""),
    }


def _write_note(artifact_dir: Path, document_id: str, number: int, note: dict[str, Any]) -> None:
    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", document_id)
    (artifact_dir / "notes" / f"{name}-{number}.json").write_text(
        json.dumps(note, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def _reading_prompt(item: dict[str, Any], location: str, text: str) -> str:
    return (
        f"Document: {item['reference']}\nTitle: {item['title']}\nRole: {item['role']}\n"
        f"Source location: {location}\n\nSource segment:\n{text}\n\nReturn the requested JSON object only."
    )


def _summary_prompt(notes: list[dict[str, Any]]) -> str:
    return "Reading notes:\n" + json.dumps(notes, ensure_ascii=False, indent=2) + "\n\nReturn the requested JSON object only."


def _source_location(result: dict[str, Any]) -> str:
    source = result.get("source", "unknown")
    if "start_line" in result:
        return f"{source}:{result.get('start_line')}-{result.get('end_line')}"
    if "start_page" in result:
        return f"{source}:pages {result.get('start_page')}-{result.get('end_page')}"
    if "start_block" in result:
        return f"{source}:blocks {result.get('start_block')}-{result.get('end_block')}"
    return f"{source}:chars {result.get('start_char', 0)}-{result.get('end_char', 0)}"


def _next_cursor(result: dict[str, Any]) -> int | None:
    for key in ("next_line", "next_page", "next_block", "next_char"):
        if result.get(key) is not None:
            return int(result[key])
    return None


def _token_batches(
    notes: list[dict[str, Any]],
    max_tokens: int,
    counter: TokenCounter,
) -> list[list[dict[str, Any]]]:
    batches: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    used = 0
    for note in notes:
        size = counter.count_json(note)
        if current and used + size > max_tokens:
            batches.append(current)
            current = []
            used = 0
        current.append(note)
        used += size
    if current:
        batches.append(current)
    return batches


def _remaining(state: DocumentsState) -> float:
    deadline = float(state.get("deadline", 0.0))
    return deadline - time.monotonic() if deadline else 1e12


def _document_id(source: str, reference: str) -> str:
    digest = hashlib.sha1(f"{source}:{reference}".encode("utf-8")).hexdigest()[:10]
    return f"{source}-{digest}"


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))
