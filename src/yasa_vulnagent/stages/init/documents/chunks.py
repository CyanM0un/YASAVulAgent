from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from langchain_core.tools import StructuredTool

from ....agent.artifacts import atomic_write_json
from ....agent.tokens import TokenCounter


@dataclass
class Chunk:
    chunk_id: str
    location: str
    kind: str
    start: int
    end: int
    tokens: int
    preview: str

    def manifest(self) -> dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "location": self.location,
            "kind": self.kind,
            "tokens_est": self.tokens,
            "preview": self.preview,
        }


class CoverageTracker:
    def __init__(self, chunks: list[Chunk]) -> None:
        self.chunks = chunks
        self.status: dict[str, str] = {chunk.chunk_id: "unread" for chunk in chunks}
        self.reasons: dict[str, str] = {}

    def mark_read(self, chunk_id: str) -> None:
        if chunk_id in self.status:
            self.status[chunk_id] = "read"

    def mark_skipped(self, chunk_id: str, reason: str) -> None:
        if chunk_id in self.status and reason.strip():
            self.status[chunk_id] = "skipped"
            self.reasons[chunk_id] = reason.strip()

    def complete(self) -> bool:
        return all(value in {"read", "skipped"} for value in self.status.values())

    def payload(self, document_id: str, source: str) -> dict[str, Any]:
        chunks = []
        for chunk in self.chunks:
            chunks.append(
                {
                    "chunk_id": chunk.chunk_id,
                    "location": chunk.location,
                    "status": self.status[chunk.chunk_id],
                    "reason": self.reasons.get(chunk.chunk_id, ""),
                }
            )
        return {"document_id": document_id, "source": source, "chunks": chunks, "complete": self.complete()}


class DocumentReadSession:
    """Per-document read tools that record coverage as the agent reads."""

    def __init__(
        self,
        *,
        toolbox: Any,
        item: dict[str, Any],
        chunks: list[Chunk],
        tracker: CoverageTracker,
    ) -> None:
        self.toolbox = toolbox
        self.item = item
        self.chunks = {chunk.chunk_id: chunk for chunk in chunks}
        self.tracker = tracker

    def list_chunks(self) -> dict[str, Any]:
        return {
            "document_id": self.item["id"],
            "source": self.item["reference"],
            "chunks": [chunk.manifest() for chunk in self.chunks.values()],
        }

    def read_chunk(self, chunk_id: str) -> dict[str, Any]:
        chunk = self.chunks.get(chunk_id)
        if chunk is None:
            return {"error": f"unknown chunk: {chunk_id}"}
        reference = str(self.item["reference"])
        if chunk.kind == "page":
            result = self.toolbox.read_pdf(reference, chunk.start, chunk.end)
        elif chunk.kind == "block":
            result = self.toolbox.read_docx(reference, chunk.start, chunk.end)
        else:
            result = self.toolbox.read_file(reference, chunk.start, chunk.end)
        if "error" not in result and result.get("status") != "too_large":
            self.tracker.mark_read(chunk_id)
        return {**result, "chunk_id": chunk_id}

    def search_document(self, query: str, offset: int = 0, limit: int = 50) -> dict[str, Any]:
        result = self.toolbox.search_text(
            query,
            path=str(self.item["reference"]),
            max_results=limit,
            offset=offset,
        )
        return result

    def langchain_tools(self) -> list[StructuredTool]:
        return [
            StructuredTool.from_function(
                func=self.list_chunks,
                name="list_chunks",
                description="List the document's chunks with locations and short previews.",
            ),
            StructuredTool.from_function(
                func=self.read_chunk,
                name="read_chunk",
                description="Read one chunk by id and record it as read.",
            ),
            StructuredTool.from_function(
                func=self.search_document,
                name="search_document",
                description="Search this document for a term; returns line locations.",
            ),
        ]


def build_manifest(
    toolbox: Any,
    item: dict[str, Any],
    *,
    max_tokens: int = 1500,
    counter: TokenCounter | None = None,
) -> list[Chunk]:
    reference = str(item["reference"])
    suffix = Path(reference).suffix.lower()
    counter = counter or TokenCounter()
    if suffix == ".pdf":
        return _pdf_chunks(toolbox, reference, max_tokens, counter)
    if suffix == ".docx":
        return _docx_chunks(toolbox, reference, max_tokens, counter)
    return _text_chunks(toolbox, reference, max_tokens, counter)


def write_manifest(path: Path, document_id: str, source: str, chunks: list[Chunk]) -> None:
    atomic_write_json(
        path,
        {
            "document_id": document_id,
            "source": source,
            "chunks": [chunk.manifest() for chunk in chunks],
        },
    )


def write_coverage(path: Path, payload: dict[str, Any]) -> None:
    existing: dict[str, Any] = {"documents": []}
    if path.is_file():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            existing = {"documents": []}
    documents = [
        item for item in existing.get("documents", []) if item.get("document_id") != payload.get("document_id")
    ]
    documents.append(payload)
    atomic_write_json(path, {"documents": documents})


def _text_chunks(toolbox: Any, reference: str, max_tokens: int, counter: TokenCounter) -> list[Chunk]:
    path = toolbox._safe_path(reference)
    if path is None or not path.is_file():
        return []
    lines = toolbox._read_lines_cached(path)
    if lines is None:
        return []
    chunks: list[Chunk] = []
    start = 1
    used = 0
    preview = ""
    for number, line in enumerate(lines, start=1):
        cost = counter.count_text(line)
        if used and used + cost > max_tokens:
            chunks.append(_chunk(len(chunks) + 1, "line", start, number - 1, used, preview, reference))
            start = number
            used = 0
        if not preview and line.strip():
            preview = line.strip()[:160]
        used += cost
    if start <= len(lines):
        chunks.append(_chunk(len(chunks) + 1, "line", start, len(lines), used, preview, reference))
    return chunks


def _pdf_chunks(toolbox: Any, reference: str, max_tokens: int, counter: TokenCounter) -> list[Chunk]:
    path = toolbox._safe_path(reference)
    if path is None or not path.is_file():
        return []
    try:
        from pypdf import PdfReader

        reader = PdfReader(str(path))
    except Exception:
        return []
    pages = toolbox._pdf_pages_cached(path, reader)
    chunks: list[Chunk] = []
    start = 1
    used = 0
    preview = ""
    for number, text in enumerate(pages, start=1):
        cost = counter.count_text(text)
        if used and used + cost > max_tokens:
            chunks.append(_page_chunk(len(chunks) + 1, start, number - 1, used, preview, reference))
            start = number
            used = 0
        if not preview and text.strip():
            preview = text.strip()[:160]
        used += cost
    if start <= len(pages):
        chunks.append(_page_chunk(len(chunks) + 1, start, len(pages), used, preview, reference))
    return chunks


def _docx_chunks(toolbox: Any, reference: str, max_tokens: int, counter: TokenCounter) -> list[Chunk]:
    path = toolbox._safe_path(reference)
    if path is None or not path.is_file():
        return []
    try:
        from docx import Document

        document = Document(str(path))
    except Exception:
        return []
    blocks = toolbox._docx_blocks_cached(path, document)
    chunks: list[Chunk] = []
    start = 1
    used = 0
    preview = ""
    for number, text in enumerate(blocks, start=1):
        cost = counter.count_text(text)
        if used and used + cost > max_tokens:
            chunks.append(_block_chunk(len(chunks) + 1, start, number - 1, used, preview, reference))
            start = number
            used = 0
        if not preview and text.strip():
            preview = text.strip()[:160]
        used += cost
    if start <= len(blocks):
        chunks.append(_block_chunk(len(chunks) + 1, start, len(blocks), used, preview, reference))
    return chunks


def _chunk(number: int, kind: str, start: int, end: int, tokens: int, preview: str, reference: str) -> Chunk:
    return Chunk(
        chunk_id=f"c{number}",
        location=f"{reference}:{start}-{end}",
        kind=kind,
        start=start,
        end=end,
        tokens=tokens,
        preview=preview,
    )


def _page_chunk(number: int, start: int, end: int, tokens: int, preview: str, reference: str) -> Chunk:
    return Chunk(
        chunk_id=f"c{number}",
        location=f"{reference}:pages {start}-{end}",
        kind="page",
        start=start,
        end=end,
        tokens=tokens,
        preview=preview,
    )


def _block_chunk(number: int, start: int, end: int, tokens: int, preview: str, reference: str) -> Chunk:
    return Chunk(
        chunk_id=f"c{number}",
        location=f"{reference}:blocks {start}-{end}",
        kind="block",
        start=start,
        end=end,
        tokens=tokens,
        preview=preview,
    )
