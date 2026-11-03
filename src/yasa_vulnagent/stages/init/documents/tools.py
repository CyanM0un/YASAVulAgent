from __future__ import annotations

import hashlib
import json
import fnmatch
import os
import re
import threading
import time
from collections import OrderedDict
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urldefrag, urljoin, urlparse

import httpx
from langchain_core.tools import StructuredTool


_EXCLUDED_DIRS = {
    ".git",
    ".tools",
    ".yasa-vulnagent",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "generated",
    "node_modules",
    "target",
    "third_party",
    "third-party",
    "vendor",
}
_SECRET_NAMES = {".env", "id_rsa", "credentials.json", "secrets.json", "secrets.yaml"}
_TEXT_SUFFIXES = {
    ".adoc",
    ".cfg",
    ".conf",
    ".docx",
    ".html",
    ".htm",
    ".ini",
    ".json",
    ".md",
    ".markdown",
    ".pdf",
    ".properties",
    ".rst",
    ".txt",
    ".toml",
    ".xml",
    ".yaml",
    ".yml",
}
_SPECIAL_NAMES = {
    "dockerfile",
    "jenkinsfile",
    "makefile",
    "procfile",
    "readme",
    "license",
    "notice",
    "contributing",
    "security",
    "changelog",
}
_URL_RE = re.compile(r"https?://[^\s<>\"')\]`(]+", re.IGNORECASE)


class _HTMLTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self.links: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() in {"script", "style", "noscript"}:
            self._skip_depth += 1
        if tag.lower() == "a":
            href = dict(attrs).get("href")
            if href:
                self.links.append(href)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "style", "noscript"} and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip_depth and data.strip():
            self.parts.append(data.strip())


class DocumentToolbox:
    """Read-only repository and documentation tools used by the documents graph."""

    def __init__(
        self,
        repository: Path,
        artifact_dir: Path,
        *,
        chunk_chars: int = 12000,
        fetch_timeout: int = 30,
        allowed_urls: dict[str, int] | None = None,
        read_timeout: int = 10,
        search_timeout: int = 30,
        http_timeout: int = 30,
        http_max_bytes: int = 2_000_000,
        max_text_bytes: int = 2_000_000,
        max_pdf_bytes: int = 50_000_000,
        max_pdf_pages: int = 300,
        max_docx_bytes: int = 20_000_000,
        max_docx_blocks: int = 5000,
        cache_bytes: int = 64_000_000,
    ) -> None:
        self.repository = repository.resolve()
        self.artifact_dir = artifact_dir
        self.sources_dir = artifact_dir / "sources"
        self.sources_dir.mkdir(parents=True, exist_ok=True)
        self.chunk_chars = chunk_chars
        self.fetch_timeout = fetch_timeout
        self.read_timeout = max(1, read_timeout)
        self.search_timeout = max(1, search_timeout)
        self.http_timeout = max(1, http_timeout)
        self.http_max_bytes = max(1000, http_max_bytes)
        self.max_text_bytes = max(1, max_text_bytes)
        self.max_pdf_bytes = max(1, max_pdf_bytes)
        self.max_pdf_pages = max(1, max_pdf_pages)
        self.max_docx_bytes = max(1, max_docx_bytes)
        self.max_docx_blocks = max(1, max_docx_blocks)
        self.cache_bytes = max(0, cache_bytes)
        self._cache: OrderedDict[tuple[Any, ...], tuple[int, Any]] = OrderedDict()
        self._cache_lock = threading.Lock()
        self.allowed_urls: dict[str, int] = {}
        self.url_prefixes: dict[str, str] = {}
        for url, depth in (allowed_urls or {}).items():
            self.allow_url(url, depth)

    def list_directory(
        self,
        path: str = ".",
        max_entries: int = 200,
        offset: int = 0,
    ) -> dict[str, Any]:
        directory = self._safe_path(path)
        if directory is None or not directory.is_dir():
            return {"error": f"directory is unavailable: {path}"}
        entries = []
        for entry in sorted(directory.iterdir(), key=lambda item: item.name.lower()):
            if self._ignored(entry):
                continue
            entries.append({"name": entry.name, "kind": "directory" if entry.is_dir() else "file"})
        start = max(0, int(offset))
        limit = max(1, min(int(max_entries), 500))
        selected = entries[start : start + limit]
        return {
            "path": self._relative(directory),
            "entries": selected,
            "returned": len(selected),
            "total_estimate": len(entries),
            "truncated": start + len(selected) < len(entries),
            "next_cursor": start + len(selected) if start + len(selected) < len(entries) else None,
        }

    def glob(
        self,
        pattern: str = "**/*",
        max_results: int = 200,
        offset: int = 0,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + self.search_timeout
        matches = []
        normalized_pattern = pattern.removeprefix("./")
        for path in self._candidate_files(self.repository):
            if time.monotonic() >= deadline:
                return {
                    "pattern": pattern,
                    "matches": matches,
                    "returned": len(matches),
                    "truncated": True,
                    "status": "timeout",
                    "next_cursor": None,
                }
            relative = self._relative(path)
            if fnmatch.fnmatchcase(relative, normalized_pattern) or fnmatch.fnmatchcase(
                relative, normalized_pattern.replace("**/", "")
            ):
                matches.append(relative)
        start = max(0, int(offset))
        limit = max(1, min(int(max_results), 500))
        selected = matches[start : start + limit]
        return {
            "pattern": pattern,
            "matches": selected,
            "returned": len(selected),
            "total_estimate": len(matches),
            "truncated": start + len(selected) < len(matches),
            "next_cursor": start + len(selected) if start + len(selected) < len(matches) else None,
        }

    def search_text(
        self,
        query: str,
        path: str = ".",
        max_results: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        root = self._safe_path(path)
        if root is None or not root.exists():
            return {"error": f"path is unavailable: {path}"}
        deadline = time.monotonic() + self.search_timeout
        files = [root] if root.is_file() else self._candidate_files(root)
        start = max(0, int(offset))
        limit = max(1, min(int(max_results), 500))
        matches: list[dict[str, Any]] = []
        for file_path in files:
            if time.monotonic() >= deadline:
                return {
                    "query": query,
                    "matches": matches,
                    "returned": len(matches),
                    "truncated": True,
                    "status": "timeout",
                    "next_cursor": start + len(matches),
                }
            lines = self._read_lines_cached(file_path)
            if lines is None:
                continue
            for line_number, line in enumerate(lines, start=1):
                if query.lower() in line.lower():
                    if len(matches) >= start + limit + 1:
                        selected = matches[start : start + limit]
                        return {
                            "query": query,
                            "matches": selected,
                            "returned": len(selected),
                            "truncated": True,
                            "next_cursor": start + len(selected),
                        }
                    matches.append(
                        {
                            "path": self._relative(file_path),
                            "line": line_number,
                            "text": line[:500],
                        }
                    )
        selected = matches[start : start + limit]
        return {
            "query": query,
            "matches": selected,
            "returned": len(selected),
            "truncated": start + len(selected) < len(matches),
            "next_cursor": start + len(selected) if start + len(selected) < len(matches) else None,
        }

    def read_file(
        self,
        path: str,
        start_line: int = 1,
        end_line: int | None = None,
    ) -> dict[str, Any]:
        file_path = self._safe_path(path)
        if file_path is None or not file_path.is_file() or not self._candidate(file_path):
            return {"error": f"file is unavailable: {path}"}
        size_error = self._size_error(file_path, self.max_text_bytes, "text")
        if size_error is not None:
            return size_error
        lines = self._read_lines_cached(file_path)
        if lines is None:
            return {"error": f"file is unreadable or binary: {path}"}
        if not lines:
            return self._source_payload(
                "",
                {
                    "source": self._relative(file_path),
                    "start_line": 1,
                    "end_line": 0,
                    "next_line": None,
                    "total_lines": 0,
                    "truncated": False,
                },
            )
        start = max(1, start_line)
        if start > len(lines):
            return self._source_payload(
                "",
                {
                    "source": self._relative(file_path),
                    "start_line": start,
                    "end_line": len(lines),
                    "next_line": None,
                    "total_lines": len(lines),
                    "truncated": False,
                },
            )
        finish = len(lines) if end_line is None else max(start, min(end_line, len(lines)))
        text, actual_end, truncated = self._bounded_lines(lines, start, finish)
        self._register_text_urls("\n".join(lines))
        return self._source_payload(
            text,
            {
                "source": self._relative(file_path),
                "start_line": start,
                "end_line": actual_end,
                "next_line": actual_end + 1 if actual_end < len(lines) else None,
                "total_lines": len(lines),
                "truncated": truncated or actual_end < finish,
            },
        )

    def read_pdf(
        self,
        path: str,
        start_page: int = 1,
        end_page: int | None = None,
    ) -> dict[str, Any]:
        file_path = self._safe_path(path)
        if file_path is None or file_path.suffix.lower() != ".pdf":
            return {"error": f"PDF is unavailable: {path}"}
        size_error = self._size_error(file_path, self.max_pdf_bytes, "PDF")
        if size_error is not None:
            return size_error
        try:
            from pypdf import PdfReader
        except ImportError:
            return {"error": "pypdf is required to read PDF documents"}
        try:
            reader = PdfReader(str(file_path))
            total_pages = len(reader.pages)
            if total_pages > self.max_pdf_pages:
                return {
                    "status": "too_large",
                    "reason": "pdf_pages",
                    "pages": total_pages,
                    "limit": self.max_pdf_pages,
                }
            pages = self._pdf_pages_cached(file_path, reader)
            start = max(1, start_page)
            finish = total_pages if end_page is None else min(end_page, total_pages)
            if start > total_pages or finish < start:
                return self._source_payload(
                    "",
                    {
                        "source": self._relative(file_path),
                        "start_page": start,
                        "end_page": start - 1,
                        "next_page": None,
                        "total_pages": total_pages,
                        "needs_ocr": False,
                        "truncated": False,
                    },
                )
            parts: list[str] = []
            actual_end = start - 1
            for page_number in range(start, max(start, finish) + 1):
                text = pages[page_number - 1] if page_number - 1 < len(pages) else ""
                parts.append(f"[Page {page_number}]\n{text}")
                actual_end = page_number
                if len("\n".join(parts)) >= self.chunk_chars:
                    break
            text = "\n\n".join(parts)[: self.chunk_chars]
            self._register_text_urls("\n\n".join(parts))
            return self._source_payload(
                text,
                {
                    "source": self._relative(file_path),
                    "start_page": start,
                    "end_page": actual_end,
                    "next_page": actual_end + 1 if actual_end < total_pages else None,
                    "total_pages": total_pages,
                    "needs_ocr": not text.strip(),
                    "truncated": actual_end < finish or len("\n\n".join(parts)) > len(text),
                },
            )
        except Exception as exc:
            return {"error": f"PDF extraction failed: {exc}"}

    def read_docx(
        self,
        path: str,
        start_block: int = 1,
        end_block: int | None = None,
    ) -> dict[str, Any]:
        file_path = self._safe_path(path)
        if file_path is None or file_path.suffix.lower() != ".docx":
            return {"error": f"DOCX is unavailable: {path}"}
        size_error = self._size_error(file_path, self.max_docx_bytes, "DOCX")
        if size_error is not None:
            return size_error
        try:
            from docx import Document
        except ImportError:
            return {"error": "python-docx is required to read DOCX documents"}
        try:
            document = Document(str(file_path))
            blocks = self._docx_blocks_cached(file_path, document)
            if len(blocks) > self.max_docx_blocks:
                return {
                    "status": "too_large",
                    "reason": "docx_blocks",
                    "blocks": len(blocks),
                    "limit": self.max_docx_blocks,
                }
            start = max(1, start_block)
            finish = len(blocks) if end_block is None else min(end_block, len(blocks))
            if finish < start:
                return self._source_payload(
                    "",
                    {
                        "source": self._relative(file_path),
                        "start_block": start,
                        "end_block": start - 1,
                        "next_block": None,
                        "total_blocks": len(blocks),
                        "truncated": False,
                    },
                )
            selected = blocks[start - 1 : max(start, finish)]
            text = "\n\n".join(
                f"[Block {start + offset}]\n{content}" for offset, content in enumerate(selected)
            )
            text = text[: self.chunk_chars]
            self._register_text_urls("\n\n".join(blocks))
            actual_end = start + len(selected) - 1 if selected else start - 1
            return self._source_payload(
                text,
                {
                    "source": self._relative(file_path),
                    "start_block": start,
                    "end_block": actual_end,
                    "next_block": actual_end + 1 if actual_end < len(blocks) else None,
                    "total_blocks": len(blocks),
                    "truncated": actual_end < finish or len("\n\n".join(selected)) > len(text),
                },
            )
        except Exception as exc:
            return {"error": f"DOCX extraction failed: {exc}"}

    def webfetch(self, url: str, start_char: int = 0) -> dict[str, Any]:
        normalized = self._normalize_url(url)
        depth = self.allowed_urls.get(normalized)
        if depth is None:
            return {"error": "URL was not discovered from an allowed repository document"}
        truncated_bytes = False
        try:
            with httpx.Client(
                follow_redirects=True,
                timeout=min(self.fetch_timeout, self.http_timeout),
                headers={"User-Agent": "yasa-vulnagent-documents/0.1"},
            ) as client:
                with client.stream("GET", normalized) as response:
                    response.raise_for_status()
                    content = bytearray()
                    for chunk in response.iter_bytes():
                        remaining = self.http_max_bytes - len(content)
                        if remaining <= 0:
                            truncated_bytes = True
                            break
                        content.extend(chunk[:remaining])
                        if len(chunk) > remaining:
                            truncated_bytes = True
                            break
                    response_url = str(response.url)
        except httpx.HTTPError as exc:
            return {"error": f"webfetch failed: {exc}"}
        parser = _HTMLTextParser()
        parser.feed(content.decode("utf-8", errors="replace"))
        full_text = "\n".join(parser.parts)
        start = max(0, start_char)
        text = full_text[start : start + self.chunk_chars]
        for link in parser.links:
            candidate = self._normalize_url(urljoin(response_url, link))
            if self._same_host(normalized, candidate) and self._same_project(normalized, candidate) and depth < 1:
                self.allow_url(candidate, depth + 1)
        return self._source_payload(
            text,
            {
                "source": normalized,
                "start_char": start,
                "end_char": start + len(text),
                "next_char": start + len(text) if start + len(text) < len(full_text) else None,
                "total_chars": len(full_text),
                "links": [self._normalize_url(urljoin(normalized, link)) for link in parser.links[:50]],
                "truncated": truncated_bytes or start + len(text) < len(full_text),
            },
        )

    def read_reference(self, item: dict[str, Any], cursor: int = 1) -> dict[str, Any]:
        reference = str(item["reference"])
        if item.get("source") == "external":
            return self.webfetch(reference, max(0, cursor))
        suffix = Path(reference).suffix.lower()
        if suffix == ".pdf":
            return self.read_pdf(reference, cursor)
        if suffix == ".docx":
            return self.read_docx(reference, cursor)
        return self.read_file(reference, cursor)

    def langchain_tools(self) -> list[StructuredTool]:
        return [
            StructuredTool.from_function(
                func=self.list_directory,
                name="list_directory",
                description="List a repository directory without editing it.",
            ),
            StructuredTool.from_function(
                func=self.glob,
                name="glob",
                description="Find project-owned documentation and configuration files.",
            ),
            StructuredTool.from_function(
                func=self.search_text,
                name="search_text",
                description="Search project-owned text for a term and return line locations.",
            ),
            StructuredTool.from_function(
                func=self.read_file,
                name="read_file",
                description="Read a bounded line range from a project-owned text file.",
            ),
            StructuredTool.from_function(
                func=self.webfetch,
                name="webfetch",
                description="Fetch a URL discovered in a local project document or its allowed one-level links.",
            ),
            StructuredTool.from_function(
                func=self.read_pdf,
                name="read_pdf",
                description="Read a bounded page range from a text-based PDF.",
            ),
            StructuredTool.from_function(
                func=self.read_docx,
                name="read_docx",
                description="Read a bounded paragraph/table block range from a DOCX file.",
            ),
        ]

    def seed_candidates(self, max_results: int = 500) -> list[str]:
        return [self._relative(path) for path in self._candidate_files(self.repository)[:max_results]]

    def allow_url(self, url: str, depth: int = 0) -> None:
        normalized = self._normalize_url(url)
        if normalized:
            self.allowed_urls.setdefault(normalized, depth)
            self.url_prefixes.setdefault(normalized, self._project_prefix(normalized))

    def _candidate_files(self, root: Path) -> list[Path]:
        if root.is_file():
            return [root] if self._candidate(root) else []
        files: list[Path] = []
        for current, directories, names in os.walk(root, topdown=True, followlinks=False):
            current_path = Path(current)
            directories[:] = sorted(
                directory
                for directory in directories
                if not self._ignored(current_path / directory)
            )
            for name in sorted(names):
                path = current_path / name
                if self._candidate(path):
                    files.append(path)
        return files

    def _candidate(self, path: Path) -> bool:
        if self._ignored(path):
            return False
        name = path.name.lower()
        return (
            path.suffix.lower() in _TEXT_SUFFIXES
            or name in _SPECIAL_NAMES
            or name.startswith("readme")
            or name == ".env.example"
        )

    def _ignored(self, path: Path) -> bool:
        try:
            relative = path.resolve().relative_to(self.repository)
        except ValueError:
            return True
        if any(part in _EXCLUDED_DIRS for part in relative.parts):
            return True
        if path.name in _SECRET_NAMES or (path.name.startswith(".env.") and path.name != ".env.example"):
            return True
        return False

    def _safe_path(self, value: str) -> Path | None:
        candidate = Path(value)
        if candidate.is_absolute() or ".." in candidate.parts:
            return None
        resolved = (self.repository / candidate).resolve()
        if resolved != self.repository and self.repository not in resolved.parents:
            return None
        return resolved

    def _relative(self, path: Path) -> str:
        return path.resolve().relative_to(self.repository).as_posix()

    def _size_error(self, path: Path, limit: int, label: str) -> dict[str, Any] | None:
        try:
            size = path.stat().st_size
        except OSError as exc:
            return {"error": str(exc)}
        if size > limit:
            return {
                "status": "too_large",
                "reason": f"{label.lower()}_bytes",
                "bytes": size,
                "limit": limit,
                "hint": "use search or a bounded range",
            }
        return None

    def _read_lines_cached(self, path: Path) -> list[str] | None:
        try:
            stat = path.stat()
        except OSError:
            return None
        key = ("text", str(path), stat.st_mtime_ns, stat.st_size)
        cached = self._cache_get(key)
        if cached is not None:
            return cached
        deadline = time.monotonic() + self.read_timeout
        try:
            raw = path.read_bytes()
        except OSError:
            return None
        if time.monotonic() > deadline:
            return None
        if b"\x00" in raw[:8192]:
            return None
        lines = raw.decode("utf-8", errors="replace").splitlines()
        self._cache_put(key, lines)
        return lines

    def _pdf_pages_cached(self, path: Path, reader: Any) -> list[str]:
        try:
            stat = path.stat()
        except OSError:
            stat = None
        key = ("pdf", str(path), getattr(stat, "st_mtime_ns", 0), getattr(stat, "st_size", 0))
        cached = self._cache_get(key)
        if cached is not None:
            return cached
        pages = [reader.pages[index].extract_text() or "" for index in range(len(reader.pages))]
        self._cache_put(key, pages)
        return pages

    def _docx_blocks_cached(self, path: Path, document: Any) -> list[str]:
        try:
            stat = path.stat()
        except OSError:
            stat = None
        key = ("docx", str(path), getattr(stat, "st_mtime_ns", 0), getattr(stat, "st_size", 0))
        cached = self._cache_get(key)
        if cached is not None:
            return cached
        blocks: list[str] = []
        for block in document.iter_inner_content():
            if hasattr(block, "text"):
                blocks.append(str(block.text))
            else:
                rows = ["\t".join(cell.text for cell in row.cells) for row in block.rows]
                blocks.append("\n".join(rows))
        self._cache_put(key, blocks)
        return blocks

    def _cache_get(self, key: tuple[Any, ...]) -> Any | None:
        with self._cache_lock:
            item = self._cache.get(key)
            if item is None:
                return None
            self._cache.move_to_end(key)
            return item[1]

    def _cache_put(self, key: tuple[Any, ...], value: Any) -> None:
        if self.cache_bytes <= 0:
            return
        try:
            size = len(json.dumps(value, ensure_ascii=False))
        except (TypeError, ValueError):
            size = 0
        if size > self.cache_bytes:
            return
        with self._cache_lock:
            self._cache[key] = (size, value)
            self._cache.move_to_end(key)
            total = sum(item[0] for item in self._cache.values())
            while total > self.cache_bytes and self._cache:
                _, evicted = self._cache.popitem(last=False)
                total -= evicted[0]

    def _bounded_lines(self, lines: list[str], start: int, finish: int) -> tuple[str, int, bool]:
        selected: list[str] = []
        actual_end = start - 1
        for number in range(start, finish + 1):
            candidate = "\n".join(selected + [lines[number - 1]])
            if selected and len(candidate) > self.chunk_chars:
                break
            selected.append(lines[number - 1])
            actual_end = number
        return "\n".join(selected), actual_end, actual_end < finish

    def _source_payload(self, text: str, metadata: dict[str, Any]) -> dict[str, Any]:
        source = str(metadata.get("source", "source"))
        digest = hashlib.sha1(source.encode("utf-8")).hexdigest()[:12]
        cursor = metadata.get("start_line", metadata.get("start_page", metadata.get("start_block", metadata.get("start_char", 0))))
        source_file = self.sources_dir / f"{digest}-{cursor}.txt"
        source_file.write_text(text, encoding="utf-8")
        return {
            **metadata,
            "text": text,
            "source_file": str(source_file.relative_to(self.artifact_dir)),
        }

    def _register_text_urls(self, text: str) -> None:
        for match in _URL_RE.findall(text):
            self.allow_url(match, 0)

    @staticmethod
    def _normalize_url(url: str) -> str:
        try:
            parsed = urlparse(urldefrag(url)[0])
        except ValueError:
            # Markdown links and bracketed hosts can produce strings urlparse rejects.
            return ""
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username:
            return ""
        return urldefrag(url)[0]

    @staticmethod
    def _same_host(first: str, second: str) -> bool:
        return urlparse(first).netloc.lower() == urlparse(second).netloc.lower()

    def _same_project(self, first: str, second: str) -> bool:
        return self.url_prefixes.get(first, self._project_prefix(first)) == self._project_prefix(second)

    @staticmethod
    def _project_prefix(url: str) -> str:
        path_parts = [part for part in urlparse(url).path.split("/") if part]
        return "/" + path_parts[0] if path_parts else "/"

