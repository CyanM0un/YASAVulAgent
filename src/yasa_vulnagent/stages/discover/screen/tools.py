from __future__ import annotations

import fnmatch
import json
import logging
import os
from pathlib import Path
from typing import Any, Iterable

from langchain_core.tools import StructuredTool

from ..ledger import DiscoverLedger

logger = logging.getLogger(__name__)
_SECRET_NAMES = {".env", "id_rsa", "credentials.json", "secrets.json", "secrets.yaml"}
_SECRET_SUFFIXES = (".pem", ".key", ".p12", ".pfx")


def _secret_name(name: str) -> bool:
    lowered = name.lower()
    return lowered in _SECRET_NAMES or lowered.startswith(".env.") or lowered.endswith(_SECRET_SUFFIXES)


_EXCLUDED_DIRS = {
    ".git",
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


def _bounded(value: str, limit: int) -> tuple[str, bool]:
    if len(value) <= limit:
        return value, False
    return value[: max(0, limit)], True


class ReadCache:
    """Per-wave file content cache, invalidated by size or mtime."""

    def __init__(self, max_bytes: int = 4_194_304) -> None:
        self.max_bytes = max(1, int(max_bytes))
        self._files: dict[str, tuple[int, int, list[str]]] = {}

    def lines(self, path: Path) -> list[str]:
        stat = path.stat()
        if stat.st_size > self.max_bytes:
            return path.read_text(encoding="utf-8", errors="replace").splitlines()
        key = str(path)
        cached = self._files.get(key)
        if cached is not None and cached[0] == stat.st_size and cached[1] == stat.st_mtime_ns:
            return cached[2]
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        self._files[key] = (stat.st_size, stat.st_mtime_ns, lines)
        return lines


class SourceToolbox:
    """Read-only, inventory-scoped source tools for one screen task."""

    def __init__(
        self,
        repository: Path,
        allowed_paths: Iterable[str] | None = None,
        *,
        ledger: DiscoverLedger | None = None,
        task_id: str = "",
        max_output_chars: int = 12000,
        cache: ReadCache | None = None,
        notes_max: int = 20,
        note_chars: int = 2000,
        search_max_file_bytes: int = 2_097_152,
        max_scan_files: int = 2000,
        allow_all: bool = False,
    ) -> None:
        self.repository = repository.expanduser().resolve()
        self.ledger = ledger
        self.task_id = str(task_id)
        self.allow_all = bool(allow_all)
        self.allowed_paths = {
            Path(path).as_posix().removeprefix("./")
            for path in (allowed_paths or [])
            if path
        }
        self.max_output_chars = max(1, int(max_output_chars))
        self.cache = cache
        self.notes_max = max(1, int(notes_max))
        self.note_chars = max(1, int(note_chars))
        self.search_max_file_bytes = max(1, int(search_max_file_bytes))
        self.max_scan_files = max(1, int(max_scan_files))
        self.receipts: list[dict[str, Any]] = []
        self._stats: dict[str, os.stat_result] = {}

    def list_directory(
        self,
        path: str = ".",
        max_entries: int = 200,
        cursor: str = "",
    ) -> dict[str, Any]:
        directory = self._safe_path(path, directory=True)
        if directory is None or not directory.is_dir():
            return self._error("list_directory", path, "directory is unavailable")
        entries: list[dict[str, str]] = []
        for item in sorted(directory.iterdir(), key=lambda value: value.name.lower()):
            if self._ignored(item):
                continue
            relative = self._relative(item)
            if item.is_file() and not self._path_allowed(relative):
                continue
            if item.is_dir() and not self._has_allowed_descendant(relative):
                continue
            if cursor and relative <= cursor:
                continue
            entries.append(
                {"name": item.name, "kind": "directory" if item.is_dir() else "file"}
            )
            if len(entries) >= max(1, min(int(max_entries), 200)):
                break
        next_cursor = (
            self._relative(directory / entries[-1]["name"])
            if len(entries) >= max(1, min(int(max_entries), 200))
            else None
        )
        result = {"path": self._relative(directory), "entries": entries, "next_cursor": next_cursor}
        return self._record("list_directory", path, result)

    def glob(self, pattern: str = "**/*", max_results: int = 200, cursor: str = "") -> dict[str, Any]:
        normalized = pattern.removeprefix("./")
        matches: list[str] = []
        scanned_last = cursor
        for path in self._iter_allowed_paths(after=cursor):
            scanned_last = path
            if fnmatch.fnmatchcase(path, normalized) or fnmatch.fnmatchcase(
                path, normalized.removeprefix("**/")
            ):
                matches.append(path)
                if len(matches) >= max(1, min(int(max_results), 200)):
                    break
        page_limit = max(1, min(int(max_results), 200))
        result = {
            "pattern": pattern,
            "matches": matches[:page_limit],
            "truncated": len(matches) >= page_limit,
            "next_cursor": scanned_last if len(matches) >= page_limit else None,
        }
        return self._record("glob", pattern, result)

    def search_text(
        self,
        query: str,
        path: str = ".",
        max_results: int = 100,
        cursor: str = "",
    ) -> dict[str, Any]:
        root = self._safe_path(path, directory=True)
        if root is None or not root.exists():
            return self._error("search_text", path, "path is unavailable")
        limit = max(1, min(int(max_results), 100))
        matches: list[dict[str, Any]] = []
        needle = str(query).lower()
        scanned_last = cursor
        previous = cursor
        scanned = 0
        skipped_large = 0
        for relative in self._iter_allowed_paths(after=cursor):
            candidate = self.repository / relative
            if not self._under(root, candidate):
                continue
            try:
                size = self._stat(candidate).st_size
            except OSError:
                continue
            if size > self.search_max_file_bytes:
                skipped_large += 1
                continue
            if scanned >= self.max_scan_files:
                result = {
                    "query": query,
                    "matches": matches,
                    "truncated": True,
                    "next_cursor": previous or None,
                    "skipped_large": skipped_large,
                }
                return self._record("search_text", path, result)
            scanned_last = relative
            previous = relative
            scanned += 1
            try:
                lines = self._lines(candidate)
            except OSError as exc:
                self._record_error("search_text", self._relative(candidate), str(exc))
                continue
            for line_number, line in enumerate(lines, start=1):
                if needle in line.lower():
                    matches.append(
                        {
                            "path": self._relative(candidate),
                            "line": line_number,
                            "text": line[:500],
                        }
                    )
                    if len(matches) >= limit:
                        result = {
                            "query": query,
                            "matches": matches,
                            "truncated": True,
                            "next_cursor": scanned_last,
                            "skipped_large": skipped_large,
                        }
                        return self._record("search_text", path, result)
        return self._record(
            "search_text",
            path,
            {
                "query": query,
                "matches": matches,
                "truncated": False,
                "next_cursor": None,
                "skipped_large": skipped_large,
            },
        )

    def read_file(
        self,
        path: str,
        start_line: int = 1,
        end_line: int | None = None,
    ) -> dict[str, Any]:
        file_path = self._safe_path(path)
        if file_path is None or not file_path.is_file():
            return self._error("read_file", path, "file is unavailable")
        try:
            lines = self._lines(file_path)
        except OSError as exc:
            return self._error("read_file", path, str(exc))
        start = max(1, int(start_line))
        total_lines = len(lines)
        if start > total_lines:
            result = {
                "path": self._relative(file_path),
                "text": "",
                "start_line": start,
                "end_line": total_lines,
                "next_line": None,
                "total_lines": total_lines,
                "truncated": False,
            }
            self.receipts.append(
                {
                    "tool": "read_file",
                    "path": self._relative(file_path),
                    "start_line": start,
                    "end_line": total_lines,
                    "total_lines": total_lines,
                    "truncated": False,
                    "chars": 0,
                    "status": "ok",
                }
            )
            return result
        requested_end = total_lines if end_line is None else max(start, min(int(end_line), total_lines))
        selected = lines[start - 1 : requested_end]
        text, truncated_by_chars = _bounded("\n".join(selected), self.max_output_chars)
        actual_end = start + text.count("\n")
        if text and not truncated_by_chars and actual_end < requested_end:
            actual_end = requested_end
        truncated = truncated_by_chars or actual_end < requested_end
        result = {
            "path": self._relative(file_path),
            "text": text,
            "start_line": start,
            "end_line": actual_end,
            "next_line": actual_end + 1 if actual_end < total_lines else None,
            "total_lines": total_lines,
            "truncated": truncated,
        }
        receipt = {
            "tool": "read_file",
            "path": self._relative(file_path),
            "start_line": start,
            "end_line": actual_end,
            "total_lines": total_lines,
            "truncated": truncated,
            "chars": len(text),
            "status": "ok",
        }
        self.receipts.append(receipt)
        return result

    def langchain_tools(self) -> list[StructuredTool]:
        return [
            StructuredTool.from_function(
                func=self.list_directory,
                name="list_directory",
                description="List allowed repository directories without editing them; use cursor for pagination.",
            ),
            StructuredTool.from_function(
                func=self.glob,
                name="glob",
                description="Find allowed repository files matching a glob pattern; use cursor for pagination.",
            ),
            StructuredTool.from_function(
                func=self.search_text,
                name="search_text",
                description="Search literal text in allowed repository files; use cursor for pagination.",
            ),
            StructuredTool.from_function(
                func=self.read_file,
                name="read_file",
                description="Read a bounded line range from an allowed repository file.",
            ),
            StructuredTool.from_function(
                func=self.save_note,
                name="save_note",
                description=(
                    "Save one durable note (key plus short text) for this task. "
                    "Notes survive context compaction and are shown back to you after it."
                ),
            ),
        ]

    def save_note(self, key: str, text: str) -> dict[str, Any]:
        if self.ledger is None:
            return {"error": "notes require a ledger-backed task", "tool": "save_note"}
        if self.ledger.note_count(self.task_id) >= self.notes_max:
            return {
                "error": f"note limit reached ({self.notes_max})",
                "tool": "save_note",
            }
        note = self.ledger.put_note(
            self.task_id,
            str(key).strip()[:120] or "note",
            str(text).strip()[: self.note_chars],
        )
        return {"status": "ok", "tool": "save_note", "note_id": note["note_id"]}

    def notes_text(self, limit: int = 3000) -> str:
        if self.ledger is None:
            return ""
        rows = self.ledger.notes(self.task_id, limit=self.notes_max)
        if not rows:
            return ""
        lines = ["Your saved notes (still valid, re-read source before relying on them):"]
        for row in rows:
            lines.append(f"- {row['key']}: {row['text']}")
        return "\n".join(lines)[:limit]

    def _stat(self, path: Path) -> os.stat_result:
        key = str(path)
        cached = self._stats.get(key)
        if cached is None:
            cached = path.stat()
            self._stats[key] = cached
        return cached

    def _lines(self, path: Path) -> list[str]:
        if self.cache is not None:
            return self.cache.lines(path)
        return path.read_text(encoding="utf-8", errors="replace").splitlines()

    def _safe_path(self, path: str, *, directory: bool = False) -> Path | None:
        candidate = Path(str(path))
        if candidate.is_absolute():
            return None
        resolved = (self.repository / candidate).resolve()
        if not self._under(self.repository, resolved):
            return None
        relative = self._relative(resolved)
        if any(part in _EXCLUDED_DIRS for part in Path(relative).parts):
            return None
        if any(_secret_name(part) for part in Path(relative).parts):
            return None
        if directory:
            return resolved if self._has_allowed_descendant(relative) or relative == "." else None
        return resolved if self._path_allowed(relative) else None

    def _has_allowed_descendant(self, directory: str) -> bool:
        if self.allow_all:
            return True
        if self.ledger is not None:
            if directory in {"", "."}:
                return self.ledger.scope_count(self.ledger.get_task(self.task_id) or {}) > 0
            return self.ledger.scope_has_descendant(self.task_id, directory)
        prefix = "" if directory in {"", "."} else directory.rstrip("/") + "/"
        return any(path.startswith(prefix) for path in self.allowed_paths)

    def _path_allowed(self, path: str) -> bool:
        if self.allow_all:
            return True
        if self.ledger is not None:
            return self.ledger.path_allowed(self.task_id, path)
        return path in self.allowed_paths

    def _iter_allowed_paths(self, *, after: str = "") -> Iterable[str]:
        if self.allow_all:
            for root, directories, files in os.walk(self.repository):
                directories[:] = sorted(
                    name
                    for name in directories
                    if name not in _EXCLUDED_DIRS and not _secret_name(name)
                )
                for name in sorted(files):
                    if _secret_name(name):
                        continue
                    path = Path(root) / name
                    if not self._under(self.repository, path):
                        continue
                    relative = self._relative(path)
                    if relative > after:
                        yield relative
            return
        if self.ledger is not None:
            task = self.ledger.get_task(self.task_id)
            if task:
                cursor = after
                while True:
                    page = list(self.ledger.iter_scope_paths(task, after=cursor, limit=200))
                    if not page:
                        return
                    yield from page
                    cursor = page[-1]
                    if len(page) < 200:
                        return
                return
        for path in sorted(self.allowed_paths):
            if path > after:
                yield path

    def _ignored(self, path: Path) -> bool:
        return any(
            part in _EXCLUDED_DIRS or _secret_name(part)
            for part in path.relative_to(self.repository).parts
        )

    def _relative(self, path: Path) -> str:
        return path.resolve().relative_to(self.repository).as_posix() or "."

    @staticmethod
    def _under(root: Path, candidate: Path) -> bool:
        try:
            candidate.resolve().relative_to(root.resolve())
            return True
        except ValueError:
            return False

    def _record(self, tool: str, target: str, result: dict[str, Any]) -> dict[str, Any]:
        serialized, truncated = _bounded(
            json.dumps(result, ensure_ascii=False, default=str), self.max_output_chars
        )
        if truncated:
            next_cursor = result.get("next_cursor")
            result = {
                "tool": tool,
                "target": target,
                "summary": serialized,
                "truncated": True,
            }
            if next_cursor:
                result["next_cursor"] = next_cursor
        self.receipts.append(
            {
                "tool": tool,
                "target": target,
                "status": "ok",
                "truncated": truncated,
                "chars": len(serialized),
            }
        )
        return result

    def _error(self, tool: str, target: str, message: str) -> dict[str, Any]:
        self._record_error(tool, target, message)
        return {"error": message, "tool": tool, "target": target}

    def _record_error(self, tool: str, target: str, message: str) -> None:
        logger.warning(
            "discover screen tool error tool=%s target=%s fallback=source-or-unknown reason=%s",
            tool,
            target,
            message,
        )
        self.receipts.append(
            {"tool": tool, "target": target, "status": "error", "error": message}
        )


class YasaToolbox:
    """Small, bounded LangChain adapter over an already-open MCP session."""

    _TOOL_NAMES = ("search_symbol", "get_function", "get_class_by_name", "get_import_by_file")

    def __init__(
        self,
        session: Any,
        repository: Path,
        *,
        max_output_chars: int = 12000,
        budget: Any | None = None,
    ) -> None:
        self.session = session
        self.repository = repository.expanduser().resolve()
        self.max_output_chars = max(1, int(max_output_chars))
        self.budget = budget
        self.receipts: list[dict[str, Any]] = []

    def langchain_tools(self) -> list[StructuredTool]:
        return [
            StructuredTool.from_function(
                coroutine=self.search_symbol,
                name="search_symbol",
                description="Search YASA's indexed symbols; use only for structural navigation.",
            ),
            StructuredTool.from_function(
                coroutine=self.get_function,
                name="get_function",
                description="Get a bounded YASA function definition for structural navigation.",
            ),
            StructuredTool.from_function(
                coroutine=self.get_class_by_name,
                name="get_class_by_name",
                description="Get a bounded YASA class definition for structural navigation.",
            ),
            StructuredTool.from_function(
                coroutine=self.get_import_by_file,
                name="get_import_by_file",
                description="Get imports recorded by YASA for one repository file.",
            ),
        ]

    async def search_symbol(
        self,
        search: str = "",
        kind: str = "",
        detail_level: str = "summary",
        max_results: int = 20,
    ) -> dict[str, Any]:
        return await self._call(
            "search_symbol",
            {"search": search, "kind": kind, "detail_level": detail_level, "max_results": max_results},
        )

    async def get_function(
        self,
        name: str = "",
        function_fqn: str = "",
        file_path: str = "",
        code: str = "",
        detail_level: str = "summary",
        max_results: int = 20,
    ) -> dict[str, Any]:
        return await self._call(
            "get_function",
            {
                "name": name,
                "function_fqn": function_fqn,
                "file_path": file_path,
                "code": code,
                "detail_level": detail_level,
                "max_results": max_results,
            },
        )

    async def get_class_by_name(
        self,
        name: str = "",
        class_fqn: str = "",
        include_methods: bool = False,
        max_results: int = 20,
    ) -> dict[str, Any]:
        return await self._call(
            "get_class_by_name",
            {
                "name": name,
                "class_fqn": class_fqn,
                "include_methods": include_methods,
                "max_results": max_results,
            },
        )

    async def get_import_by_file(
        self,
        file_path: str,
        fuzzy_match: bool = True,
        exclude_external_import: bool = False,
        max_results: int = 50,
    ) -> dict[str, Any]:
        return await self._call(
            "get_import_by_file",
            {
                "file_path": file_path,
                "fuzzy_match": fuzzy_match,
                "exclude_external_import": exclude_external_import,
                "max_results": max_results,
            },
        )

    async def _call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        safe_arguments = dict(arguments)
        safe_arguments["project_path"] = str(self.repository)
        if "max_results" in safe_arguments:
            safe_arguments["max_results"] = max(1, min(int(safe_arguments["max_results"]), 50))
        safe_arguments["max_output_tokens"] = max(1, min(self.max_output_chars // 4, 6000))
        try:
            call = self.session.call_tool(name, safe_arguments)
            if self.budget is not None:
                import asyncio

                result = await asyncio.wait_for(call, timeout=self.budget.remaining_seconds())
            else:
                result = await call
            payload = _mcp_payload(result)
            serialized, truncated = _bounded(
                json.dumps(payload, ensure_ascii=False, default=str), self.max_output_chars
            )
            if truncated:
                payload = {"summary": serialized, "truncated": True}
            self.receipts.append(
                {"tool": name, "status": "ok", "truncated": truncated, "chars": len(serialized)}
            )
            return payload if isinstance(payload, dict) else {"results": payload}
        except Exception as exc:
            message = str(exc)
            logger.warning("discover screen YASA tool error tool=%s reason=%s", name, message)
            self.receipts.append({"tool": name, "status": "error", "error": message})
            return {"error": message, "tool": name}


def _mcp_payload(result: Any) -> Any:
    for item in getattr(result, "content", []) or []:
        text = getattr(item, "text", None)
        if not text:
            continue
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            continue
    structured = getattr(result, "structuredContent", None)
    return structured if structured is not None else {}
