from __future__ import annotations

import os
import re
import subprocess
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any

from langchain_core.tools import StructuredTool


_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_REVISION_RE = re.compile(r"^(?:HEAD|[0-9a-fA-F]{4,64})$")
_SAFE_PATH_RE = re.compile(r"^[^\x00]*$")
_SUPPORTED_LANGUAGES = {
    ".java": "java",
    ".py": "python",
    ".go": "go",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".php": "php",
}
_SENSITIVE_NAMES = {
    ".env",
    "id_rsa",
    "id_dsa",
    "credentials.json",
    "secrets.json",
    "secrets.yaml",
    "secrets.yml",
    "private_key.pem",
}


class GitToolError(RuntimeError):
    """Raised when a fixed, read-only Git operation cannot be completed."""


class GitToolbox:
    """Structured, read-only Git access bound to one captured repository HEAD."""

    def __init__(
        self,
        repository: Path,
        *,
        captured_head: str | None = None,
        command_timeout: int = 30,
        diff_chars: int = 24000,
        cache_bytes: int = 64_000_000,
    ) -> None:
        self.repository = repository.expanduser().resolve()
        self.command_timeout = max(1, command_timeout)
        self.diff_chars = max(1000, diff_chars)
        self.captured_head = captured_head
        self.cache_bytes = max(0, cache_bytes)
        self._cache: OrderedDict[tuple[Any, ...], tuple[int, Any]] = OrderedDict()
        self._cache_lock = threading.Lock()

    def _run(self, args: list[str], *, timeout: int | None = None) -> str:
        if not self.repository.is_dir():
            raise GitToolError(f"repository is not a directory: {self.repository}")
        environment = {
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_EXTERNAL_DIFF": "",
        }
        try:
            completed = subprocess.run(
                ["git", "--no-pager", *args],
                cwd=self.repository,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=timeout or self.command_timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GitToolError(f"git command failed: {exc}") from exc
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            raise GitToolError(f"git {' '.join(args)} failed: {detail}")
        return completed.stdout

    def snapshot(self) -> dict[str, Any]:
        try:
            inside = self._run(["rev-parse", "--is-inside-work-tree"]).strip()
            if inside != "true":
                return {"available": False, "reason": "not a work tree"}
            head = self._canonicalize(self._run(["rev-parse", "HEAD"]).strip())
            shallow = self._run(["rev-parse", "--is-shallow-repository"]).strip() == "true"
            count = int(self._run(["rev-list", "--count", head]).strip() or "0")
        except (GitToolError, ValueError) as exc:
            return {"available": False, "reason": str(exc)}
        self.captured_head = head
        return {
            "available": True,
            "head": head,
            "shallow": shallow,
            "commit_count": count,
            "parent_policy": "first_parent",
            "read_only": True,
        }

    def _canonicalize(self, revision: str) -> str:
        if not _REVISION_RE.fullmatch(revision.strip()):
            raise GitToolError("revision must be HEAD or a hexadecimal commit id")
        value = self._run(["rev-parse", "--verify", f"{revision}^{{commit}}"]).strip()
        if not _SHA_RE.fullmatch(value):
            raise GitToolError(f"Git returned an invalid commit id: {value!r}")
        return value

    def canonical_commit(self, revision: str) -> str:
        value = self._canonicalize(revision.strip())
        self._ensure_reachable(value)
        return value

    def _ensure_reachable(self, commit: str) -> None:
        if self.captured_head is None:
            self.snapshot()
        if not self.captured_head:
            raise GitToolError("repository HEAD has not been captured")
        try:
            self._run(["merge-base", "--is-ancestor", commit, self.captured_head])
        except GitToolError as exc:
            raise GitToolError(f"commit is outside captured HEAD: {commit}") from exc

    def _parents(self, commit: str) -> list[str]:
        line = self._run(["rev-list", "--parents", "-n", "1", commit]).strip()
        values = line.split()
        return [self._canonicalize(value) for value in values[1:]]

    def commit_details(self, commit: str) -> dict[str, Any]:
        canonical = self.canonical_commit(commit)
        parents = self._parents(canonical)
        body = self._run(["show", "-s", "--format=%B", canonical]).strip()
        subject = self._run(["show", "-s", "--format=%s", canonical]).strip()
        authored = self._run(["show", "-s", "--format=%aI", canonical]).strip()
        return {
            "commit": canonical,
            "parents": parents,
            "parent": parents[0] if parents else None,
            "merge_parent_count": len(parents),
            "subject": subject,
            "message": body,
            "authored_at": authored,
            "parent_policy": "first_parent",
        }

    def search_commits(
        self,
        query: str = "",
        path: str = ".",
        max_results: int = 50,
        cursor: int = 0,
    ) -> dict[str, Any]:
        normalized_path = self._safe_path(path, allow_directory=True)
        if normalized_path is None:
            return {"error": f"path is unavailable: {path}"}
        if self.captured_head is None:
            self.snapshot()
        args = [
            "log",
            self.captured_head or "HEAD",
            "--date=iso-strict",
            "--format=%H%x1f%P%x1f%s%x1f%aI%x1e",
            "--no-renames",
            "--skip=" + str(max(0, cursor)),
            "-n",
            str(max(1, min(max_results, 200)) + 1),
        ]
        if query.strip():
            args.extend(["--regexp-ignore-case", "--grep=" + query.strip()])
        if normalized_path != ".":
            args.extend(["--", normalized_path])
        try:
            output = self._run(args)
        except GitToolError as exc:
            return {"error": str(exc), "commits": []}
        records: list[dict[str, Any]] = []
        for record in output.split("\x1e"):
            fields = record.strip().split("\x1f")
            if len(fields) != 4 or not fields[0]:
                continue
            records.append(
                {
                    "commit": fields[0],
                    "parents": fields[1].split() if fields[1] else [],
                    "subject": fields[2],
                    "authored_at": fields[3],
                }
            )
        limited = records[: max(1, min(max_results, 200))]
        has_more = len(records) > len(limited)
        return {
            "query": query,
            "path": normalized_path,
            "cursor": max(0, cursor),
            "commits": limited,
            "next_cursor": cursor + len(limited) if has_more else None,
            "truncated": has_more,
            "captured_head": self.captured_head,
        }

    def changed_paths(self, commit: str, parent: str | None = None) -> list[dict[str, Any]]:
        canonical = self.canonical_commit(commit)
        actual_parent = parent if parent is not None else self.commit_details(canonical)["parent"]
        if actual_parent is not None:
            actual_parent = self.canonical_commit(actual_parent)
            args = ["diff", "--name-status", "--no-renames", actual_parent, canonical, "--"]
        else:
            args = ["diff-tree", "--root", "--no-commit-id", "--name-status", "-r", canonical, "--"]
        output = _redact_diff(self._run(args))
        paths: list[dict[str, Any]] = []
        for line in output.splitlines():
            fields = line.split("\t", 1)
            if len(fields) != 2:
                continue
            status, path = fields
            if self._safe_path(path) is None:
                paths.append({"status": status, "path": path, "excluded": True, "reason": "unsafe or sensitive path"})
            else:
                paths.append({"status": status, "path": path})
        return paths

    def read_diff(
        self,
        commit: str,
        parent: str | None = None,
        start_char: int = 0,
        max_chars: int | None = None,
    ) -> dict[str, Any]:
        canonical = self.canonical_commit(commit)
        details = self.commit_details(canonical)
        actual_parent = parent if parent is not None else details["parent"]
        if actual_parent is not None:
            actual_parent = self.canonical_commit(actual_parent)
            args = ["diff", "--no-ext-diff", "--no-textconv", "--unified=80", actual_parent, canonical, "--"]
        else:
            args = ["diff-tree", "--root", "--no-commit-id", "-p", "--unified=80", canonical, "--"]
        cache_key = ("diff", canonical, actual_parent, max(0, start_char), max(1000, max_chars or self.diff_chars))
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached
        output = _redact_diff(self._run(args))
        start = max(0, start_char)
        limit = max(1000, max_chars or self.diff_chars)
        text = output[start : start + limit]
        end = start + len(text)
        payload = {
            "commit": canonical,
            "parent": actual_parent,
            "text": text,
            "start_char": start,
            "end_char": end,
            "total_chars": len(output),
            "next_char": end if end < len(output) else None,
            "truncated": end < len(output),
            "changed_paths": self.changed_paths(canonical, actual_parent),
        }
        self._cache_put(cache_key, payload)
        return payload

    def read_revision_file(
        self,
        revision: str,
        path: str,
        start_line: int = 1,
        end_line: int | None = None,
        max_chars: int | None = None,
    ) -> dict[str, Any]:
        canonical = self.canonical_commit(revision)
        safe_path = self._safe_path(path)
        if safe_path is None or safe_path == ".":
            return {"error": f"file path is unavailable: {path}"}
        cache_key = ("file", canonical, safe_path, max(1, start_line), end_line, max_chars)
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached
        try:
            text = self._run(["show", f"{canonical}:{safe_path}"])
        except GitToolError as exc:
            return {"error": str(exc), "revision": canonical, "path": safe_path}
        lines = text.splitlines()
        start = max(1, start_line)
        finish = len(lines) if end_line is None else min(max(start, end_line), len(lines))
        selected: list[str] = []
        used_chars = 0
        limit = max(1000, max_chars or self.diff_chars)
        if start <= len(lines):
            for line in lines[start - 1 : finish]:
                proposed = used_chars + len(line) + (1 if selected else 0)
                if selected and proposed > limit:
                    break
                selected.append(line)
                used_chars = proposed
        actual_end = start + len(selected) - 1 if selected else start - 1
        payload = {
            "revision": canonical,
            "path": safe_path,
            "text": "\n".join(selected),
            "start_line": start,
            "end_line": actual_end,
            "total_lines": len(lines),
            "next_line": actual_end + 1 if actual_end < len(lines) else None,
            "truncated": actual_end < finish,
            "language": language_for_path(safe_path),
        }
        self._cache_put(cache_key, payload)
        return payload

    def search_revision(
        self,
        revision: str,
        query: str,
        path: str = ".",
        max_results: int = 100,
    ) -> dict[str, Any]:
        safe_path = self._safe_path(path, allow_directory=True)
        if safe_path is None:
            return {"error": f"path is unavailable: {path}", "matches": []}
        canonical = self.canonical_commit(revision)
        try:
            paths = [safe_path]
            if safe_path == ".":
                listing = self._run(["ls-tree", "-r", "--name-only", canonical])
                paths = [item for item in listing.splitlines() if self._safe_path(item) is not None]
            matches: list[dict[str, Any]] = []
            for candidate in paths:
                payload = self.read_revision_file(canonical, candidate)
                if "error" in payload:
                    continue
                for offset, line in enumerate(str(payload["text"]).splitlines(), start=payload["start_line"]):
                    if query.lower() in line.lower():
                        matches.append({"revision": canonical, "path": candidate, "line": offset, "text": line[:500]})
                        if len(matches) >= max(1, min(max_results, 500)):
                            return {"revision": canonical, "query": query, "matches": matches, "truncated": True}
            return {"revision": canonical, "query": query, "matches": matches, "truncated": False}
        except GitToolError as exc:
            return {"error": str(exc), "matches": []}

    def langchain_tools(self) -> list[StructuredTool]:
        return [
            StructuredTool.from_function(
                self.search_commits,
                name="git_search_commits",
                description="Search commits reachable from the captured HEAD. Read-only and paginated.",
            ),
            StructuredTool.from_function(
                self.commit_details,
                name="git_commit_details",
                description="Read structured metadata for one commit reachable from the captured HEAD.",
            ),
            StructuredTool.from_function(
                self.read_diff,
                name="git_read_diff",
                description="Read a bounded diff chunk for a commit and its fixed first parent.",
            ),
            StructuredTool.from_function(
                self.changed_paths,
                name="git_changed_paths",
                description="List paths changed by a commit without renames.",
            ),
            StructuredTool.from_function(
                self.read_revision_file,
                name="git_read_revision_file",
                description="Read a bounded line range from a file at a historical revision.",
            ),
            StructuredTool.from_function(
                self.search_revision,
                name="git_search_revision",
                description="Search text in files at one historical revision.",
            ),
        ]

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
            size = len(str(value))
        except Exception:
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

    def _safe_path(self, path: str, *, allow_directory: bool = False) -> str | None:
        if not isinstance(path, str) or not _SAFE_PATH_RE.fullmatch(path):
            return None
        normalized = path.replace("\\", "/").strip()
        if normalized in {"", "."}:
            return "."
        if normalized.startswith("/") or normalized.startswith("~"):
            return None
        parts = Path(normalized).parts
        if ".." in parts:
            return None
        if _is_sensitive_path(normalized):
            return None
        if not allow_directory and normalized.endswith("/"):
            return None
        return normalized.removeprefix("./")


def language_for_path(path: str) -> str | None:
    return _SUPPORTED_LANGUAGES.get(Path(path).suffix.lower())


def is_supported_source(path: str) -> bool:
    return language_for_path(path) is not None


def _is_sensitive_path(path: str) -> bool:
    basename = Path(path).name.lower()
    return basename in _SENSITIVE_NAMES or basename.startswith(".env.")


def _redact_diff(diff: str) -> str:
    """Drop sensitive file sections before a diff can reach prompts or artifacts."""
    sections = diff.split("diff --git ")
    if len(sections) == 1:
        return diff
    rendered: list[str] = [sections[0]]
    for section in sections[1:]:
        header = section.splitlines()[0] if section.splitlines() else ""
        paths = header.split()
        if any(_is_sensitive_path(item.removeprefix("a/").removeprefix("b/")) for item in paths[:2]):
            rendered.append("[sensitive diff section redacted]\n")
        else:
            rendered.append("diff --git " + section)
    return "".join(rendered)
