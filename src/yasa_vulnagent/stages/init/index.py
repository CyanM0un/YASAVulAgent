from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from langchain_core.tools import StructuredTool


class InitIndex:
    """Run-local FTS5 index over init notes, commits, and patch units."""

    def __init__(self, path: Path, *, reset: bool = True) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        exists = path.is_file()
        self._lock = threading.Lock()
        self._connection = sqlite3.connect(str(path), check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        if reset or not exists:
            self.reset()

    def reset(self) -> None:
        with self._lock:
            self._connection.executescript(
                """
                DROP TABLE IF EXISTS notes_fts;
                DROP TABLE IF EXISTS commits_fts;
                DROP TABLE IF EXISTS units_fts;
                CREATE VIRTUAL TABLE notes_fts USING fts5(
                    note_id UNINDEXED, document_id UNINDEXED, path UNINDEXED, text
                );
                CREATE VIRTUAL TABLE commits_fts USING fts5(
                    sha UNINDEXED, subject, message, changed_paths
                );
                CREATE VIRTUAL TABLE units_fts USING fts5(
                    commit_sha UNINDEXED, unit_id UNINDEXED, kind, summary, paths
                );
                """
            )
            self._connection.commit()

    def upsert_note(self, note: dict[str, Any], source: str = "") -> None:
        note_id = str(note.get("document_id") or "")
        if not note_id:
            return
        text = " ".join(
            [
                str(note.get("summary", "")),
                json.dumps(note.get("facts", []), ensure_ascii=False),
                " ".join(str(item) for item in note.get("unknowns", []) if item),
            ]
        )
        with self._lock:
            self._connection.execute("DELETE FROM notes_fts WHERE note_id = ?", (note_id,))
            self._connection.execute(
                "INSERT INTO notes_fts (note_id, document_id, path, text) VALUES (?, ?, ?, ?)",
                (note_id, note_id, source or str(note.get("source", "")), text),
            )
            self._connection.commit()

    def upsert_commit(self, review: dict[str, Any], changed_paths: list[str] | None = None) -> None:
        sha = str(review.get("commit") or "")
        if not sha:
            return
        with self._lock:
            self._connection.execute("DELETE FROM commits_fts WHERE sha = ?", (sha,))
            self._connection.execute(
                "INSERT INTO commits_fts (sha, subject, message, changed_paths) VALUES (?, ?, ?, ?)",
                (
                    sha,
                    str(review.get("subject") or sha),
                    str(review.get("reason", review.get("message", ""))),
                    " ".join(changed_paths or []),
                ),
            )
            self._connection.commit()

    def upsert_unit(self, commit: str, unit: dict[str, Any]) -> None:
        unit_id = str(unit.get("id") or unit.get("unit_id") or "")
        if not unit_id:
            return
        with self._lock:
            self._connection.execute(
                "DELETE FROM units_fts WHERE commit_sha = ? AND unit_id = ?", (commit, unit_id)
            )
            self._connection.execute(
                "INSERT INTO units_fts (commit_sha, unit_id, kind, summary, paths) VALUES (?, ?, ?, ?, ?)",
                (
                    commit,
                    unit_id,
                    str(unit.get("kind", "")),
                    str(unit.get("summary", "")),
                    " ".join(str(item) for item in unit.get("paths", []) if item),
                ),
            )
            self._connection.commit()

    def search_notes(self, query: str, *, limit: int = 20, offset: int = 0) -> dict[str, Any]:
        return self._search("notes_fts", "note_id, document_id, path", 3, query, limit, offset)

    def search_commits(self, query: str, *, limit: int = 20, offset: int = 0) -> dict[str, Any]:
        return self._search("commits_fts", "sha, subject", 2, query, limit, offset)

    def search_units(self, query: str, *, limit: int = 20, offset: int = 0) -> dict[str, Any]:
        return self._search("units_fts", "commit_sha, unit_id, kind, summary", 4, query, limit, offset)

    def rebuild_documents(self, notes_dir: Path) -> None:
        for path in sorted(notes_dir.glob("*.json")) if notes_dir.is_dir() else []:
            try:
                note = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            self.upsert_note(note)

    def rebuild_history(self, history_dir: Path) -> None:
        reviews_dir = history_dir / "reviews"
        for path in sorted(reviews_dir.glob("*.json")) if reviews_dir.is_dir() else []:
            try:
                review = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            self.upsert_commit(review)
        patches_dir = history_dir / "patches"
        for result_path in sorted(patches_dir.glob("*/result.json")) if patches_dir.is_dir() else []:
            try:
                patch = json.loads(result_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            graph = patch.get("graph") if isinstance(patch.get("graph"), dict) else {}
            commit = str(patch.get("commit") or result_path.parent.name)
            for unit in graph.get("units", []) if isinstance(graph.get("units"), list) else []:
                if isinstance(unit, dict):
                    self.upsert_unit(commit, unit)

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _search(
        self,
        table: str,
        columns: str,
        snippet_index: int,
        query: str,
        limit: int,
        offset: int,
    ) -> dict[str, Any]:
        match = _match_query(query)
        if not match:
            return {"query": query, "results": [], "truncated": False, "next_cursor": None}
        limit = max(1, min(int(limit), 100))
        offset = max(0, int(offset))
        statement = (
            f"SELECT {columns}, snippet({table}, {snippet_index}, '[', ']', '…', 12) AS snippet "
            f"FROM {table} WHERE {table} MATCH ? ORDER BY rank LIMIT ? OFFSET ?"
        )
        try:
            with self._lock:
                rows = self._connection.execute(statement, (match, limit + 1, offset)).fetchall()
        except sqlite3.Error as exc:
            return {"query": query, "results": [], "truncated": False, "error": str(exc)}
        selected = [dict(row) for row in rows[:limit]]
        return {
            "query": query,
            "results": selected,
            "truncated": len(rows) > limit,
            "next_cursor": offset + len(selected) if len(rows) > limit else None,
        }


def retrieval_tools(index: InitIndex) -> list[StructuredTool]:
    """Read-only retrieval tools over the init FTS index."""
    return [
        StructuredTool.from_function(
            func=index.search_notes,
            name="search_notes",
            description="Search document reading notes by keyword.",
        ),
        StructuredTool.from_function(
            func=index.search_commits,
            name="search_commits",
            description="Search historical commits and review reasons by keyword.",
        ),
        StructuredTool.from_function(
            func=index.search_units,
            name="search_units",
            description="Search extracted patch units by keyword.",
        ),
    ]


def _match_query(query: str) -> str:
    terms = [term for term in query.strip().split() if term]
    if not terms:
        return ""
    return " AND ".join('"' + term.replace('"', '""') + '"' for term in terms)
