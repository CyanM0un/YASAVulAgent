from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


_SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
    path TEXT PRIMARY KEY,
    size INTEGER NOT NULL DEFAULT 0,
    fingerprint TEXT NOT NULL DEFAULT '',
    content_type TEXT NOT NULL DEFAULT 'unknown',
    kind TEXT NOT NULL DEFAULT 'unknown',
    usage_hint TEXT NOT NULL DEFAULT 'production-candidate',
    source_origin TEXT NOT NULL DEFAULT '',
    large INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending',
    error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_files_usage_status ON files(usage_hint, content_type, status, path);

CREATE TABLE IF NOT EXISTS excluded_files (
    path TEXT PRIMARY KEY,
    reason TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
    task_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    wave INTEGER NOT NULL DEFAULT 0,
    view TEXT NOT NULL DEFAULT '',
    independent INTEGER NOT NULL DEFAULT 0,
    coverage_required INTEGER NOT NULL DEFAULT 1,
    scope_type TEXT NOT NULL DEFAULT 'production-text',
    scope_prefix TEXT NOT NULL DEFAULT '',
    scope_count INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0,
    priority TEXT NOT NULL DEFAULT 'normal',
    artifact_dir TEXT NOT NULL DEFAULT '',
    payload TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_tasks_status_kind ON tasks(status, kind, wave, task_id);

CREATE TABLE IF NOT EXISTS task_scope_paths (
    task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    PRIMARY KEY(task_id, path)
);
CREATE INDEX IF NOT EXISTS idx_task_scope_path ON task_scope_paths(task_id, path);

CREATE TABLE IF NOT EXISTS read_receipts (
    receipt_id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    start_line INTEGER NOT NULL DEFAULT 0,
    end_line INTEGER NOT NULL DEFAULT 0,
    total_lines INTEGER NOT NULL DEFAULT 0,
    truncated INTEGER NOT NULL DEFAULT 0,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_receipts_task_path ON read_receipts(task_id, path, start_line, end_line);

CREATE TABLE IF NOT EXISTS entries (
    entry_id TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'candidate',
    payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS gaps (
    message TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS warnings (
    message TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS dispositions (
    debt_id TEXT PRIMARY KEY,
    debt_type TEXT NOT NULL,
    ref_id TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT NOT NULL,
    owner TEXT NOT NULL,
    evidence_refs TEXT NOT NULL,
    source TEXT NOT NULL,
    created_at TEXT NOT NULL,
    confirm_task_id TEXT NOT NULL DEFAULT '',
    consumed_at TEXT NOT NULL DEFAULT '',
    reopen_condition TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS mechanisms (
    mechanism_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'unknown',
    definition_path TEXT NOT NULL DEFAULT '',
    line_start INTEGER NOT NULL DEFAULT 0,
    line_end INTEGER NOT NULL DEFAULT 0,
    evidence_refs TEXT NOT NULL DEFAULT '[]',
    query_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'observed',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS feature_queries (
    query_id TEXT PRIMARY KEY,
    mechanism_id TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    regex INTEGER NOT NULL DEFAULT 0,
    scope TEXT NOT NULL DEFAULT '[]',
    cursor INTEGER NOT NULL DEFAULT 0,
    returned INTEGER NOT NULL DEFAULT 0,
    truncated INTEGER NOT NULL DEFAULT 0,
    complete INTEGER NOT NULL DEFAULT 0,
    limitations TEXT NOT NULL DEFAULT '[]',
    errors TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    payload TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS feature_hits (
    hit_id TEXT PRIMARY KEY,
    query_id TEXT NOT NULL DEFAULT '',
    mechanism_id TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL,
    line_start INTEGER NOT NULL DEFAULT 0,
    line_end INTEGER NOT NULL DEFAULT 0,
    candidate_id TEXT NOT NULL DEFAULT '',
    confirm_task_id TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_feature_hits_candidate ON feature_hits(candidate_id);

CREATE TABLE IF NOT EXISTS task_notes (
    note_id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
    key TEXT NOT NULL DEFAULT '',
    text TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_task_notes_task ON task_notes(task_id, note_id);
"""


class DiscoverLedger:
    """A small, run-local SQLite ledger for discover's growing collections."""

    def __init__(self, path: Path, connection: sqlite3.Connection) -> None:
        self.path = path
        self._connection = connection
        self._owner = threading.get_ident()
        self._local = threading.local()
        self._thread_connections: list[sqlite3.Connection] = []
        self._lock = threading.RLock()

    @classmethod
    def open(cls, path: Path) -> "DiscoverLedger":
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(
            path,
            timeout=30,
            check_same_thread=False,
        )
        connection.row_factory = sqlite3.Row
        connection.executescript(_SCHEMA)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.commit()
        return cls(path, connection)

    @property
    def connection(self) -> sqlite3.Connection:
        """Return this thread's connection.

        Screen task graphs run their sync nodes in a worker thread, so several
        threads share one ledger. A sqlite3 connection is not thread-safe: every
        thread gets its own connection to the same WAL database instead.
        """
        if threading.get_ident() == self._owner:
            return self._connection
        connection = getattr(self._local, "connection", None)
        if connection is not None:
            return connection
        connection = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        self._local.connection = connection
        with self._lock:
            self._thread_connections.append(connection)
        return connection

    def close(self) -> None:
        with self._lock:
            for connection in self._thread_connections:
                try:
                    connection.close()
                except sqlite3.Error:
                    pass
            self._thread_connections.clear()
        self._connection.close()

    def __enter__(self) -> "DiscoverLedger":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                self.connection.execute("BEGIN")
                yield self.connection
            except Exception:
                self.connection.rollback()
                raise
            else:
                self.connection.commit()

    def replace_inventory(
        self,
        files: list[dict[str, Any]],
        excluded: list[dict[str, Any]],
    ) -> dict[str, int]:
        """Replace inventory metadata while preserving prior review progress."""
        current_paths = {str(item.get("path", "")) for item in files if item.get("path")}
        with self.transaction() as connection:
            for item in files:
                path = str(item["path"])
                old = connection.execute(
                    "SELECT status, error FROM files WHERE path = ?", (path,)
                ).fetchone()
                status = str(old["status"]) if old is not None else str(item.get("status", "pending"))
                error = str(old["error"]) if old is not None else str(item.get("error", ""))
                connection.execute(
                    """
                    INSERT INTO files(
                        path, size, fingerprint, content_type, kind, usage_hint,
                        source_origin, large, status, error
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(path) DO UPDATE SET
                        size=excluded.size,
                        fingerprint=excluded.fingerprint,
                        content_type=excluded.content_type,
                        kind=excluded.kind,
                        usage_hint=excluded.usage_hint,
                        source_origin=excluded.source_origin,
                        large=excluded.large,
                        status=excluded.status,
                        error=excluded.error
                    """,
                    (
                        path,
                        int(item.get("size", 0)),
                        str(item.get("fingerprint", "")),
                        str(item.get("content_type", "unknown")),
                        str(item.get("kind", "unknown")),
                        str(item.get("usage_hint", "production-candidate")),
                        str(item.get("source_origin", "")),
                        int(bool(item.get("large", False))),
                        status,
                        error,
                    ),
                )
            existing_paths = [
                str(row["path"])
                for row in connection.execute("SELECT path FROM files")
            ]
            stale_paths = [path for path in existing_paths if path not in current_paths]
            connection.executemany("DELETE FROM files WHERE path = ?", [(path,) for path in stale_paths])
            connection.execute("DELETE FROM excluded_files")
            connection.executemany(
                "INSERT INTO excluded_files(path, reason) VALUES (?, ?)",
                [
                    (str(item.get("path", "")), str(item.get("reason", "")))
                    for item in excluded
                    if item.get("path")
                ],
            )
        return {
            "file_count": self.file_count(),
            "excluded_count": self.connection.execute(
                "SELECT COUNT(*) FROM excluded_files"
            ).fetchone()[0],
        }

    def file_count(self) -> int:
        return int(self.connection.execute("SELECT COUNT(*) FROM files").fetchone()[0])

    def excluded_count(self) -> int:
        return int(self.connection.execute("SELECT COUNT(*) FROM excluded_files").fetchone()[0])

    def file_counts(self) -> dict[str, int]:
        rows = self.connection.execute(
            "SELECT status, COUNT(*) AS count FROM files GROUP BY status"
        ).fetchall()
        counts = {str(row["status"]): int(row["count"]) for row in rows}
        counts["total"] = sum(counts.values())
        counts["production_text"] = int(
            self.connection.execute(
                """
                SELECT COUNT(*) FROM files
                WHERE usage_hint = 'production-candidate' AND content_type = 'text'
                  AND status != 'unavailable'
                """
            ).fetchone()[0]
        )
        counts["screened"] = int(
            self.connection.execute(
                "SELECT COUNT(*) FROM files WHERE status = 'screened'"
            ).fetchone()[0]
        )
        counts["covered"] = counts["screened"] + int(
            self.connection.execute(
                "SELECT COUNT(*) FROM files WHERE status = 'candidate'"
            ).fetchone()[0]
        )
        return counts

    def iter_files(self, *, after: str = "", limit: int = 500) -> Iterator[dict[str, Any]]:
        cursor = str(after)
        page_size = max(1, int(limit))
        while True:
            rows = self.connection.execute(
                """
                SELECT path, size, fingerprint, content_type, kind, usage_hint,
                       source_origin, large, status, error
                FROM files WHERE path > ? ORDER BY path LIMIT ?
                """,
                (cursor, page_size),
            ).fetchall()
            if not rows:
                return
            for row in rows:
                yield _file_from_row(row)
            cursor = str(rows[-1]["path"])
            if len(rows) < page_size:
                return

    def get_file(self, path: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            """
            SELECT path, size, fingerprint, content_type, kind, usage_hint,
                   source_origin, large, status, error
            FROM files WHERE path = ?
            """,
            (str(path),),
        ).fetchone()
        return _file_from_row(row) if row is not None else None

    def set_file_status(self, path: str, status: str, *, error: str = "") -> None:
        self.connection.execute(
            "UPDATE files SET status = ?, error = ? WHERE path = ?",
            (status, error, str(path)),
        )
        self.connection.commit()

    def eligible_paths(
        self,
        *,
        after: str = "",
        limit: int = 500,
        uncovered_only: bool = False,
    ) -> list[str]:
        conditions = [
            "path > ?",
            "usage_hint = 'production-candidate'",
            "content_type = 'text'",
            "status != 'unavailable'",
        ]
        values: list[Any] = [after]
        if uncovered_only:
            conditions.append("status NOT IN ('screened', 'candidate')")
        rows = self.connection.execute(
            "SELECT path FROM files WHERE "
            + " AND ".join(conditions)
            + " ORDER BY path LIMIT ?",
            (*values, max(1, int(limit))),
        ).fetchall()
        return [str(row["path"]) for row in rows]

    def disposition_rows(self, *, status: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT debt_id, debt_type, ref_id, status, reason, owner, evidence_refs, source, created_at, confirm_task_id, consumed_at, reopen_condition FROM dispositions"
        values: list[Any] = []
        if status:
            query += " WHERE status = ?"
            values.append(status)
        query += " ORDER BY debt_id"
        rows = []
        for row in self.connection.execute(query, values):
            item = dict(row)
            try:
                evidence = json.loads(str(item.get("evidence_refs", "[]")))
            except json.JSONDecodeError:
                evidence = []
            item["evidence_refs"] = evidence if isinstance(evidence, list) else []
            rows.append(item)
        return rows

    def put_disposition(
        self,
        *,
        debt_id: str,
        debt_type: str,
        ref_id: str,
        status: str,
        reason: str,
        owner: str,
        evidence_refs: list[str],
        source: str,
        confirm_task_id: str = "",
        consumed_at: str = "",
        reopen_condition: str = "",
    ) -> None:
        from ...storage import utc_now

        self.connection.execute(
            """
            INSERT INTO dispositions(
                debt_id, debt_type, ref_id, status, reason, owner, evidence_refs,
                source, created_at, confirm_task_id, consumed_at, reopen_condition
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(debt_id) DO UPDATE SET
                debt_type=excluded.debt_type,
                ref_id=excluded.ref_id,
                status=excluded.status,
                reason=excluded.reason,
                owner=excluded.owner,
                evidence_refs=excluded.evidence_refs,
                source=excluded.source,
                created_at=excluded.created_at,
                confirm_task_id=excluded.confirm_task_id,
                consumed_at=excluded.consumed_at,
                reopen_condition=excluded.reopen_condition
            """,
            (
                str(debt_id),
                str(debt_type),
                str(ref_id),
                str(status),
                str(reason),
                str(owner),
                json.dumps([str(item) for item in evidence_refs], ensure_ascii=False),
                str(source),
                utc_now(),
                str(confirm_task_id),
                str(consumed_at),
                str(reopen_condition),
            ),
        )
        self.connection.commit()

    def retire_exhausted_tasks(
        self, tasks: list[dict[str, Any]], *, max_attempts: int
    ) -> list[dict[str, Any]]:
        """Drop tasks that exhausted their attempts, recording why instead of silently looping."""
        active: list[dict[str, Any]] = []
        for task in tasks:
            task_id = str(task.get("task_id", ""))
            if int(task.get("attempts", 0)) < max_attempts:
                active.append(task)
                continue
            task["status"] = "deferred"
            self.put_task(task)
            self.put_disposition(
                debt_id=f"task:{task_id}",
                debt_type="task",
                ref_id=task_id,
                status="deferred",
                reason="attempt_limit",
                owner="discover",
                evidence_refs=[],
                source="attempt_limit",
                reopen_condition="split the task or raise TASK_MAX_ATTEMPTS",
            )
        return active

    def _json_value(self, value: Any, default: Any) -> Any:
        if isinstance(value, (list, dict)):
            return value
        try:
            decoded = json.loads(str(value))
        except (TypeError, json.JSONDecodeError):
            return default
        return decoded if isinstance(decoded, type(default)) else default

    def task_scope_paths(self, task_id: str) -> list[str]:
        return [
            str(row["path"])
            for row in self.connection.execute(
                "SELECT path FROM task_scope_paths WHERE task_id = ? ORDER BY path",
                (str(task_id),),
            )
        ]

    def put_evidence(self, evidence: dict[str, Any]) -> None:
        evidence_id = str(evidence.get("evidence_id", ""))
        if not evidence_id:
            raise ValueError("discover evidence requires evidence_id")
        self.connection.execute(
            "INSERT OR REPLACE INTO evidence(evidence_id, payload) VALUES (?, ?)",
            (evidence_id, json.dumps(dict(evidence), ensure_ascii=False, default=str)),
        )
        self.connection.commit()

    def get_entry(self, entry_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT payload FROM entries WHERE entry_id = ?", (str(entry_id),)
        ).fetchone()
        return json.loads(str(row["payload"])) if row is not None else None

    def put_entry(self, entry: dict[str, Any]) -> None:
        entry_id = str(entry.get("entry_id", ""))
        if not entry_id:
            raise ValueError("discover entry requires entry_id")
        status = str(entry.get("status", "candidate"))
        payload = dict(entry)
        payload["entry_id"] = entry_id
        payload["status"] = status
        self.connection.execute(
            "INSERT OR REPLACE INTO entries(entry_id, status, payload) VALUES (?, ?, ?)",
            (
                entry_id,
                status,
                json.dumps(payload, ensure_ascii=False, default=str),
            ),
        )
        self.connection.commit()

    def update_entry(
        self,
        entry_id: str,
        *,
        status: str | None = None,
        updates: dict[str, Any] | None = None,
        evidence: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        existing = self.get_entry(entry_id) or {"entry_id": str(entry_id)}
        value = dict(existing)
        value.update(updates or {})
        if status:
            value["status"] = str(status)
        refs = [str(item) for item in value.get("evidence_refs", []) if str(item).strip()]
        for item in evidence or []:
            evidence_id = str(item.get("evidence_id", ""))
            if not evidence_id:
                continue
            self.put_evidence(item)
            if evidence_id not in refs:
                refs.append(evidence_id)
        value["evidence_refs"] = refs
        self.put_entry(value)
        return value

    def evidence_exists(self, evidence_id: str) -> bool:
        return self.get_evidence(evidence_id) is not None

    def get_evidence(self, evidence_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT payload FROM evidence WHERE evidence_id = ?", (str(evidence_id),)
        ).fetchone()
        if row is None:
            return None
        value = json.loads(str(row["payload"]))
        return value if isinstance(value, dict) else None

    def put_mechanism(self, mechanism: dict[str, Any]) -> None:
        mechanism_id = str(mechanism.get("mechanism_id", ""))
        if not mechanism_id:
            raise ValueError("discover mechanism requires mechanism_id")
        self.connection.execute(
            """
            INSERT INTO mechanisms(
                mechanism_id, kind, name, role, definition_path, line_start,
                line_end, evidence_refs, query_id, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(mechanism_id) DO UPDATE SET
                role=excluded.role,
                evidence_refs=excluded.evidence_refs,
                query_id=excluded.query_id,
                status=excluded.status
            """,
            (
                mechanism_id,
                str(mechanism.get("kind", "unknown")),
                str(mechanism.get("name", "")),
                str(mechanism.get("role", "unknown")),
                str(mechanism.get("definition_path", "")),
                int(mechanism.get("line_start", 0)),
                int(mechanism.get("line_end", 0)),
                json.dumps(
                    [str(item) for item in mechanism.get("evidence_refs", [])],
                    ensure_ascii=False,
                ),
                str(mechanism.get("query_id", "")),
                str(mechanism.get("status", "observed")),
                str(mechanism.get("created_at", "")),
            ),
        )
        self.connection.commit()

    def mechanism_rows(self, *, status: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM mechanisms"
        values: list[Any] = []
        if status:
            query += " WHERE status = ?"
            values.append(str(status))
        query += " ORDER BY mechanism_id"
        result: list[dict[str, Any]] = []
        for row in self.connection.execute(query, values):
            item = dict(row)
            item["evidence_refs"] = self._json_value(item.get("evidence_refs"), [])
            result.append(item)
        return result

    def delete_mechanism(self, mechanism_id: str) -> None:
        self.connection.execute(
            "DELETE FROM mechanisms WHERE mechanism_id = ?", (str(mechanism_id),)
        )
        self.connection.commit()

    def get_mechanism(self, mechanism_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM mechanisms WHERE mechanism_id = ?", (str(mechanism_id),)
        ).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["evidence_refs"] = self._json_value(item.get("evidence_refs"), [])
        return item

    def put_query(self, query: dict[str, Any]) -> None:
        query_id = str(query.get("query_id", ""))
        if not query_id:
            raise ValueError("discover feature query requires query_id")
        self.connection.execute(
            """
            INSERT OR REPLACE INTO feature_queries(
                query_id, mechanism_id, kind, target, regex, scope, cursor,
                returned, truncated, complete, limitations, errors, created_at, payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                query_id,
                str(query.get("mechanism_id", "")),
                str(query.get("kind", "text")),
                str(query.get("target", "")),
                int(bool(query.get("regex", False))),
                json.dumps(query.get("scope", []), ensure_ascii=False, default=str),
                int(query.get("cursor", 0)),
                int(query.get("returned", 0)),
                int(bool(query.get("truncated", False))),
                int(bool(query.get("complete", False))),
                json.dumps(query.get("limitations", []), ensure_ascii=False, default=str),
                json.dumps(query.get("errors", []), ensure_ascii=False, default=str),
                str(query.get("created_at", "")),
                json.dumps(query, ensure_ascii=False, default=str),
            ),
        )
        self.connection.commit()

    def query_rows(self) -> list[dict[str, Any]]:
        return [
            self._json_value(row["payload"], {})
            for row in self.connection.execute(
                "SELECT payload FROM feature_queries ORDER BY query_id"
            )
        ]

    def incomplete_queries(self) -> list[dict[str, Any]]:
        return [
            item
            for item in self.query_rows()
            if not bool(item.get("complete", False))
        ]

    def put_hit(self, hit: dict[str, Any]) -> None:
        hit_id = str(hit.get("hit_id", ""))
        if not hit_id:
            raise ValueError("discover feature hit requires hit_id")
        self.connection.execute(
            """
            INSERT OR REPLACE INTO feature_hits(
                hit_id, query_id, mechanism_id, path, line_start, line_end,
                candidate_id, confirm_task_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                hit_id,
                str(hit.get("query_id", "")),
                str(hit.get("mechanism_id", "")),
                str(hit.get("path", "")),
                int(hit.get("line_start", 0)),
                int(hit.get("line_end", 0)),
                str(hit.get("candidate_id", "")),
                str(hit.get("confirm_task_id", "")),
                str(hit.get("created_at", "")),
            ),
        )
        self.connection.commit()

    def hit_rows(self) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.connection.execute(
                "SELECT * FROM feature_hits ORDER BY hit_id"
            )
        ]

    def hits_without_tasks(self) -> list[dict[str, Any]]:
        covered: set[str] = set()
        for task in self.list_tasks(kind_prefix="confirm"):
            covered.update(str(item) for item in task.get("candidate_ids", []))
        return [
            item
            for item in self.hit_rows()
            if not item.get("candidate_id")
            or (
                not item.get("confirm_task_id")
                and str(item.get("candidate_id", "")) not in covered
            )
        ]

    def count_mechanisms(self) -> int:
        return int(
            self.connection.execute("SELECT COUNT(*) FROM mechanisms").fetchone()[0]
        )

    def count_feature_queries(self) -> int:
        return int(
            self.connection.execute("SELECT COUNT(*) FROM feature_queries").fetchone()[0]
        )

    def count_feature_hits(self) -> int:
        return int(
            self.connection.execute("SELECT COUNT(*) FROM feature_hits").fetchone()[0]
        )

    def open_handoffs(self) -> list[dict[str, Any]]:
        return [
            item
            for item in self.disposition_rows(status="handoff_to_confirm")
            if not item.get("consumed_at")
        ]

    def mark_handoff_consumed(self, debt_id: str, confirm_task_id: str) -> None:
        from ...storage import utc_now

        self.connection.execute(
            "UPDATE dispositions SET confirm_task_id = ?, consumed_at = ? WHERE debt_id = ?",
            (str(confirm_task_id), utc_now(), str(debt_id)),
        )
        self.connection.commit()

    def ensure_confirm_task(
        self,
        *,
        path: str,
        candidate_ids: list[str],
        origin: str = "candidate",
        question: str = "",
        artifact_dir: str = "",
        wave: int = 0,
        exclude_task_id: str = "",
        max_candidates: int = 8,
    ) -> str:
        normalized_path = str(path).removeprefix("./")
        ids = sorted({str(item) for item in candidate_ids if str(item).strip()})
        for task in self.list_tasks(
            statuses={"pending", "partial", "running"}, kind_prefix="confirm"
        ):
            task_id = str(task.get("task_id", ""))
            if task_id and task_id == str(exclude_task_id):
                continue
            if not self.path_allowed(task_id, normalized_path):
                continue
            existing = [str(item) for item in task.get("candidate_ids", [])]
            merged = sorted(set(existing) | set(ids))
            if merged == existing:
                return task_id
            if len(existing) >= max(1, int(max_candidates)) and set(ids) - set(existing):
                continue
            task["candidate_ids"] = merged
            self.put_task(task)
            self._link_hits(task_id, merged)
            return task_id
        task_id = f"confirm-{_next_number(self.list_tasks(), 'confirm'):04d}"
        task = {
            "task_id": task_id,
            "kind": "confirm",
            "status": "pending",
            "origin": str(origin),
            "candidate_ids": ids,
            "question": question
            or f"Verify the candidate entry(s) in {normalized_path}.",
            "reason": "confirm queue",
            "attempts": 0,
            "wave": int(wave),
            "view": "confirm",
            "independent": False,
            "coverage_required": False,
            "scope_type": "explicit",
            "scope_paths": [normalized_path],
            "scope_count": 1,
            "read_ranges": [],
            "tool_receipts": [],
            "candidates": [],
            "negative_results": [],
            "unknowns": [],
            "deferred": [],
            "deferred_items": [],
            "follow_up": [],
            "entry_results": [],
            "feature_observations": [],
            "same_file_reviewed": False,
            "artifact_dir": str(artifact_dir),
        }
        self.put_task(task)
        self._link_hits(task_id, ids)
        return task_id

    def _link_hits(self, task_id: str, candidate_ids: list[str]) -> None:
        if not candidate_ids:
            return
        placeholders = ",".join("?" for _ in candidate_ids)
        self.connection.execute(
            f"UPDATE feature_hits SET confirm_task_id = ? "
            f"WHERE confirm_task_id = '' AND candidate_id IN ({placeholders})",
            (str(task_id), *[str(item) for item in candidate_ids]),
        )
        self.connection.commit()

    def ensure_screen_task(
        self,
        *,
        paths: list[str],
        question: str,
        reason: str = "",
        origin: str = "confirm_scope",
        parent_task_id: str = "",
        follow_up_key: str = "",
        artifact_dir: str = "",
        wave: int = 0,
        coverage_required: bool = True,
    ) -> str:
        normalized = sorted(
            {str(path).removeprefix("./") for path in paths if str(path).strip()}
        )
        if not normalized:
            raise ValueError("screen task requires paths")
        for task in self.list_tasks(
            statuses={"pending", "partial", "running", "complete"},
            kind_prefix="screen",
        ):
            if (
                str(task.get("origin", "")) == str(origin)
                and (
                    not follow_up_key
                    or str(task.get("follow_up_key", "")) == str(follow_up_key)
                )
                and sorted(
                    str(path) for path in task.get("scope_paths", task.get("paths", []))
                )
                == normalized
            ):
                return str(task.get("task_id", ""))
        task_id = f"screen-{_next_number(self.list_tasks(), 'screen'):04d}"
        task = {
            "task_id": task_id,
            "kind": "screen_follow_up",
            "status": "pending",
            "origin": str(origin),
            "parent_task_id": str(parent_task_id),
            "follow_up_key": str(follow_up_key),
            "question": str(question),
            "reason": str(reason),
            "attempts": 0,
            "wave": int(wave),
            "view": "follow-up",
            "independent": False,
            "coverage_required": bool(coverage_required),
            "scope_type": "explicit",
            "scope_paths": normalized,
            "scope_count": len(normalized),
            "read_ranges": [],
            "tool_receipts": [],
            "candidates": [],
            "negative_results": [],
            "unknowns": [],
            "deferred": [],
            "deferred_items": [],
            "follow_up": [],
            "feature_observations": [],
            "artifact_dir": str(artifact_dir),
        }
        self.put_task(task)
        return task_id

    def disposition_count(self, status: str | None = None) -> int:
        if status:
            return int(
                self.connection.execute(
                    "SELECT COUNT(*) FROM dispositions WHERE status = ?", (status,)
                ).fetchone()[0]
            )
        return int(self.connection.execute("SELECT COUNT(*) FROM dispositions").fetchone()[0])

    def debt_items(self) -> list[dict[str, Any]]:
        """Return open work not closed by a disposition or screened file."""
        disposed = {
            str(row["debt_id"])
            for row in self.connection.execute("SELECT debt_id FROM dispositions")
        }
        items: list[dict[str, Any]] = []
        candidate_paths = {
            str((entry.get("location") or {}).get("path", ""))
            for entry in self.entries(status="candidate")
        }
        terminal_paths = {
            str((entry.get("location") or {}).get("path", ""))
            for entry in self.entries()
            if str(entry.get("status", "")) in {"confirmed", "not_applicable", "unknown", "deferred"}
        }
        for row in self.connection.execute(
            """
            SELECT path, size, status, kind, usage_hint, content_type
            FROM files
            WHERE usage_hint = 'production-candidate' AND content_type = 'text'
              AND status != 'unavailable'
            ORDER BY path
            """
        ):
            path = str(row["path"])
            status = str(row["status"])
            if status == "screened":
                continue
            if status == "candidate" and path in candidate_paths:
                continue
            if path in terminal_paths and path not in candidate_paths:
                continue
            debt_id = f"file:{path}"
            if debt_id in disposed:
                continue
            items.append(
                {
                    "debt_id": debt_id,
                    "debt_type": "file",
                    "ref_id": path,
                    "path": path,
                    "size": int(row["size"]),
                    "status": status,
                    "kind": str(row["kind"]),
                }
            )
        for entry in self.entries(status="candidate"):
            entry_id = str(entry.get("entry_id", ""))
            debt_id = f"candidate:{entry_id}"
            if not entry_id or debt_id in disposed:
                continue
            location = entry.get("location") if isinstance(entry.get("location"), dict) else {}
            items.append(
                {
                    "debt_id": debt_id,
                    "debt_type": "candidate",
                    "ref_id": entry_id,
                    "path": str(location.get("path", "")),
                    "line_start": location.get("line_start"),
                    "line_end": location.get("line_end"),
                    "status": "candidate",
                    "kind": str(entry.get("kind", "candidate")),
                }
            )
        for task in self.list_tasks(statuses={"pending", "running", "partial"}):
            task_id = str(task.get("task_id", ""))
            debt_id = f"task:{task_id}"
            if not task_id or debt_id in disposed:
                continue
            items.append(
                {
                    "debt_id": debt_id,
                    "debt_type": "task",
                    "ref_id": task_id,
                    "status": str(task.get("status", "")),
                    "kind": str(task.get("kind", "")),
                    "question": str(task.get("question", "")),
                    "error": str(task.get("error", "")),
                }
            )
        follow_up_keys = {
            str(task.get("follow_up_key", ""))
            for task in self.list_tasks()
            if task.get("follow_up_key")
        }
        for task in self.list_tasks(statuses={"complete"}, kind_prefix="screen"):
            task_id = str(task.get("task_id", ""))
            scope_paths = self.task_scope_paths(task_id)
            for index, item in enumerate(_task_follow_up_items(task, scope_paths)):
                key = str(item.get("follow_up_key", "")) or _follow_up_key(task_id, index, item)
                debt_id = f"followup:{key}"
                if debt_id in disposed or key in follow_up_keys:
                    continue
                items.append(
                    {
                        "debt_id": debt_id,
                        "debt_type": "followup",
                        "ref_id": task_id,
                        "task_id": task_id,
                        "follow_up_key": key,
                        "paths": item.get("paths", scope_paths),
                        "question": str(item.get("question", "")),
                        "reason": str(item.get("reason", "")),
                        "status": "open",
                    }
                )
            for index, item in enumerate(task.get("deferred_items", [])):
                if not isinstance(item, dict):
                    continue
                debt_id = f"task_deferred:{task_id}:{index}"
                if debt_id in disposed:
                    continue
                items.append(
                    {
                        "debt_id": debt_id,
                        "debt_type": "task_deferred",
                        "ref_id": task_id,
                        "task_id": task_id,
                        "paths": item.get("paths", scope_paths),
                        "reason": str(item.get("reason", "")),
                        "reopen_condition": str(item.get("reopen_condition", "")),
                    }
                )
        query_mechanisms = {
            str(query.get("mechanism_id", ""))
            for query in self.query_rows()
            if query.get("mechanism_id")
        }
        for mechanism in self.mechanism_rows():
            mechanism_id = str(mechanism.get("mechanism_id", ""))
            if not mechanism_id or mechanism_id in query_mechanisms:
                continue
            debt_id = f"mechanism:{mechanism_id}"
            if debt_id in disposed:
                continue
            items.append(
                {
                    "debt_id": debt_id,
                    "debt_type": "mechanism",
                    "ref_id": mechanism_id,
                    "path": str(mechanism.get("definition_path", "")),
                    "kind": str(mechanism.get("kind", "")),
                    "name": str(mechanism.get("name", "")),
                }
            )
        for query in self.incomplete_queries():
            query_id = str(query.get("query_id", ""))
            debt_id = f"query:{query_id}"
            if not query_id or debt_id in disposed:
                continue
            mechanism = self.get_mechanism(str(query.get("mechanism_id", ""))) or {}
            items.append(
                {
                    "debt_id": debt_id,
                    "debt_type": "query",
                    "ref_id": query_id,
                    "mechanism_id": str(query.get("mechanism_id", "")),
                    "path": str(mechanism.get("definition_path", "")),
                    "line_start": mechanism.get("line_start"),
                    "line_end": mechanism.get("line_end"),
                    "truncated": bool(query.get("truncated", False)),
                    "limitations": query.get("limitations", []),
                }
            )
        for hit in self.hits_without_tasks():
            hit_id = str(hit.get("hit_id", ""))
            debt_id = f"hit:{hit_id}"
            if not hit_id or debt_id in disposed:
                continue
            items.append(
                {
                    "debt_id": debt_id,
                    "debt_type": "hit",
                    "ref_id": hit_id,
                    "path": str(hit.get("path", "")),
                    "line_start": hit.get("line_start"),
                    "line_end": hit.get("line_end"),
                }
            )
        for disposition in self.open_handoffs():
            debt_id = f"handoff:{disposition.get('debt_id', '')}"
            if debt_id in disposed:
                continue
            items.append(
                {
                    "debt_id": debt_id,
                    "debt_type": "handoff",
                    "ref_id": str(disposition.get("ref_id", "")),
                    "disposition_debt_id": str(disposition.get("debt_id", "")),
                    "reason": str(disposition.get("reason", "")),
                }
            )
        return sorted(items, key=lambda item: str(item["debt_id"]))

    def debt_count(self) -> int:
        return len(self.debt_items())

    def feature_debt_count(self) -> int:
        return sum(
            1
            for item in self.debt_items()
            if item.get("debt_type") in {"mechanism", "query", "hit"}
        )

    def task_count(self) -> int:
        return int(self.connection.execute("SELECT COUNT(*) FROM tasks").fetchone()[0])

    def pending_task_count(self) -> int:
        return int(
            self.connection.execute(
                "SELECT COUNT(*) FROM tasks WHERE status IN ('pending', 'running', 'partial')"
            ).fetchone()[0]
        )

    def open_task_count(self) -> int:
        return sum(1 for item in self.debt_items() if item.get("debt_type") == "task")

    def close_task(self, task_id: str) -> None:
        self.connection.execute(
            "UPDATE tasks SET status = 'closed' WHERE task_id = ?", (str(task_id),)
        )
        self.connection.commit()

    def recover_running_tasks(self) -> int:
        with self.transaction() as connection:
            cursor = connection.execute(
                "UPDATE tasks SET status = 'pending' WHERE status = 'running'"
            )
        return int(cursor.rowcount)

    def list_tasks(
        self,
        *,
        statuses: set[str] | None = None,
        kind_prefix: str = "",
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        conditions: list[str] = []
        values: list[Any] = []
        if statuses:
            placeholders = ",".join("?" for _ in statuses)
            conditions.append(f"status IN ({placeholders})")
            values.extend(sorted(statuses))
        if kind_prefix:
            conditions.append("kind LIKE ?")
            values.append(f"{kind_prefix}%")
        query = "SELECT * FROM tasks"
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY attempts, wave, task_id"
        if limit is not None:
            query += " LIMIT ?"
            values.append(max(1, int(limit)))
        return [self.task_from_row(row) for row in self.connection.execute(query, values)]

    def get_task(self, task_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM tasks WHERE task_id = ?", (str(task_id),)
        ).fetchone()
        return self.task_from_row(row) if row is not None else None

    def put_task(self, task: dict[str, Any]) -> None:
        task_id = str(task.get("task_id", ""))
        if not task_id:
            raise ValueError("discover task requires task_id")
        scope_type, scope_prefix, scope_paths = _task_scope(task)
        payload = {
            key: value
            for key, value in task.items()
            if key not in {"paths", "scope_paths", "scope_type", "scope_prefix", "scope_count"}
        }
        if scope_type == "explicit" and not scope_paths:
            scope_paths = [
                str(row["path"])
                for row in self.connection.execute(
                    "SELECT path FROM task_scope_paths WHERE task_id = ? ORDER BY path",
                    (task_id,),
                )
            ]
        with self.transaction() as connection:
            self._put_task(connection, task, scope_type, scope_prefix, scope_paths, payload)

    def _put_task(
        self,
        connection: sqlite3.Connection,
        task: dict[str, Any],
        scope_type: str,
        scope_prefix: str,
        scope_paths: list[str],
        payload: dict[str, Any],
    ) -> None:
        task_id = str(task.get("task_id", ""))
        connection.execute(
                """
                INSERT INTO tasks(
                    task_id, kind, status, wave, view, independent, coverage_required,
                    scope_type, scope_prefix, scope_count, attempts, priority,
                    artifact_dir, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(task_id) DO UPDATE SET
                    kind=excluded.kind,
                    status=excluded.status,
                    wave=excluded.wave,
                    view=excluded.view,
                    independent=excluded.independent,
                    coverage_required=excluded.coverage_required,
                    scope_type=excluded.scope_type,
                    scope_prefix=excluded.scope_prefix,
                    scope_count=excluded.scope_count,
                    attempts=excluded.attempts,
                    priority=excluded.priority,
                    artifact_dir=excluded.artifact_dir,
                    payload=excluded.payload
                """,
                (
                    task_id,
                    str(task.get("kind", "screen")),
                    str(task.get("status", "pending")),
                    int(task.get("wave", 0)),
                    str(task.get("view", "")),
                    int(bool(task.get("independent", False))),
                    int(bool(task.get("coverage_required", True))),
                    scope_type,
                    scope_prefix,
                    len(scope_paths) if scope_type == "explicit" else int(task.get("scope_count", 0)),
                    int(task.get("attempts", 0)),
                    str(task.get("priority", "normal")),
                    str(task.get("artifact_dir", "")),
                    json.dumps(payload, ensure_ascii=False, default=str),
                ),
        )
        connection.execute("DELETE FROM task_scope_paths WHERE task_id = ?", (task_id,))
        connection.executemany(
            "INSERT INTO task_scope_paths(task_id, path) VALUES (?, ?)",
            [(task_id, path) for path in scope_paths],
        )

    def task_from_row(self, row: sqlite3.Row | None) -> dict[str, Any]:
        if row is None:
            return {}
        payload = json.loads(str(row["payload"]))
        if not isinstance(payload, dict):
            payload = {}
        payload.update(
            {
                "task_id": str(row["task_id"]),
                "kind": str(row["kind"]),
                "status": str(row["status"]),
                "wave": int(row["wave"]),
                "view": str(row["view"]),
                "independent": bool(row["independent"]),
                "coverage_required": bool(row["coverage_required"]),
                "scope_type": str(row["scope_type"]),
                "scope_prefix": str(row["scope_prefix"]),
                "scope_count": int(row["scope_count"]),
                "attempts": int(row["attempts"]),
                "priority": str(row["priority"]),
                "artifact_dir": str(row["artifact_dir"]),
            }
        )
        return payload

    def scope_count(self, task: dict[str, Any]) -> int:
        scope_type = str(task.get("scope_type", "production-text"))
        if scope_type == "explicit":
            return int(
                self.connection.execute(
                    "SELECT COUNT(*) FROM task_scope_paths WHERE task_id = ?",
                    (str(task.get("task_id", "")),),
                ).fetchone()[0]
            )
        if scope_type == "prefix":
            prefix = str(task.get("scope_prefix", ""))
            if prefix in {"", "."}:
                return int(
                    self.connection.execute(
                        """
                        SELECT COUNT(*) FROM files
                        WHERE usage_hint = 'production-candidate' AND content_type = 'text'
                          AND status != 'unavailable'
                        """
                    ).fetchone()[0]
                )
            return int(
                self.connection.execute(
                    """
                    SELECT COUNT(*) FROM files
                    WHERE usage_hint = 'production-candidate' AND content_type = 'text'
                      AND status != 'unavailable' AND (path = ? OR path LIKE ?)
                    """,
                    (prefix, f"{prefix.rstrip('/')}/%"),
                ).fetchone()[0]
            )
        return int(
            self.connection.execute(
                """
                SELECT COUNT(*) FROM files
                WHERE usage_hint = 'production-candidate' AND content_type = 'text'
                  AND status != 'unavailable'
                """
            ).fetchone()[0]
        )

    def iter_scope_paths(
        self,
        task: dict[str, Any],
        *,
        after: str = "",
        limit: int = 500,
    ) -> Iterator[str]:
        scope_type = str(task.get("scope_type", "production-text"))
        values: list[Any] = [after]
        if scope_type == "explicit":
            query = """
                SELECT path FROM task_scope_paths
                WHERE task_id = ? AND path > ? ORDER BY path LIMIT ?
            """
            values = [str(task.get("task_id", "")), after, max(1, int(limit))]
        else:
            conditions = [
                "usage_hint = 'production-candidate'",
                "content_type = 'text'",
                "status != 'unavailable'",
                "path > ?",
            ]
            if scope_type == "prefix":
                prefix = str(task.get("scope_prefix", ""))
                if prefix not in {"", "."}:
                    conditions.append("(path = ? OR path LIKE ?)")
                    values.extend([prefix, f"{prefix.rstrip('/')}/%"])
            query = (
                "SELECT path FROM files WHERE "
                + " AND ".join(conditions)
                + " ORDER BY path LIMIT ?"
            )
            values.append(max(1, int(limit)))
        for row in self.connection.execute(query, values):
            yield str(row["path"])

    def path_allowed(self, task_id: str, path: str) -> bool:
        task = self.get_task(task_id)
        if not task:
            return False
        candidate = str(path).removeprefix("./")
        scope_type = str(task.get("scope_type", "production-text"))
        if scope_type == "explicit":
            return (
                self.connection.execute(
                    "SELECT 1 FROM task_scope_paths WHERE task_id = ? AND path = ?",
                    (task_id, candidate),
                ).fetchone()
                is not None
            )
        file = self.get_file(candidate)
        if not file or file.get("usage_hint") != "production-candidate" or file.get("content_type") != "text":
            return False
        if scope_type == "prefix":
            prefix = str(task.get("scope_prefix", ""))
            if prefix in {"", "."}:
                return True
            return candidate == prefix or candidate.startswith(prefix.rstrip("/") + "/")
        return True

    def scope_has_descendant(self, task_id: str, directory: str) -> bool:
        task = self.get_task(task_id)
        if not task:
            return False
        relative = str(directory).removeprefix("./").rstrip("/")
        prefix = f"{relative}/" if relative else ""
        scope_type = str(task.get("scope_type", "production-text"))
        if scope_type == "explicit":
            return (
                self.connection.execute(
                    "SELECT 1 FROM task_scope_paths WHERE task_id = ? AND path LIKE ? LIMIT 1",
                    (task_id, f"{prefix}%"),
                ).fetchone()
                is not None
            )
        conditions = [
            "usage_hint = 'production-candidate'",
            "content_type = 'text'",
            "status != 'unavailable'",
            "path LIKE ?",
        ]
        values: list[Any] = [f"{prefix}%"]
        if scope_type == "prefix":
            scope_prefix = str(task.get("scope_prefix", ""))
            if scope_prefix not in {"", "."}:
                conditions.append("(path = ? OR path LIKE ?)")
                values.extend([scope_prefix, f"{scope_prefix.rstrip('/')}/%"])
        return (
            self.connection.execute(
                "SELECT 1 FROM files WHERE " + " AND ".join(conditions) + " LIMIT 1",
                values,
            ).fetchone()
            is not None
        )

    def record_receipts(self, task_id: str, receipts: list[dict[str, Any]]) -> None:
        with self.transaction() as connection:
            for receipt in receipts:
                if receipt.get("tool") != "read_file" or receipt.get("status") != "ok":
                    continue
                connection.execute(
                    """
                    INSERT INTO read_receipts(
                        task_id, path, start_line, end_line, total_lines, truncated, payload
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        task_id,
                        str(receipt.get("path", "")),
                        int(receipt.get("start_line", 0)),
                        int(receipt.get("end_line", 0)),
                        int(receipt.get("total_lines", 0)),
                        int(bool(receipt.get("truncated", False))),
                        json.dumps(receipt, ensure_ascii=False, default=str),
                    ),
                )

    def coverage_complete_for_path(
        self,
        path: str,
        extra_receipts: list[dict[str, Any]] | None = None,
    ) -> bool:
        rows = self.connection.execute(
            """
            SELECT r.start_line, r.end_line, r.total_lines, r.truncated
            FROM read_receipts r
            JOIN tasks t ON t.task_id = r.task_id
            WHERE r.path = ? AND r.truncated = 0 AND t.kind = 'screen'
            ORDER BY r.start_line, r.end_line
            """,
            (str(path),),
        ).fetchall()
        ranges: list[tuple[int, int, int]] = [
            (int(row["start_line"]), int(row["end_line"]), int(row["total_lines"]))
            for row in rows
        ]
        for receipt in extra_receipts or []:
            if receipt.get("tool") == "read_file" and receipt.get("status") == "ok" and not receipt.get("truncated") and str(receipt.get("path", "")) == str(path):
                ranges.append(
                    (
                        int(receipt.get("start_line", 0)),
                        int(receipt.get("end_line", 0)),
                        int(receipt.get("total_lines", 0)),
                    )
                )
        if not ranges:
            return False
        total = max(item[2] for item in ranges)
        cursor = 1
        for start, end, _total in sorted(ranges):
            if start > cursor:
                return False
            cursor = max(cursor, end + 1)
        return cursor > total

    def coverage_complete_for_task(
        self,
        task: dict[str, Any],
        extra_receipts: list[dict[str, Any]] | None = None,
    ) -> bool:
        if not bool(task.get("coverage_required", True)):
            return False
        cursor = ""
        seen = False
        while True:
            page = list(self.iter_scope_paths(task, after=cursor, limit=1000))
            if not page:
                break
            seen = True
            for path in page:
                if not self.coverage_complete_for_path(path, extra_receipts):
                    return False
            cursor = page[-1]
            if len(page) < 1000:
                break
        return seen

    def commit_task(self, task: dict[str, Any]) -> None:
        """Commit a task result, receipts and derived records atomically."""
        task_id = str(task.get("task_id", ""))
        receipts = [item for item in task.get("tool_receipts", []) if isinstance(item, dict)]
        candidates = [item for item in task.get("candidates", []) if isinstance(item, dict)]
        candidate_paths = {str(item.get("path", "")) for item in candidates if item.get("path")}
        with self.transaction() as connection:
            scope_type, scope_prefix, scope_paths = _task_scope(task)
            if scope_type == "explicit" and not scope_paths:
                scope_paths = [
                    str(row["path"])
                    for row in connection.execute(
                        "SELECT path FROM task_scope_paths WHERE task_id = ? ORDER BY path",
                        (task_id,),
                    )
                ]
            payload = {
                key: value
                for key, value in task.items()
                if key not in {"paths", "scope_paths", "scope_type", "scope_prefix", "scope_count"}
            }
            self._put_task(connection, task, scope_type, scope_prefix, scope_paths, payload)
            for receipt in receipts:
                if receipt.get("tool") == "read_file" and receipt.get("status") == "ok":
                    connection.execute(
                        """
                        INSERT INTO read_receipts(
                            task_id, path, start_line, end_line, total_lines, truncated, payload
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            task_id,
                            str(receipt.get("path", "")),
                            int(receipt.get("start_line", 0)),
                            int(receipt.get("end_line", 0)),
                            int(receipt.get("total_lines", 0)),
                            int(bool(receipt.get("truncated", False))),
                            json.dumps(receipt, ensure_ascii=False, default=str),
                        ),
                    )
            for candidate in candidates:
                entry_id = _entry_id(candidate)
                evidence_id = _evidence_id(candidate)
                file_row = connection.execute(
                    "SELECT fingerprint FROM files WHERE path = ?",
                    (str(candidate.get("path", "")),),
                ).fetchone()
                entry = {
                    "entry_id": entry_id,
                    "status": "candidate",
                    "kind": candidate.get("kind", "input-candidate"),
                    "role": str(candidate.get("role", "unknown")),
                    "location": {
                        "path": candidate.get("path", ""),
                        "line_start": candidate.get("line_start"),
                        "line_end": candidate.get("line_end"),
                    },
                    "summary": str(candidate.get("summary", ""))[:4000],
                    "assumptions": ["screen candidate requires confirm verification"],
                    "evidence_refs": [evidence_id],
                    "stale_reason": "",
                }
                evidence = {
                    "evidence_id": evidence_id,
                    "kind": "screen-observation",
                    "source_file": candidate.get("path", ""),
                    "source_fingerprint": str(file_row["fingerprint"]) if file_row else "",
                    "line_start": candidate.get("line_start"),
                    "line_end": candidate.get("line_end"),
                    "excerpt_ref": task_id,
                    "summary": str(candidate.get("summary", ""))[:4000],
                }
                connection.execute(
                    "INSERT OR REPLACE INTO entries(entry_id, status, payload) VALUES (?, ?, ?)",
                    (entry_id, "candidate", json.dumps(entry, ensure_ascii=False)),
                )
                connection.execute(
                    "INSERT OR REPLACE INTO evidence(evidence_id, payload) VALUES (?, ?)",
                    (evidence_id, json.dumps(evidence, ensure_ascii=False)),
                )
                connection.execute(
                    "UPDATE files SET status = 'candidate' WHERE path = ?", (str(candidate.get("path")),)
                )
            touched = {
                str(receipt.get("path", ""))
                for receipt in receipts
                if receipt.get("tool") == "read_file" and receipt.get("status") == "ok"
            }
            for path in touched - candidate_paths:
                if not str(task.get("kind", "")).startswith("screen"):
                    continue
                if self.coverage_complete_for_path(path):
                    connection.execute(
                        "UPDATE files SET status = 'screened' WHERE path = ? AND status NOT IN ('candidate', 'metadata', 'unavailable')",
                        (path,),
                    )
            for message in [*task.get("unknowns", []), *task.get("deferred", [])]:
                if str(message).strip():
                    connection.execute("INSERT OR IGNORE INTO gaps(message) VALUES (?)", (str(message),))
            for item in task.get("deferred_items", []):
                if isinstance(item, dict) and str(item.get("reason", "")).strip():
                    connection.execute(
                        "INSERT OR IGNORE INTO gaps(message) VALUES (?)",
                        (str(item["reason"]),),
                    )
            if task.get("error"):
                connection.execute("INSERT OR IGNORE INTO gaps(message) VALUES (?)", (str(task["error"]),))

    def add_messages(self, *, gaps: list[str] = (), warnings: list[str] = ()) -> None:
        with self.transaction() as connection:
            connection.executemany(
                "INSERT OR IGNORE INTO gaps(message) VALUES (?)",
                [(str(item),) for item in gaps if str(item).strip()],
            )
            connection.executemany(
                "INSERT OR IGNORE INTO warnings(message) VALUES (?)",
                [(str(item),) for item in warnings if str(item).strip()],
            )

    def messages(self, table: str, *, limit: int = 20) -> list[str]:
        if table not in {"gaps", "warnings"}:
            raise ValueError(f"unsupported message table: {table}")
        rows = self.connection.execute(
            f"SELECT message FROM {table} ORDER BY rowid DESC LIMIT ?", (max(1, int(limit)),)
        ).fetchall()
        return [str(row["message"]) for row in rows]

    def message_count(self, table: str) -> int:
        if table not in {"gaps", "warnings"}:
            raise ValueError(f"unsupported message table: {table}")
        return int(self.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])

    def put_note(self, task_id: str, key: str, text: str) -> dict[str, Any]:
        with self.transaction() as connection:
            cursor = connection.execute(
                "INSERT INTO task_notes(task_id, key, text, created_at) VALUES (?, ?, ?, ?)",
                (task_id, key, text, datetime.now(timezone.utc).isoformat()),
            )
            note_id = int(cursor.lastrowid or 0)
        return {"note_id": note_id, "key": key, "text": text}

    def notes(self, task_id: str, *, limit: int = 20) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.connection.execute(
                "SELECT note_id, key, text, created_at FROM task_notes "
                "WHERE task_id = ? ORDER BY note_id LIMIT ?",
                (task_id, max(1, int(limit))),
            ).fetchall()
        return [dict(row) for row in rows]

    def note_count(self, task_id: str) -> int:
        with self._lock:
            row = self.connection.execute(
                "SELECT COUNT(*) FROM task_notes WHERE task_id = ?", (task_id,)
            ).fetchone()
        return int(row[0]) if row else 0

    def prior_context_for_task(self, task_id: str, *, limit: int = 20) -> dict[str, Any]:
        """Return negative results and entries from other tasks sharing this scope."""
        limit = max(1, int(limit))
        negative: list[dict[str, Any]] = []
        seen_tasks: set[str] = set()
        rows = self.connection.execute(
            """
            SELECT t.task_id, t.payload
            FROM tasks t
            JOIN task_scope_paths p ON p.task_id = t.task_id
            WHERE t.task_id != ?
              AND t.status IN ('complete', 'partial')
              AND p.path IN (SELECT path FROM task_scope_paths WHERE task_id = ?)
            ORDER BY t.task_id
            LIMIT 200
            """,
            (task_id, task_id),
        ).fetchall()
        scope = set(self.task_scope_paths(task_id))
        for row in rows:
            other_id = str(row["task_id"])
            if other_id in seen_tasks:
                continue
            seen_tasks.add(other_id)
            try:
                payload = json.loads(row["payload"] or "{}")
            except json.JSONDecodeError:
                continue
            result = payload.get("result") if isinstance(payload, dict) else None
            for item in (result or {}).get("negative_results", []) if isinstance(result, dict) else []:
                if not isinstance(item, dict):
                    continue
                path = str(item.get("path", ""))
                if path and path not in scope:
                    continue
                negative.append(
                    {
                        "path": path,
                        "summary": str(item.get("summary", ""))[:1000],
                        "source_task": other_id,
                    }
                )
                if len(negative) >= limit:
                    break
            if len(negative) >= limit:
                break
        entries: list[dict[str, Any]] = []
        for row in self.connection.execute(
            "SELECT payload FROM entries WHERE status IN ('candidate', 'confirmed') "
            "ORDER BY entry_id DESC LIMIT 500"
        ):
            try:
                payload = json.loads(row["payload"] or "{}")
            except json.JSONDecodeError:
                continue
            location = payload.get("location") if isinstance(payload, dict) else None
            path = str((location or {}).get("path", ""))
            if path not in scope:
                continue
            entries.append(
                {
                    "status": str(payload.get("status", "")),
                    "path": path,
                    "line_start": int((location or {}).get("line_start", 0) or 0),
                    "line_end": int((location or {}).get("line_end", 0) or 0),
                    "summary": str(payload.get("summary", ""))[:1000],
                }
            )
            if len(entries) >= limit:
                break
        context: dict[str, Any] = {}
        if negative:
            context["negative_results"] = negative
        if entries:
            context["entries"] = entries
        return context

    def entries(self, *, status: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT payload FROM entries"
        values: list[Any] = []
        if status:
            query += " WHERE status = ?"
            values.append(status)
        query += " ORDER BY entry_id"
        return [json.loads(str(row["payload"])) for row in self.connection.execute(query, values)]

    def evidence(self) -> list[dict[str, Any]]:
        return [
            json.loads(str(row["payload"]))
            for row in self.connection.execute("SELECT payload FROM evidence ORDER BY evidence_id")
        ]

    def count_entries(self, status: str | None = None) -> int:
        if status:
            return int(
                self.connection.execute("SELECT COUNT(*) FROM entries WHERE status = ?", (status,)).fetchone()[0]
            )
        return int(self.connection.execute("SELECT COUNT(*) FROM entries").fetchone()[0])

    def count_evidence(self) -> int:
        return int(self.connection.execute("SELECT COUNT(*) FROM evidence").fetchone()[0])

    def business_digest(self) -> str:
        parts = [
            json.dumps(self.file_counts(), sort_keys=True),
            json.dumps(
                [tuple(row) for row in self.connection.execute(
                    "SELECT status, kind, COUNT(*) FROM tasks GROUP BY status, kind ORDER BY status, kind"
                )],
                sort_keys=True,
            ),
            json.dumps(
                [tuple(row) for row in self.connection.execute(
                    "SELECT status, COUNT(*) FROM entries GROUP BY status ORDER BY status"
                )],
                sort_keys=True,
            ),
            str(
                self.connection.execute(
                    "SELECT COALESCE(MAX(entry_id), '') FROM entries"
                ).fetchone()[0]
            ),
            json.dumps(
                tuple(
                    self.connection.execute(
                        "SELECT COUNT(*), COALESCE(MAX(receipt_id), 0) FROM read_receipts"
                    ).fetchone()
                )
            ),
            json.dumps(
                [tuple(row) for row in self.connection.execute(
                    "SELECT status, COUNT(*), COALESCE(MAX(debt_id), '') FROM dispositions GROUP BY status ORDER BY status"
                )],
                sort_keys=True,
            ),
            json.dumps(
                [tuple(row) for row in self.connection.execute(
                    "SELECT status, COUNT(*) FROM mechanisms GROUP BY status ORDER BY status"
                )],
                sort_keys=True,
            ),
            json.dumps(
                [tuple(row) for row in self.connection.execute(
                    "SELECT complete, truncated, COUNT(*), COALESCE(MAX(cursor), 0), "
                    "COALESCE(MAX(query_id), '') FROM feature_queries "
                    "GROUP BY complete, truncated ORDER BY complete, truncated"
                )],
                sort_keys=True,
            ),
            json.dumps(
                [tuple(row) for row in self.connection.execute(
                    "SELECT COUNT(*), COALESCE(MAX(hit_id), ''), "
                    "SUM(CASE WHEN confirm_task_id = '' THEN 1 ELSE 0 END) "
                    "FROM feature_hits"
                )],
                sort_keys=True,
            ),
        ]
        return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()

    def export_inventory(self, artifact_dir: Path) -> None:
        """Write the two human-readable inventory snapshots.

        All other discover data is queried from this run-local ledger; there is
        no JSON mirror of tasks, entries, evidence, or feature tables.
        """
        artifact_dir.mkdir(parents=True, exist_ok=True)
        _write_json_array(artifact_dir / "files.json", self.iter_files(limit=1000))
        _write_json_array(
            artifact_dir / "excluded-files.json",
            (
                {"path": str(row["path"]), "reason": str(row["reason"])}
                for row in self.connection.execute(
                    "SELECT path, reason FROM excluded_files ORDER BY path"
                )
            ),
        )


def _follow_up_key(task_id: str, index: int, item: dict[str, Any]) -> str:
    question = str(item.get("question", "")).strip() or "Inspect related source scope."
    return hashlib.sha256(f"{task_id}:{index}:{question}".encode()).hexdigest()[:16]


def _task_follow_up_items(
    task: dict[str, Any], scope_paths: list[str]
) -> list[dict[str, Any]]:
    raw = task.get("follow_up_items")
    if not isinstance(raw, list):
        raw = task.get("follow_up", [])
    items: list[dict[str, Any]] = []
    for value in raw if isinstance(raw, list) else []:
        if isinstance(value, dict):
            item = dict(value)
            item["question"] = str(item.get("question", "")).strip() or "Inspect related source scope."
            items.append(item)
        elif str(value).strip():
            items.append(
                {
                    "question": str(value).strip(),
                    "paths": scope_paths,
                    "reason": "completed screen task requested follow-up",
                }
            )
    return items


def _next_number(tasks: list[dict[str, Any]], prefix: str) -> int:
    highest = 0
    marker = f"{prefix}-"
    for task in tasks:
        task_id = str(task.get("task_id", ""))
        if not task_id.startswith(marker):
            continue
        try:
            highest = max(highest, int(task_id[len(marker):]))
        except ValueError:
            continue
    return highest + 1


def _task_scope(task: dict[str, Any]) -> tuple[str, str, list[str]]:
    scope_type = str(task.get("scope_type", ""))
    raw_paths = task.get("scope_paths", task.get("paths", []))
    paths = [str(path).removeprefix("./") for path in raw_paths if str(path).strip()]
    if paths or scope_type == "explicit":
        return "explicit", "", sorted(set(paths))
    if scope_type == "prefix":
        return "prefix", str(task.get("scope_prefix", "")), []
    return "production-text", "", []


def _file_from_row(row: sqlite3.Row) -> dict[str, Any]:
    result: dict[str, Any] = {
        "path": str(row["path"]),
        "size": int(row["size"]),
        "fingerprint": str(row["fingerprint"]),
        "content_type": str(row["content_type"]),
        "kind": str(row["kind"]),
        "usage_hint": str(row["usage_hint"]),
        "source_origin": str(row["source_origin"]),
        "large": bool(row["large"]),
        "status": str(row["status"]),
    }
    if row["error"]:
        result["error"] = str(row["error"])
    return result


def _entry_id(candidate: dict[str, Any]) -> str:
    return "entry-" + hashlib.sha256(
        f"{candidate.get('path')}:{candidate.get('line_start')}:{candidate.get('line_end')}:{candidate.get('kind')}".encode()
    ).hexdigest()[:16]


def _evidence_id(candidate: dict[str, Any]) -> str:
    return "evidence-" + hashlib.sha256(
        f"{candidate.get('path')}:{candidate.get('line_start')}:{candidate.get('line_end')}:{candidate.get('summary')}".encode()
    ).hexdigest()[:16]


def _write_json_array(path: Path, values: Iterator[dict[str, Any]] | list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as target:
        target.write("[\n")
        first = True
        for value in values:
            if not first:
                target.write(",\n")
            json.dump(value, target, ensure_ascii=False, sort_keys=True)
            first = False
        target.write("\n]\n")
    temporary.replace(path)
