from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from yasa_vulnagent.stages.discover.ledger import DiscoverLedger
from yasa_vulnagent.stages.discover.schema import empty_state
from yasa_vulnagent.stages.discover.screen.tools import SourceToolbox
from yasa_vulnagent.stages.discover.screen.graph import validate_response


class DiscoverLedgerTest(unittest.TestCase):
    def test_large_inventory_stays_in_sqlite_and_paginates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ledger_path = root / "ledger.sqlite"
            records = [
                {
                    "path": f"module/{index:05d}.py",
                    "size": 10,
                    "fingerprint": "",
                    "content_type": "text",
                    "kind": "source",
                    "usage_hint": "production-candidate",
                    "status": "pending",
                }
                for index in range(100_000)
            ]
            with DiscoverLedger.open(ledger_path) as ledger:
                ledger.replace_inventory(records, [])
                ledger.put_task(
                    {
                        "task_id": "screen-0001",
                        "kind": "screen",
                        "status": "pending",
                        "scope_type": "production-text",
                        "coverage_required": False,
                    }
                )
                first = ledger.eligible_paths(limit=17)
                second = ledger.eligible_paths(after=first[-1], limit=17)
                self.assertEqual(first, [f"module/{index:05d}.py" for index in range(17)])
                self.assertEqual(
                    second,
                    [f"module/{index:05d}.py" for index in range(17, 34)],
                )
                self.assertEqual(ledger.file_count(), 100_000)
                task = ledger.get_task("screen-0001")
                self.assertEqual(task.get("scope_type"), "production-text")
                self.assertNotIn("paths", task)
                self.assertNotIn("scope_paths", task)
                explicit = {
                    "task_id": "screen-0002",
                    "kind": "screen_follow_up",
                    "status": "pending",
                    "scope_type": "explicit",
                    "scope_paths": ["module/00000.py"],
                }
                ledger.put_task(explicit)
                restored = ledger.get_task("screen-0002")
                ledger.put_task(restored)
                self.assertTrue(ledger.path_allowed("screen-0002", "module/00000.py"))
            state = empty_state("/repo", str(root), str(root / "state.json"))
            self.assertNotIn("files", state)
            self.assertNotIn("tasks", state)
            self.assertNotIn("entries", state)
            self.assertNotIn("evidence", state)

    def test_scope_tools_use_cursor_without_loading_all_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            for index in range(5):
                (repository / f"file-{index}.py").write_text(f"value = {index}\n", encoding="utf-8")
            with DiscoverLedger.open(root / "ledger.sqlite") as ledger:
                ledger.replace_inventory(
                    [
                        {
                            "path": f"file-{index}.py",
                            "content_type": "text",
                            "usage_hint": "production-candidate",
                            "status": "pending",
                        }
                        for index in range(5)
                    ],
                    [],
                )
                ledger.put_task(
                    {
                        "task_id": "screen-0001",
                        "kind": "screen",
                        "status": "pending",
                        "scope_type": "production-text",
                        "coverage_required": False,
                    }
                )
                toolbox = SourceToolbox(repository, ledger=ledger, task_id="screen-0001")
                page = toolbox.glob("*.py", max_results=2)
                next_page = toolbox.glob("*.py", max_results=2, cursor=page["next_cursor"])
                self.assertEqual(page["matches"], ["file-0.py", "file-1.py"])
                self.assertEqual(next_page["matches"], ["file-2.py", "file-3.py"])
                self.assertNotEqual(set(page["matches"]), set(next_page["matches"]))

    def test_task_commit_keeps_receipts_and_candidate_atomic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with DiscoverLedger.open(root / "ledger.sqlite") as ledger:
                ledger.replace_inventory(
                    [
                        {
                            "path": "main.py",
                            "content_type": "text",
                            "usage_hint": "production-candidate",
                            "status": "pending",
                        }
                    ],
                    [],
                )
                task = {
                    "task_id": "screen-0001",
                    "kind": "screen_coverage",
                    "status": "complete",
                    "scope_type": "explicit",
                    "scope_paths": ["main.py"],
                    "coverage_required": True,
                    "read_ranges": [
                        {
                            "tool": "read_file",
                            "path": "main.py",
                            "start_line": 1,
                            "end_line": 2,
                            "total_lines": 2,
                            "truncated": False,
                            "status": "ok",
                        }
                    ],
                    "tool_receipts": [
                        {
                            "tool": "read_file",
                            "path": "main.py",
                            "start_line": 1,
                            "end_line": 1,
                            "total_lines": 1,
                            "truncated": False,
                            "status": "ok",
                        }
                    ],
                    "candidates": [
                        {
                            "path": "main.py",
                            "line_start": 1,
                            "line_end": 1,
                            "kind": "input-candidate",
                            "summary": "source observation",
                        }
                    ],
                    "unknowns": [],
                    "deferred": [],
                    "follow_up": [],
                }
                ledger.commit_task(task)
                self.assertEqual(ledger.get_task("screen-0001")["status"], "complete")
                self.assertEqual(ledger.count_entries("candidate"), 1)
                self.assertEqual(ledger.get_file("main.py")["status"], "candidate")
                receipt_count = ledger.connection.execute(
                    "SELECT COUNT(*) FROM read_receipts"
                ).fetchone()[0]
                self.assertEqual(receipt_count, 1)

    def test_concurrent_note_writes_are_serialized(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with DiscoverLedger.open(root / "ledger.sqlite") as ledger:
                ledger.put_task({"task_id": "screen-0001", "kind": "screen", "status": "running"})
                errors: list[Exception] = []

                def write_note(index: int) -> None:
                    try:
                        ledger.put_note("screen-0001", f"key-{index}", "value")
                        ledger.notes("screen-0001")
                    except Exception as exc:
                        errors.append(exc)

                threads = [threading.Thread(target=write_note, args=(index,)) for index in range(20)]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()

                self.assertEqual(errors, [])
                self.assertEqual(ledger.note_count("screen-0001"), 20)

    def test_coverage_validation_includes_current_uncommitted_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with DiscoverLedger.open(root / "ledger.sqlite") as ledger:
                ledger.replace_inventory(
                    [
                        {
                            "path": "main.py",
                            "content_type": "text",
                            "usage_hint": "production-candidate",
                            "status": "pending",
                        }
                    ],
                    [],
                )
                task = {
                    "task_id": "screen-0001",
                    "kind": "screen_coverage",
                    "status": "running",
                    "scope_type": "explicit",
                    "scope_paths": ["main.py"],
                    "coverage_required": True,
                    "read_ranges": [
                        {
                            "tool": "read_file",
                            "path": "main.py",
                            "start_line": 1,
                            "end_line": 2,
                            "total_lines": 2,
                            "truncated": False,
                            "status": "ok",
                        }
                    ],
                    "tool_receipts": [
                        {
                            "tool": "read_file",
                            "path": "main.py",
                            "start_line": 1,
                            "end_line": 2,
                            "total_lines": 2,
                            "truncated": False,
                            "status": "ok",
                        }
                    ],
                }
                ledger.put_task(task)
                result = validate_response(
                    '{"scope_status":"complete","candidates":[]}',
                    task,
                    ledger=ledger,
                )
                self.assertTrue(result["coverage_complete"])


class DiscoverLedgerThreadTest(unittest.TestCase):
    def test_worker_threads_read_through_their_own_connections(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "ledger.sqlite"
            ledger = DiscoverLedger.open(path)
            ledger.put_task({"task_id": "screen-0001", "kind": "screen", "status": "pending"})
            main_connection = ledger.connection
            barrier = threading.Barrier(4)
            seen: list[int] = []
            errors: list[str] = []
            lock = threading.Lock()

            def worker() -> None:
                try:
                    barrier.wait()
                    connection = ledger.connection
                    for _ in range(25):
                        if ledger.get_task("screen-0001") is None:
                            raise AssertionError("task missing")
                    with lock:
                        seen.append(id(connection))
                except Exception as exc:  # noqa: BLE001 - surface thread failures
                    with lock:
                        errors.append(str(exc))

            threads = [threading.Thread(target=worker) for _ in range(4)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            self.assertEqual(errors, [])
            self.assertEqual(len(set(seen)), 4)
            self.assertNotIn(id(main_connection), set(seen))
            self.assertIs(ledger.connection, main_connection)
            ledger.close()


if __name__ == "__main__":
    unittest.main()
