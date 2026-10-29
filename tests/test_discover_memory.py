from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from yasa_vulnagent.stages.discover.ledger import DiscoverLedger


class DiscoverMemoryTest(unittest.TestCase):
    def _ledger(self, root: Path) -> DiscoverLedger:
        ledger = DiscoverLedger.open(root / "ledger.sqlite")
        ledger.replace_inventory(
            [
                {
                    "path": path,
                    "status": "pending",
                    "usage_hint": "production-candidate",
                    "content_type": "text",
                }
                for path in ("a.py", "b.py", "c.py")
            ],
            [],
        )
        ledger.put_task(
            {
                "task_id": "t1",
                "kind": "screen",
                "status": "complete",
                "view": "follow-up",
                "paths": ["a.py"],
                "result": {
                    "negative_results": [
                        {"path": "a.py", "summary": "no HTTP handlers in this file"}
                    ]
                },
            }
        )
        ledger.put_task(
            {
                "task_id": "t2",
                "kind": "screen",
                "status": "running",
                "view": "follow-up",
                "paths": ["a.py"],
            }
        )
        ledger.put_task(
            {
                "task_id": "t3",
                "kind": "screen",
                "status": "complete",
                "view": "follow-up",
                "paths": ["b.py"],
                "result": {
                    "negative_results": [{"path": "b.py", "summary": "unrelated"}]
                },
            }
        )
        ledger.put_entry(
            {
                "entry_id": "e1",
                "status": "candidate",
                "location": {"path": "a.py", "line_start": 3, "line_end": 5},
                "summary": "reads request input",
            }
        )
        return ledger

    def test_returns_negative_results_from_sharing_scope_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self._ledger(Path(temporary)) as ledger:
                context = ledger.prior_context_for_task("t2", limit=10)
        negatives = context["negative_results"]
        self.assertEqual(len(negatives), 1)
        self.assertEqual(negatives[0]["path"], "a.py")
        self.assertEqual(negatives[0]["source_task"], "t1")
        self.assertNotIn("unrelated", str(negatives))

    def test_returns_entries_inside_the_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self._ledger(Path(temporary)) as ledger:
                context = ledger.prior_context_for_task("t2", limit=10)
        entries = context["entries"]
        self.assertEqual(entries[0]["path"], "a.py")
        self.assertEqual(entries[0]["line_start"], 3)
        self.assertEqual(entries[0]["status"], "candidate")

    def test_returns_empty_when_no_other_task_shares_the_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self._ledger(Path(temporary)) as ledger:
                ledger.put_task(
                    {
                        "task_id": "t4",
                        "kind": "screen",
                        "status": "running",
                        "paths": ["c.py"],
                    }
                )
                context = ledger.prior_context_for_task("t4", limit=10)
        self.assertEqual(context, {})

    def test_notes_are_scoped_per_task(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self._ledger(Path(temporary)) as ledger:
                ledger.put_note("t1", "k", "note text")
                self.assertEqual(len(ledger.notes("t1")), 1)
                self.assertEqual(ledger.notes("t2"), [])


if __name__ == "__main__":
    unittest.main()
