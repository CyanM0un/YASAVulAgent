from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from yasa_vulnagent.agent.context import compact_json
from yasa_vulnagent.stages.discover.confirm.node import _task_context as confirm_context
from yasa_vulnagent.stages.discover.ledger import DiscoverLedger
from yasa_vulnagent.stages.discover.screen.graph import _task_context as screen_context


class CompactJsonTest(unittest.TestCase):
    def test_drops_then_shrinks_and_stays_valid(self) -> None:
        value = {
            "task_id": "t1",
            "init_context": {
                "status": "ok",
                "summary": "x" * 20000,
                "details": {"nested": "y" * 10000},
            },
        }
        text = compact_json(
            value, 2000, drop_keys=("init_context.details",)
        )
        parsed = json.loads(text)
        self.assertLessEqual(len(text), 2000)
        self.assertTrue(parsed["_truncated"])
        self.assertEqual(parsed["task_id"], "t1")
        self.assertNotIn("details", parsed["init_context"])

    def test_returns_original_when_it_fits(self) -> None:
        value = {"task_id": "t1", "summary": "short"}
        text = compact_json(value, 4000)
        self.assertNotIn("_truncated", json.loads(text))
        self.assertEqual(json.loads(text), value)


class ScreenTaskContextTest(unittest.TestCase):
    def _ledger(self, root: Path) -> DiscoverLedger:
        ledger = DiscoverLedger.open(root / "ledger.sqlite")
        ledger.replace_inventory(
            [
                {
                    "path": "a.py",
                    "status": "pending",
                    "usage_hint": "production-candidate",
                    "content_type": "text",
                }
            ],
            [],
        )
        ledger.put_task(
            {
                "task_id": "prior",
                "kind": "screen",
                "status": "complete",
                "paths": ["a.py"],
                "result": {
                    "negative_results": [
                        {"path": "a.py", "summary": "no handlers here"}
                    ]
                },
            }
        )
        ledger.put_task(
            {
                "task_id": "t2",
                "kind": "screen",
                "status": "running",
                "paths": ["a.py"],
            }
        )
        return ledger

    def test_large_init_context_is_compacted_but_kept(self) -> None:
        task = {
            "task_id": "t1",
            "view": "follow-up",
            "question": "q",
            "paths": ["a.py"],
            "independent": False,
        }
        init_context = {
            "status": "partial",
            "checks": {"cwe": {"ok": True, "text": "c" * 8000}},
            "documents": {"chunks": ["d" * 8000]},
            "security_history": {"summary": "s" * 8000},
        }
        text = screen_context(task, init_context, 4000)
        parsed = json.loads(text)
        self.assertLessEqual(len(text), 4000)
        self.assertTrue(parsed["_truncated"])
        self.assertIn("init_context", parsed)
        self.assertNotIn("chunks", parsed["init_context"].get("documents", {}))

    def test_follow_up_view_receives_prior_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self._ledger(Path(temporary)) as ledger:
                task = {
                    "task_id": "t2",
                    "view": "follow-up",
                    "question": "q",
                    "paths": ["a.py"],
                    "independent": False,
                }
                parsed = json.loads(screen_context(task, {}, 4000, ledger=ledger))
        self.assertIn("prior_findings", parsed)
        self.assertIn("no handlers here", json.dumps(parsed["prior_findings"]))
        self.assertIn("not established facts", parsed["prior_findings"]["notice"])

    def test_independent_view_does_not_receive_prior_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self._ledger(Path(temporary)) as ledger:
                task = {
                    "task_id": "t2",
                    "view": "independent-exploration",
                    "question": "q",
                    "paths": ["a.py"],
                    "independent": False,
                }
                parsed = json.loads(screen_context(task, {}, 4000, ledger=ledger))
        self.assertNotIn("prior_findings", parsed)


class ConfirmTaskContextTest(unittest.TestCase):
    def test_priority_hints_are_dropped_before_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with DiscoverLedger.open(Path(temporary) / "ledger.sqlite") as ledger:
                ledger.replace_inventory(
                    [
                        {
                            "path": "a.py",
                            "status": "pending",
                            "usage_hint": "production-candidate",
                            "content_type": "text",
                        }
                    ],
                    [],
                )
                ledger.put_entry(
                    {
                        "entry_id": "e1",
                        "status": "candidate",
                        "location": {"path": "a.py", "line_start": 1, "line_end": 2},
                        "summary": "reads request input",
                    }
                )
                ledger.put_task(
                    {
                        "task_id": "c1",
                        "kind": "confirm",
                        "status": "running",
                        "paths": ["a.py"],
                    }
                )
                text = confirm_context(
                    ledger,
                    {
                        "task_id": "c1",
                        "candidate_ids": ["e1"],
                        "paths": ["a.py"],
                    },
                    limit=4000,
                )
        parsed = json.loads(text)
        self.assertLessEqual(len(text), 4000)
        self.assertNotIn("priority_hints", parsed)
        self.assertEqual(
            set(parsed["candidates"][0]),
            {"entry_id", "path", "line_start", "line_end", "summary"},
        )
        self.assertEqual(parsed["candidates"][0]["entry_id"], "e1")


if __name__ == "__main__":
    unittest.main()
