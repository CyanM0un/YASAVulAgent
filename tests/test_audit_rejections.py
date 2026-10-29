from __future__ import annotations

import unittest

from yasa_vulnagent.stages.audit.trace.rejections import RejectionIndex


def _finding(finding_id: str = "finding-1", **overrides) -> dict:
    value = {
        "id": finding_id,
        "task_id": "task-1",
        "verdict": "rejected",
        "title": "guarded sink",
        "category": "injection_interpretation",
        "reason": "the guard is effective on this path",
        "source_to_sink": {"source": "request", "sink": "run"},
        "evidence": [{"path": "src/app.py", "start_line": 2, "end_line": 3}],
    }
    value.update(overrides)
    return value


def _review(finding_id: str = "finding-1", **overrides) -> dict:
    value = {
        "id": f"review-{finding_id}",
        "type": "finding",
        "target_id": finding_id,
        "status": "complete",
        "verdict": "rejected",
        "reason": "guard applies",
    }
    value.update(overrides)
    return value


class RejectionIndexTest(unittest.TestCase):
    def test_only_complete_rejected_reviews_are_indexed(self) -> None:
        index = RejectionIndex.from_audit(
            [
                _finding("finding-1"),
                _finding("finding-2"),
                _finding("finding-3", verdict="confirmed"),
            ],
            [
                _review("finding-1"),
                _review("finding-2", status="blocked"),
            ],
        )

        self.assertEqual([entry["id"] for entry in index.entries], ["finding-1"])
        self.assertIn("guard", index.entries[0]["reason"])

    def test_for_task_scores_and_caps(self) -> None:
        index = RejectionIndex.from_audit(
            [
                _finding("finding-1"),
                _finding(
                    "finding-2",
                    task_id="task-2",
                    category="path_traversal",
                    evidence=[{"path": "src/other.py", "start_line": 1, "end_line": 1}],
                ),
            ],
            [_review("finding-1"), _review("finding-2")],
        )

        task = {"id": "task-1", "paths": ["src/app.py"]}
        entries = index.for_task(
            task,
            categories={"injection_interpretation"},
            limit=1,
        )
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["id"], "finding-1")
        self.assertEqual(entries[0]["source_to_sink"], "request -> run")

    def test_source_revision_mismatch_is_skipped(self) -> None:
        index = RejectionIndex.from_audit(
            [_finding("finding-1", source_revision="old")],
            [_review("finding-1")],
            revision="new",
        )

        self.assertEqual(index.entries, [])


if __name__ == "__main__":
    unittest.main()
