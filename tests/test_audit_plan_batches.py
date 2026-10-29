from __future__ import annotations

import unittest

from yasa_vulnagent.stages.audit.plan.batches import build_seed_batches


def _task(
    task_id: str,
    *,
    kind: str = "entry",
    paths: list[str] | None = None,
) -> dict:
    return {"id": task_id, "kind": kind, "paths": paths or []}


class AuditPlanBatchesTest(unittest.TestCase):
    def test_empty_list_has_no_batches(self) -> None:
        self.assertEqual(build_seed_batches([], 10), [])

    def test_rejects_invalid_batch_size(self) -> None:
        for value in (0, -1, True, 1.5, "10"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    build_seed_batches([], value)

    def test_batches_cover_every_task_once(self) -> None:
        tasks = [
            _task("entry-1", paths=["src/a.py"]),
            _task("entry-2", paths=["src/a.py"]),
            _task("entry-3", paths=["src/b.py"]),
            _task("entry-4", paths=[]),
        ]
        batches = build_seed_batches(tasks, 2)

        self.assertEqual(
            [task["id"] for batch in batches for task in batch["tasks"]],
            ["entry-4", "entry-1", "entry-2", "entry-3"],
        )
        self.assertEqual([batch["id"] for batch in batches], ["batch-0001", "batch-0002", "batch-0003"])
        self.assertTrue(all(len(batch["tasks"]) <= 2 for batch in batches))
        self.assertEqual([batch["key"] for batch in batches], ["<no-path>", "src/a.py", "src/b.py"])

    def test_paths_are_not_mixed_within_a_batch(self) -> None:
        tasks = [
            _task("entry-1", paths=["src/a.py", "src/b.py"]),
            _task("entry-2", paths=["src/a.py"]),
            _task("entry-3", paths=["src/b.py"]),
        ]
        batches = build_seed_batches(tasks, 10)

        self.assertEqual([batch["key"] for batch in batches], ["src/a.py", "src/b.py"])
        self.assertEqual(
            [task["id"] for task in batches[0]["tasks"]],
            ["entry-1", "entry-2"],
        )

    def test_entry_and_patch_batches_are_separate(self) -> None:
        tasks = [
            _task("entry-1", kind="entry", paths=["src/a.py"]),
            _task("patch-1", kind="patch", paths=["src/a.py"]),
        ]
        batches = build_seed_batches(tasks, 10)

        self.assertEqual([batch["kind"] for batch in batches], ["entry", "patch"])
        self.assertEqual([batch["id"] for batch in batches], ["batch-0001", "batch-0002"])

    def test_batches_are_deterministic(self) -> None:
        tasks = [
            _task("entry-b", paths=["src/b.py"]),
            _task("entry-a", paths=["src/a.py"]),
        ]
        first = build_seed_batches(tasks, 10)
        second = build_seed_batches(list(reversed(tasks)), 10)

        self.assertEqual(first, second)

    def test_rejects_duplicate_task_ids(self) -> None:
        with self.assertRaises(ValueError):
            build_seed_batches(
                [
                    _task("entry-1", paths=["src/a.py"]),
                    _task("entry-1", paths=["src/b.py"]),
                ],
                10,
            )

    def test_rejects_unknown_kind(self) -> None:
        with self.assertRaises(ValueError):
            build_seed_batches([_task("task-1", kind="trace", paths=["src/a.py"])], 10)


if __name__ == "__main__":
    unittest.main()
