from __future__ import annotations

import json
import unittest

from yasa_vulnagent.agent.retry import RetryPolicy
from yasa_vulnagent.agent.usage import UsageRecorder
from yasa_vulnagent.stages.audit.plan.model import (
    PlanModelError,
    run_batch,
    validate_batch_output,
)


def _task(task_id: str, *, kind: str = "entry", path: str = "src/a.py", status: str = "planned") -> dict:
    return {"id": task_id, "kind": kind, "paths": [path], "status": status}


def _group(ids: list[str], *, priority: str = "normal", reason: str = "related") -> dict:
    return {"seed_task_ids": ids, "priority": priority, "reason": reason}


class _Response:
    def __init__(self, content: str) -> None:
        self.content = content


def _valid_payload() -> dict:
    return {
        "groups": [
            {
                "seed_task_ids": ["entry-a"],
                "priority": "normal",
                "reason": "one entry",
            }
        ],
        "order": [0],
    }


class AuditPlanModelRetryTest(unittest.TestCase):
    def _batch(self) -> tuple[dict, list[dict]]:
        return (
            {"id": "batch-0001", "kind": "entry"},
            [{"id": "entry-a", "kind": "entry", "paths": ["src/a.py"], "status": "planned"}],
        )

    def test_run_batch_retries_transient_failure(self) -> None:
        class _FlakyModel:
            def __init__(self) -> None:
                self.calls = 0

            def invoke(self, messages):
                self.calls += 1
                if self.calls == 1:
                    raise RuntimeError("503 service unavailable")
                return _Response(json.dumps(_valid_payload()))

        model = _FlakyModel()
        usage = UsageRecorder()
        batch, seeds = self._batch()
        payload = run_batch(
            model,
            batch,
            seeds,
            usage,
            retry=RetryPolicy(attempts=2, base_delay=0),
        )

        self.assertEqual(payload["order"], [0])
        self.assertEqual(model.calls, 2)
        self.assertEqual(usage.snapshot("audit.plan")["totals"]["attempts"], 2)
        self.assertEqual(usage.snapshot("audit.plan")["totals"]["retries"], 1)

    def test_run_batch_raises_after_retry_exhaustion(self) -> None:
        class _DownModel:
            def __init__(self) -> None:
                self.calls = 0

            def invoke(self, messages):
                self.calls += 1
                raise RuntimeError("503 service unavailable")

        model = _DownModel()
        batch, seeds = self._batch()
        with self.assertRaises(PlanModelError):
            run_batch(
                model,
                batch,
                seeds,
                None,
                retry=RetryPolicy(attempts=2, base_delay=0),
            )
        self.assertEqual(model.calls, 2)

    def test_run_batch_does_not_retry_auth_failure(self) -> None:
        class _AuthFailureModel:
            def __init__(self) -> None:
                self.calls = 0

            def invoke(self, messages):
                self.calls += 1
                raise RuntimeError("401 unauthorized")

        model = _AuthFailureModel()
        batch, seeds = self._batch()
        with self.assertRaises(PlanModelError):
            run_batch(
                model,
                batch,
                seeds,
                None,
                retry=RetryPolicy(attempts=3, base_delay=0),
            )
        self.assertEqual(model.calls, 1)

class AuditPlanModelValidationTest(unittest.TestCase):
    def _validate(self, payload: dict, tasks: list[dict], batch_id: str = "batch-0001") -> None:
        validate_batch_output(
            payload,
            {"id": batch_id, "kind": "entry"},
            tasks,
        )

    def test_accepts_complete_group_order(self) -> None:
        tasks = [_task("entry-a"), _task("entry-b")]
        self._validate(
            {"groups": [_group(["entry-a", "entry-b"])], "order": [0]},
            tasks,
        )

    def test_rejects_missing_seed(self) -> None:
        with self.assertRaises(PlanModelError):
            self._validate(
                {"groups": [_group(["entry-a"])], "order": [0]},
                [_task("entry-a"), _task("entry-b")],
            )

    def test_rejects_repeated_seed(self) -> None:
        with self.assertRaises(PlanModelError):
            self._validate(
                {
                    "groups": [_group(["entry-a"]), _group(["entry-a", "entry-b"])],
                    "order": [0, 1],
                },
                [_task("entry-a"), _task("entry-b")],
            )

    def test_rejects_unknown_seed(self) -> None:
        with self.assertRaises(PlanModelError):
            self._validate(
                {"groups": [_group(["entry-x"])], "order": [0]},
                [_task("entry-a")],
            )

    def test_rejects_mixed_kinds(self) -> None:
        with self.assertRaises(PlanModelError):
            self._validate(
                {"groups": [_group(["entry-a", "patch-a"])], "order": [0]},
                [_task("entry-a"), _task("patch-a", kind="patch")],
            )

    def test_rejects_group_larger_than_four(self) -> None:
        tasks = [_task(f"entry-{index}") for index in range(5)]
        with self.assertRaises(PlanModelError):
            self._validate(
                {
                    "groups": [_group([task["id"] for task in tasks])],
                    "order": [0],
                },
                tasks,
            )

    def test_rejects_group_without_shared_path(self) -> None:
        with self.assertRaises(PlanModelError):
            self._validate(
                {"groups": [_group(["entry-a", "entry-b"])], "order": [0]},
                [_task("entry-a", path="src/a.py"), _task("entry-b", path="src/b.py")],
            )

    def test_rejects_blocked_task_in_merged_group(self) -> None:
        with self.assertRaises(PlanModelError):
            self._validate(
                {"groups": [_group(["entry-a", "entry-b"])], "order": [0]},
                [_task("entry-a"), _task("entry-b", status="blocked")],
            )

    def test_allows_blocked_task_as_singleton(self) -> None:
        self._validate(
            {"groups": [_group(["entry-a"])], "order": [0]},
            [_task("entry-a", status="blocked")],
        )

    def test_rejects_invalid_priority(self) -> None:
        with self.assertRaises(PlanModelError):
            self._validate(
                {"groups": [_group(["entry-a"], priority="urgent")], "order": [0]},
                [_task("entry-a")],
            )

    def test_rejects_empty_reason(self) -> None:
        with self.assertRaises(PlanModelError):
            self._validate(
                {"groups": [_group(["entry-a"], reason=" ")], "order": [0]},
                [_task("entry-a")],
            )

    def test_rejects_incomplete_order(self) -> None:
        with self.assertRaises(PlanModelError):
            self._validate(
                {
                    "groups": [_group(["entry-a"]), _group(["entry-b"])],
                    "order": [0],
                },
                [_task("entry-a"), _task("entry-b")],
            )


if __name__ == "__main__":
    unittest.main()
