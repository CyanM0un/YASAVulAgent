from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from yasa_vulnagent.agent.usage import UsageRecorder
from yasa_vulnagent.config import Settings
from yasa_vulnagent.stages.audit.plan.model import (
    PlanConfigurationError,
    PlanModelError,
)
from yasa_vulnagent.stages.audit.plan.node import plan
from yasa_vulnagent.stages.audit.prepare.node import prepare
from yasa_vulnagent.stages.audit.schema import empty_state
from yasa_vulnagent.stages.audit.storage import audit_paths, load_json
from yasa_vulnagent.workflow.state import RunContext

from audit_fixtures import make_run_state, references_for


SOURCE = "src/app.py"


def _entry(entry_id: str, path: str = SOURCE) -> dict:
    return {
        "entry_id": entry_id,
        "status": "confirmed",
        "role": "request-handler",
        "summary": f"Entry {entry_id}",
        "location": {"path": path, "line_start": 1, "line_end": 1},
        "input_origin": {"summary": "external request", "evidence_refs": []},
        "registration": {"summary": "route", "evidence_refs": []},
        "activation": {"summary": "call", "evidence_refs": []},
        "input_binding": {"summary": "path parameter", "evidence_refs": []},
        "trust_boundary": {"summary": "untrusted input", "evidence_refs": []},
        "evidence_refs": [f"source:{path}:1-1"],
    }


def _patch(commit: str, *, units: bool = True) -> dict:
    return {
        "commit": commit,
        "parent": "b" * 40,
        "status": "complete",
        "units": (
            [
                {
                    "id": "unit-1",
                    "kind": "guard",
                    "summary": "reject invalid input",
                    "paths": [SOURCE],
                    "source_refs": [{"path": SOURCE, "start_line": 1, "end_line": 1}],
                }
            ]
            if units
            else []
        ),
        "explanations": [{"kind": "constraint", "text": "reject invalid input"}],
    }


class FakeModel:
    model_name = "fake"

    def __init__(self, responder) -> None:
        self.responder = responder
        self.calls = 0
        self.payloads: list[dict] = []

    def invoke(self, messages):
        self.calls += 1
        text = messages[-1].content
        payload = json.loads(text.split("\n", 1)[1])
        self.payloads.append(payload)
        result = self.responder(payload)
        return SimpleNamespace(
            content=json.dumps(result),
            usage_metadata={
                "input_tokens": 10,
                "output_tokens": 5,
                "total_tokens": 15,
            },
        )


def _singletons(payload: dict) -> dict:
    groups = [
        {
            "seed_task_ids": [task["id"]],
            "priority": "normal",
            "reason": "singleton",
        }
        for task in payload["seed_tasks"]
    ]
    return {"groups": groups, "order": list(range(len(groups)))}


class AuditPlanTest(unittest.TestCase):
    def _prepared(
        self,
        root: Path,
        *,
        entries: list[dict] | None = None,
        patches: list[dict] | None = None,
        mode: str = "combined",
    ) -> tuple[dict, object]:
        run_state = make_run_state(
            root,
            mode=mode,
            entries=entries or [],
            patches=patches or [],
            evidence=[
                {
                    "evidence_id": "e1",
                    "source_file": SOURCE,
                    "line_start": 1,
                    "line_end": 1,
                    "summary": "entry evidence",
                }
            ],
            init_status="complete",
            discover_status="complete",
            overview=True,
        )
        paths = audit_paths(run_state["stages_dir"])
        state = empty_state(run_state, paths)
        state["references"] = references_for(run_state)
        update = prepare(state)
        return {**state, **update}, paths

    def _context(
        self,
        model,
        *,
        batch_size: int = 100,
        api_key: str | None = None,
    ) -> SimpleNamespace:
        settings = Settings(
            api_key=api_key,
            base_url="http://localhost",
            model="fake",
            audit_plan_batch_size=batch_size,
        )
        return SimpleNamespace(
            context=RunContext(
                settings=settings,
                model=model,
                usage=UsageRecorder(),
            )
        )

    def test_plan_builds_entry_task_and_category_checks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, paths = self._prepared(Path(temporary), entries=[_entry("entry-1")], mode="entries")
            business = paths.business_file
            business.write_text('{"sentinel": true}\n', encoding="utf-8")
            model = FakeModel(_singletons)

            result = plan(state, self._context(model))

            self.assertEqual(model.calls, 1)
            self.assertEqual(result["plan"]["status"], "complete")
            self.assertEqual(result["plan"]["model"]["status"], "used")
            self.assertEqual(result["plan"]["task_count"], 1)
            self.assertEqual(len(result["tasks"]), 1)
            self.assertEqual(len(result["category_checks"]), 11)
            self.assertEqual(result["mechanism_checks"], [])
            self.assertEqual(
                {check["category"] for check in result["category_checks"]},
                {
                    "identity_authentication_authorization",
                    "injection_interpretation",
                    "files_paths_archives_uploads",
                    "network_protocol_boundaries",
                    "parsing_deserialization_representation",
                    "secrets_sensitive_data",
                    "state_workflow_business_logic",
                    "resource_exhaustion_availability",
                    "configuration_dependency_supply_chain",
                    "native_binary_unsafe_memory",
                    "open_exploration",
                },
            )
            self.assertTrue(all(check["status"] == "pending" for check in result["category_checks"]))
            self.assertFalse(
                any(
                    "cwe_ids" in check or "checks" in check
                    for check in result["category_checks"]
                )
            )
            persisted = load_json(paths.audit_file)
            self.assertEqual(persisted["tasks"], result["tasks"])
            self.assertEqual(persisted["category_checks"], result["category_checks"])
            self.assertEqual(business.read_text(encoding="utf-8"), '{"sentinel": true}\n')
            self.assertFalse((paths.root / "plan.json").exists())

    def test_plan_builds_patch_mechanism_checks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, paths = self._prepared(
                Path(temporary),
                patches=[_patch("a" * 40)],
                mode="patches",
            )
            model = FakeModel(_singletons)

            result = plan(state, self._context(model))

            self.assertEqual(model.calls, 1)
            self.assertEqual(result["plan"]["status"], "complete")
            self.assertEqual(result["plan"]["patch_task_count"], 1)
            self.assertEqual(len(result["mechanism_checks"]), 3)
            self.assertEqual(
                {check["kind"] for check in result["mechanism_checks"]},
                {"original_path", "bypass", "same_mechanism"},
            )
            self.assertEqual(len(result["tasks"][0]["repair_unit_refs"]), 1)
            self.assertEqual(load_json(paths.audit_file)["mechanism_checks"], result["mechanism_checks"])

    def test_plan_merges_same_path_entries_into_one_group(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, _ = self._prepared(
                Path(temporary),
                entries=[_entry("entry-1"), _entry("entry-2")],
                mode="entries",
            )

            def responder(payload: dict) -> dict:
                ids = [task["id"] for task in payload["seed_tasks"]]
                return {
                    "groups": [
                        {
                            "seed_task_ids": ids,
                            "priority": "high",
                            "reason": "same handler",
                        }
                    ],
                    "order": [0],
                }

            model = FakeModel(responder)
            result = plan(state, self._context(model))

            self.assertEqual(model.calls, 1)
            self.assertEqual(result["plan"]["task_count"], 1)
            self.assertEqual(len(result["category_checks"]), 11)
            self.assertEqual(
                sorted(result["tasks"][0]["entry_ids"]),
                ["entry-1", "entry-2"],
            )
            self.assertEqual(result["tasks"][0]["priority"], "high")

    def test_plan_uses_one_model_call_per_batch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, _ = self._prepared(
                Path(temporary),
                entries=[_entry("entry-1"), _entry("entry-2")],
                mode="entries",
            )
            model = FakeModel(_singletons)

            result = plan(state, self._context(model, batch_size=1))

            self.assertEqual(model.calls, 2)
            self.assertEqual(result["plan"]["batch_count"], 2)
            self.assertEqual(result["plan"]["batch_size"], 1)
            self.assertEqual(result["plan"]["task_count"], 2)
            self.assertIn("cross-batch merging is disabled", result["plan"]["limitations"][0])


    def test_plan_orders_tasks_by_priority_then_batch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, _ = self._prepared(
                Path(temporary),
                entries=[_entry("entry-1")],
                patches=[_patch("a" * 40)],
            )

            def responder(payload: dict) -> dict:
                priority = "high" if payload["kind"] == "patch" else "normal"
                task_id = payload["seed_tasks"][0]["id"]
                return {
                    "groups": [
                        {
                            "seed_task_ids": [task_id],
                            "priority": priority,
                            "reason": "ordered",
                        }
                    ],
                    "order": [0],
                }

            result = plan(state, self._context(FakeModel(responder)))

            self.assertEqual(result["plan"]["batch_count"], 2)
            self.assertEqual(
                [task["kind"] for task in result["tasks"]],
                ["patch", "entry"],
            )

    def test_plan_rejects_invalid_model_output_without_writing_tasks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, paths = self._prepared(Path(temporary), entries=[_entry("entry-1")], mode="entries")
            model = FakeModel(
                lambda payload: {
                    "groups": [
                        {
                            "seed_task_ids": ["task-unknown"],
                            "priority": "normal",
                            "reason": "unknown",
                        }
                    ],
                    "order": [0],
                }
            )

            with self.assertRaises(PlanModelError):
                plan(state, self._context(model))

            self.assertEqual(load_json(paths.audit_file)["tasks"], [])


    def test_plan_hard_fails_when_model_request_fails(self) -> None:
        class FailingModel:
            model_name = "fake"

            def invoke(self, messages):
                raise RuntimeError("provider unavailable")

        with tempfile.TemporaryDirectory() as temporary:
            state, paths = self._prepared(
                Path(temporary),
                entries=[_entry("entry-1")],
                mode="entries",
            )

            with self.assertRaises(PlanModelError):
                plan(state, self._context(FailingModel()))

            self.assertEqual(load_json(paths.audit_file)["tasks"], [])

    def test_plan_requires_a_configured_model_for_seed_tasks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, _ = self._prepared(Path(temporary), entries=[_entry("entry-1")])

            with self.assertRaises(PlanConfigurationError):
                plan(state, self._context(None, api_key=None))

    def test_plan_without_inputs_does_not_call_model(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, paths = self._prepared(Path(temporary))
            model = FakeModel(lambda payload: self.fail("model must not be called"))

            result = plan(state, self._context(model))

            self.assertEqual(model.calls, 0)
            self.assertEqual(result["plan"]["model"]["status"], "not_run")
            self.assertEqual(result["tasks"], [])
            self.assertEqual(result["plan"]["status"], "partial")
            self.assertEqual(load_json(paths.audit_file)["tasks"], [])

    def test_not_applicable_patch_does_not_create_plan_gap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            patch = _patch("a" * 40, units=False)
            patch["status"] = "not_applicable"
            state, paths = self._prepared(
                Path(temporary),
                patches=[patch],
                mode="patches",
            )
            model = FakeModel(_singletons)

            result = plan(state, self._context(model))

            self.assertEqual(result["tasks"][0]["status"], "blocked")
            self.assertEqual(result["plan"]["gaps"], [])
            gaps = load_json(paths.audit_file)["gaps"]
            self.assertFalse(any(gap.get("source") == "plan" for gap in gaps))

    def test_plan_reuses_existing_tasks_without_model_call(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, paths = self._prepared(Path(temporary), entries=[_entry("entry-1")], mode="entries")
            audit = load_json(paths.audit_file)
            audit["tasks"] = [{"id": "task-sentinel"}]
            paths.audit_file.write_text(json.dumps(audit), encoding="utf-8")
            state["framework"]["plan_done"] = True
            model = FakeModel(lambda payload: self.fail("model must not be called"))

            result = plan(state, self._context(model))

            self.assertEqual(model.calls, 0)
            self.assertEqual(result["plan"]["model"]["status"], "existing")
            self.assertEqual(result["tasks"], [{"id": "task-sentinel"}])
            self.assertEqual(load_json(paths.audit_file)["tasks"], [{"id": "task-sentinel"}])

    def test_blocked_patch_is_recorded_as_a_plan_gap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, paths = self._prepared(
                Path(temporary),
                patches=[_patch("a" * 40, units=False)],
                mode="patches",
            )
            model = FakeModel(_singletons)

            result = plan(state, self._context(model))

            self.assertEqual(result["plan"]["status"], "partial")
            self.assertEqual(result["tasks"][0]["status"], "blocked")
            self.assertEqual(result["mechanism_checks"], [])
            self.assertEqual(len(result["plan"]["gaps"]), 1)
            gaps = load_json(paths.audit_file)["gaps"]
            self.assertTrue(any(gap.get("source") == "plan" for gap in gaps))


if __name__ == "__main__":
    unittest.main()
