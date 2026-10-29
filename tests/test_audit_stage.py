from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from yasa_vulnagent.config import Settings
from yasa_vulnagent.stages.audit.node import run_stage
from yasa_vulnagent.workflow.state import RunContext

from audit_fixtures import make_run_state


class AuditStageTest(unittest.TestCase):
    def _run_state(
        self,
        root: Path,
        *,
        entries: list[dict] | None = None,
        patches: list[dict] | None = None,
        overview: bool = False,
    ) -> dict:
        return make_run_state(
            root,
            entries=entries if entries is not None else [],
            patches=patches if patches is not None else [],
            overview=overview,
        )

    def _context(self, *, recursion_limit: int | None = None) -> SimpleNamespace:
        settings = Settings(api_key=None, base_url="http://localhost", model="fake")
        if recursion_limit is not None:
            settings = Settings(
                api_key=None,
                base_url="http://localhost",
                model="fake",
                audit_recursion_limit=recursion_limit,
            )
        return SimpleNamespace(context=RunContext(settings=settings))

    def test_writes_artifacts_and_partial_stage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self._run_state(root)
            update = run_stage(state, runtime=self._context())

            audit_dir = Path(state["stages_dir"]) / "audit"
            for name in (
                "state.json",
                "framework.json",
                "audit.json",
                "prepare.json",
                "business-logic.json",
                "report.md",
                "index.json",
                "validation.json",
                "usage.json",
                "stage.json",
            ):
                self.assertTrue((audit_dir / name).is_file(), name)

            summary = update["audit"]
            self.assertEqual(summary["status"], "partial")
            self.assertNotIn("scaffold", summary)
            self.assertNotIn("pending_nodes", summary)
            self.assertEqual(
                summary["executed_nodes"],
                ["prepare", "plan", "trace", "recon", "trace", "verify", "gate", "finalize"],
            )
            self.assertEqual(
                summary["implemented_nodes"],
                ["prepare", "plan", "trace", "recon", "verify", "gate", "finalize"],
            )
            self.assertIn("prepare", summary)
            self.assertEqual(summary["prepare"]["scope_file_count"], 1)

            stage = json.loads((audit_dir / "stage.json").read_text(encoding="utf-8"))
            self.assertEqual(stage["status"], "partial")
            self.assertNotIn("scaffold", stage["details"])
            self.assertEqual(stage["details"]["executed_nodes"], summary["executed_nodes"])

            audit = json.loads((audit_dir / "audit.json").read_text(encoding="utf-8"))
            for name in (
                "entries",
                "patches",
                "tasks",
                "traces",
                "category_checks",
                "mechanism_checks",
                "summaries",
                "findings",
                "reviews",
            ):
                self.assertEqual(audit[name], [], name)
            self.assertTrue(audit["gaps"])
            self.assertEqual(audit["gaps"][0]["source"], "prepare")
            self.assertEqual(audit["scope"]["files"], ["src/app.py"])
            self.assertNotIn("scaffold", audit)
            self.assertNotIn("pending_nodes", audit)
            self.assertEqual(
                audit["execution"]["implemented_nodes"],
                ["prepare", "plan", "trace", "recon", "verify", "gate", "finalize"],
            )
            self.assertEqual(audit["execution"]["executed_nodes"], summary["executed_nodes"])

            business = json.loads(
                (audit_dir / "business-logic.json").read_text(encoding="utf-8")
            )
            self.assertNotIn("scaffold", business)
            framework = json.loads(
                (audit_dir / "framework.json").read_text(encoding="utf-8")
            )
            self.assertNotIn("scaffold", framework)
            self.assertNotIn("pending_nodes", framework)
            index = json.loads((audit_dir / "index.json").read_text(encoding="utf-8"))
            self.assertNotIn("pending_nodes", index)

            prepare = json.loads((audit_dir / "prepare.json").read_text(encoding="utf-8"))
            self.assertEqual(prepare["stop_reason"], "inputs_unavailable")
            self.assertEqual(prepare["inputs"]["scope_source"], "discover-ledger")

            validation = json.loads(
                (audit_dir / "validation.json").read_text(encoding="utf-8")
            )
            self.assertEqual(validation["status"], "not_run")
            usage = json.loads((audit_dir / "usage.json").read_text(encoding="utf-8"))
            self.assertEqual(usage["totals"]["calls"], 0)
            self.assertIn("not a security conclusion", (audit_dir / "report.md").read_text())

            persisted = json.loads(Path(state["run_file"]).read_text(encoding="utf-8"))
            self.assertEqual(persisted["audit"]["status"], "partial")
            self.assertNotIn("scaffold", persisted["audit"])

    def test_missing_optional_inputs_still_produce_partial(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_run_state(root, entries=None, patches=None)
            update = run_stage(state, runtime=self._context())

            self.assertEqual(update["audit"]["status"], "partial")
            self.assertEqual(update["audit"]["prepare"]["stop_reason"], "inputs_unavailable")
            audit_dir = Path(state["stages_dir"]) / "audit"
            state_payload = json.loads((audit_dir / "state.json").read_text(encoding="utf-8"))
            self.assertEqual(
                state_payload["framework"]["inputs"]["init"], "partial"
            )
            self.assertEqual(
                state_payload["framework"]["inputs"]["discover"], "partial"
            )

    def test_stage_status_uses_graph_result(self) -> None:
        class FakeGraph:
            def invoke(self, state, **kwargs):
                return {
                    "status": "complete",
                    "stop_reason": "gate_complete",
                    "next_action": "finalize",
                    "framework": {
                        "executed": ["prepare", "plan", "trace", "recon", "trace", "verify", "gate", "finalize"],
                        "visits": {},
                    },
                    "gate": {"status": "complete", "action": "finalize"},
                }

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self._run_state(root)
            with patch(
                "yasa_vulnagent.stages.audit.graph.build_audit_graph",
                return_value=FakeGraph(),
            ):
                update = run_stage(state, runtime=self._context())

            self.assertEqual(update["audit"]["status"], "complete")
            stage = json.loads(
                (Path(state["stages_dir"]) / "audit" / "stage.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(stage["status"], "complete")

    def test_repeated_run_stays_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self._run_state(root)
            run_stage(state, runtime=self._context())
            audit_dir = Path(state["stages_dir"]) / "audit"
            audit_file = audit_dir / "audit.json"
            audit = json.loads(audit_file.read_text(encoding="utf-8"))
            audit["tasks"] = [{"id": "task-sentinel"}]
            audit_file.write_text(json.dumps(audit), encoding="utf-8")

            update = run_stage(state, runtime=self._context())

            self.assertEqual(
                update["audit"]["executed_nodes"],
                ["prepare", "plan", "trace", "verify", "gate", "finalize"],
            )
            self.assertEqual(len(list(audit_dir.glob("state.json"))), 1)
            audit = json.loads(audit_file.read_text(encoding="utf-8"))
            self.assertEqual(audit["tasks"], [{"id": "task-sentinel"}])

    def test_resume_resets_visit_counts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self._run_state(root)
            run_stage(state, runtime=self._context())
            audit_dir = Path(state["stages_dir"]) / "audit"
            state_file = audit_dir / "state.json"
            payload = json.loads(state_file.read_text(encoding="utf-8"))
            payload["framework"]["visits"] = {"trace": 4, "gate": 4}
            payload["stop_reason"] = "node_visit_limit"
            state_file.write_text(json.dumps(payload), encoding="utf-8")

            update = run_stage(state, runtime=self._context())

            self.assertNotEqual(update["audit"]["stop_reason"], "node_visit_limit")
            saved = json.loads(state_file.read_text(encoding="utf-8"))
            self.assertEqual(saved["framework"]["invocations"], 2)
            self.assertLess(saved["framework"]["visits"].get("trace", 0), 4)
            self.assertIn("prepare", saved["framework"]["executed"])

    def test_recursion_limit_still_writes_partial_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self._run_state(root)
            update = run_stage(state, runtime=self._context(recursion_limit=1))

            self.assertEqual(update["audit"]["status"], "partial")
            self.assertEqual(update["audit"]["stop_reason"], "recursion_limit")
            audit_dir = Path(state["stages_dir"]) / "audit"
            self.assertTrue((audit_dir / "report.md").is_file())


if __name__ == "__main__":
    unittest.main()
