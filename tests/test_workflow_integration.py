from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from yasa_vulnagent.stages.init.node import run_stage as init_stage
from yasa_vulnagent.workflow.runner import run


class WorkflowIntegrationTest(unittest.TestCase):
    @patch("yasa_vulnagent.stages.init.graph.run_documents", return_value={})
    @patch("yasa_vulnagent.stages.init.graph.run_yasa", return_value={})
    def test_runs_all_stages_and_persists_records(
        self, _yasa_stage, _documents_stage
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()

            state = run(repository)

            self.assertEqual(state["status"], "complete")
            self.assertEqual(
                [stage["name"] for stage in state["stages"]],
                ["init", "discover", "audit", "validate", "report"],
            )
            self.assertEqual(state["stages"][0]["status"], "partial")
            self.assertEqual(state["stages"][1]["status"], "partial")
            self.assertEqual(state["stages"][2]["status"], "partial")
            self.assertNotIn("scaffold", state["stages"][2]["details"])
            self.assertEqual(state["stages"][3]["status"], "complete")
            self.assertEqual(state["stages"][4]["status"], "complete")
            self.assertEqual(state["report"]["status"], "complete")
            report_dir = Path(state["stages"][4]["artifact_dir"])
            for name in ("report.json", "summary.md", "index.json", "state.json", "usage.json"):
                self.assertTrue((report_dir / name).is_file(), name)
            self.assertEqual(state["validation"]["status"], "complete")
            self.assertTrue(Path(state["validation"]["validation_file"]).is_file())
            self.assertNotIn("scaffold", state["audit"])
            self.assertEqual(
                state["audit"]["executed_nodes"],
                ["prepare", "plan", "trace", "recon", "trace", "verify", "gate", "finalize"],
            )
            audit_dir = Path(state["stages"][2]["artifact_dir"])
            for name in (
                "audit.json",
                "business-logic.json",
                "framework.json",
                "index.json",
                "report.md",
                "state.json",
                "validation.json",
                "usage.json",
            ):
                self.assertTrue((audit_dir / name).is_file(), name)
            self.assertEqual(state["discover"]["pending_task_count"], 0)
            self.assertEqual(
                state["stages"][0]["details"]["checks"]["cwe"]["status"],
                "complete",
            )
            self.assertFalse("api_key" in state["config"])
            self.assertTrue(Path(state["stages_dir"]).is_dir())
            self.assertTrue(Path(state["run_file"]).with_name("run.log").is_file())
            for stage in state["stages"]:
                artifact_dir = Path(stage["artifact_dir"])
                artifact_file = Path(stage["artifact_file"])
                self.assertTrue(artifact_dir.is_dir())
                self.assertEqual(json.loads(artifact_file.read_text(encoding="utf-8")), stage)

            record = json.loads(Path(state["run_file"]).read_text(encoding="utf-8"))
            self.assertEqual(record, state)

    @patch("yasa_vulnagent.stages.init.graph.run_documents", return_value={})
    @patch("yasa_vulnagent.stages.init.graph.run_yasa", return_value={})
    def test_custom_output_directory(self, _yasa_stage, _documents_stage) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            output_dir = root / "records"
            repository.mkdir()

            state = run(repository, output_dir)

            self.assertTrue(Path(state["run_file"]).is_relative_to(output_dir.resolve()))

    def test_missing_repository_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing"
            with self.assertRaises(ValueError):
                run(missing)

    @patch("yasa_vulnagent.stages.init.graph.run_documents", return_value={})
    @patch("yasa_vulnagent.stages.init.graph.run_yasa", return_value={})
    def test_failure_record_keeps_persisted_stage_progress(
        self, _yasa_stage, _documents_stage
    ) -> None:
        class FailingGraph:
            def invoke(self, state, **_kwargs):
                init_stage(state)
                raise RuntimeError("stage failed")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()

            with patch("yasa_vulnagent.workflow.runner.build_graph", return_value=FailingGraph()):
                with self.assertRaisesRegex(RuntimeError, "stage failed"):
                    run(repository)

            records = list((repository / ".yasa-vulnagent" / "runs").glob("*/run.json"))
            self.assertEqual(len(records), 1)
            record = json.loads(records[0].read_text(encoding="utf-8"))
            self.assertEqual(record["status"], "failed")
            self.assertEqual([stage["name"] for stage in record["stages"]], ["init"])
            self.assertEqual(record["stages"][0]["status"], "partial")
            self.assertTrue(Path(record["stages"][0]["artifact_file"]).is_file())

    @patch("yasa_vulnagent.stages.init.node.build_init_graph")
    def test_init_failure_updates_formal_stage_record(
        self, build_init_graph
    ) -> None:
        class FailingChildGraph:
            def invoke(self, _state, **_kwargs):
                raise RuntimeError("init failed")

        build_init_graph.return_value = FailingChildGraph()
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            repository.mkdir()

            with self.assertRaisesRegex(RuntimeError, "init failed"):
                run(repository)

            records = list((repository / ".yasa-vulnagent" / "runs").glob("*/run.json"))
            record = json.loads(records[0].read_text(encoding="utf-8"))
            self.assertEqual(record["stages"][0]["status"], "failed")
            self.assertEqual(record["stages"][0]["details"]["error"], "init failed")


if __name__ == "__main__":
    unittest.main()
