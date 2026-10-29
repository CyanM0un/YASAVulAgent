from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from langgraph.runtime import Runtime

from report_fixtures import (
    FatalError,
    ScriptedModel,
    draft_payload,
    make_state,
    review_payload,
    route_payload,
)
from yasa_vulnagent.config import load_settings
from yasa_vulnagent.stages.report.node import run_stage
from yasa_vulnagent.stages.report.storage import report_paths
from yasa_vulnagent.workflow.state import RunContext


class ReportStageTest(unittest.TestCase):
    def _run(self, root: Path, responses: list, *, state: dict | None = None) -> tuple[dict, dict]:
        state = state or make_state(root)
        model = ScriptedModel(responses)
        update = run_stage(
            state,
            runtime=Runtime(
                context=RunContext(settings=load_settings(), model=model)
            ),
        )
        artifact = json.loads(
            (Path(state["stages_dir"]) / "report" / "report.json").read_text(
                encoding="utf-8"
            )
        )
        return update, artifact

    def test_happy_path_email_route_and_submission(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_state(root)
            update, artifact = self._run(
                root,
                [route_payload(), draft_payload(), review_payload()],
                state=state,
            )
            paths = report_paths(state["stages_dir"])
            submission = paths.submissions_dir / "finding-1.md"
            envelope = json.loads(
                (paths.submissions_dir / "finding-1.json").read_text(encoding="utf-8")
            )
            submission_text = submission.read_text(encoding="utf-8")
            self.assertTrue(submission.is_file())
            self.assertTrue(paths.summary_file.is_file())
            self.assertTrue(paths.index_file.is_file())
        self.assertEqual(update["report"]["status"], "complete")
        self.assertEqual(update["status"], "complete")
        self.assertEqual(artifact["status"], "complete")
        self.assertNotIn("schema_version", artifact)
        item = artifact["findings"][0]
        self.assertEqual(item["status"], "ready")
        self.assertEqual(item["route_status"], "confirmed")
        self.assertEqual(item["format"], "email")
        self.assertEqual(item["subject"], "Remote command execution in widget")
        self.assertEqual(envelope["recipient"], "security@example.com")
        self.assertTrue(artifact["direct_submit_ready"])
        self.assertEqual(item["cwe"], ["CWE-78"])
        self.assertEqual(item["cvss"]["base_score"], 9.8)
        self.assertTrue(item["review"]["independent"])
        self.assertIn("# Proof of concept", submission_text)
        self.assertIn("Base score: 9.8", submission_text)

    def test_default_advisory_when_no_route(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_state(root, policy=None)
            update, artifact = self._run(
                root,
                [
                    {"kind": "github_advisory", "status": "default"},
                    draft_payload(),
                    review_payload(),
                ],
                state=state,
            )
        self.assertEqual(update["report"]["status"], "complete")
        item = artifact["findings"][0]
        self.assertEqual(item["route_status"], "default")
        self.assertEqual(item["format"], "github_advisory")
        self.assertFalse(artifact["direct_submit_ready"])
        self.assertTrue(item["form_fields"]["steps_to_reproduce"])

    def test_review_blocked_marks_item_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_state(root)
            update, artifact = self._run(
                root,
                [route_payload(), draft_payload(), review_payload(status="blocked")],
                state=state,
            )
            submission_exists = (
                Path(state["stages_dir"]) / "report" / "submissions" / "finding-1.md"
            ).is_file()
        self.assertEqual(update["report"]["status"], "partial")
        item = artifact["findings"][0]
        self.assertEqual(item["status"], "blocked")
        self.assertTrue(any("cvss_justified" in gap for gap in item["gaps"]))
        self.assertTrue(submission_exists)

    def test_no_confirmed_findings_completes_without_model(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_state(root, confirmed=False)
            model = ScriptedModel([])
            update = run_stage(
                state,
                runtime=Runtime(
                    context=RunContext(settings=load_settings(), model=model)
                ),
            )
            artifact = json.loads(
                (Path(state["stages_dir"]) / "report" / "report.json").read_text(
                    encoding="utf-8"
                )
            )
        self.assertEqual(update["report"]["status"], "complete")
        self.assertEqual(artifact["findings"], [])
        self.assertEqual(model.seen, [])

    def test_second_run_reuses_cached_materials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_state(root)
            self._run(
                root,
                [route_payload(), draft_payload(), review_payload()],
                state=state,
            )
            model = ScriptedModel([])
            update = run_stage(
                state,
                runtime=Runtime(
                    context=RunContext(settings=load_settings(), model=model)
                ),
            )
        self.assertEqual(update["report"]["status"], "complete")
        self.assertEqual(model.seen, [])

    def test_source_drift_is_a_warning(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_state(root)
            validation_path = Path(state["stages_dir"]) / "validate" / "validation.json"
            validation = json.loads(validation_path.read_text(encoding="utf-8"))
            validation["repo_commit"] = "deadbeef"
            validation_path.write_text(json.dumps(validation), encoding="utf-8")
            update, artifact = self._run(
                root,
                [route_payload(), draft_payload(), review_payload()],
                state=state,
            )
        self.assertEqual(update["report"]["status"], "complete")
        self.assertEqual(artifact["findings"][0]["status"], "ready")
        self.assertTrue(any(gap["id"] == "source-drift" for gap in artifact["gaps"]))

    def test_unresolved_route_keeps_body_pending(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_state(root)
            update, artifact = self._run(
                root,
                [
                    {"kind": "email", "status": "unknown", "source": "SECURITY.md"},
                    draft_payload(),
                    review_payload(),
                ],
                state=state,
            )
        self.assertEqual(update["report"]["status"], "partial")
        item = artifact["findings"][0]
        self.assertEqual(item["status"], "pending")
        self.assertEqual(item["body_status"], "ready")
        self.assertEqual(item["route_status"], "unknown")

    def test_fatal_model_error_blocks_stage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_state(root)
            model = ScriptedModel([FatalError("invalid api key")])
            update = run_stage(
                state,
                runtime=Runtime(
                    context=RunContext(settings=load_settings(), model=model)
                ),
            )
        self.assertEqual(update["report"]["status"], "blocked")
        self.assertEqual(update["report"]["stop_reason"], "model_configuration")

    def test_invalid_draft_is_repaired_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_state(root)
            broken = draft_payload()
            broken["body"] = "# Title\n\nshort"
            update, artifact = self._run(
                root,
                [route_payload(), broken, draft_payload(), review_payload()],
                state=state,
            )
        self.assertEqual(update["report"]["status"], "complete")
        self.assertEqual(artifact["findings"][0]["status"], "ready")


if __name__ == "__main__":
    unittest.main()
