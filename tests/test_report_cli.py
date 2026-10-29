from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from report_fixtures import ScriptedModel, draft_payload, make_state, review_payload, route_payload
from yasa_vulnagent.cli import main
from yasa_vulnagent.workflow.runner import run_report


class ReportCliTest(unittest.TestCase):
    def test_report_command_completes_empty_selection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_state(root, confirmed=False)
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["report", "--run-file", state["run_file"]])
            result = json.loads(output.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(result["report"]["status"], "complete")
        self.assertEqual(result["report"]["selected_finding_ids"], [])

    def test_run_report_resumes_from_cached_materials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_state(root)
            with patch(
                "yasa_vulnagent.stages.report.node.build_model",
                return_value=ScriptedModel(
                    [route_payload(), draft_payload(), review_payload()]
                ),
            ):
                first = run_report(Path(state["run_file"]))
            self.assertEqual(first["report"]["status"], "complete")
            with patch(
                "yasa_vulnagent.stages.report.node.build_model",
                return_value=ScriptedModel([]),
            ):
                second = run_report(Path(state["run_file"]))
        self.assertEqual(second["report"]["status"], "complete")
        self.assertEqual(second["report"]["ready"], 1)

    def test_run_report_requires_validate_stage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_state(root, confirmed=False)
            state["stages"] = []
            (root / "run.json").write_text(json.dumps(state), encoding="utf-8")
            with self.assertRaises(ValueError):
                run_report(Path(state["run_file"]))


if __name__ == "__main__":
    unittest.main()
