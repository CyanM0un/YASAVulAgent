from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from yasa_vulnagent.cli import main
from yasa_vulnagent.storage import save_state
from yasa_vulnagent.workflow.runner import run_audit

from audit_fixtures import make_run_state


class AuditCliTest(unittest.TestCase):
    def _run_file(self, root: Path, *, include_discover: bool = True) -> Path:
        state = make_run_state(root, entries=[], patches=[])
        if not include_discover:
            state["stages"] = [
                record for record in state["stages"] if record["name"] != "discover"
            ]
        state["status"] = "running"
        run_file = Path(state["run_file"])
        save_state(state)
        return run_file

    def test_run_audit_writes_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_file = self._run_file(Path(temporary))
            state = run_audit(run_file)

            self.assertEqual(state["audit"]["status"], "partial")
            self.assertNotIn("scaffold", state["audit"])
            audit_dir = Path(state["stages_dir"]) / "audit"
            self.assertTrue((audit_dir / "audit.json").is_file())
            self.assertTrue((audit_dir / "prepare.json").is_file())
            self.assertTrue((audit_dir / "stage.json").is_file())

    def test_missing_discover_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_file = self._run_file(Path(temporary), include_discover=False)
            with self.assertRaisesRegex(ValueError, "discover"):
                run_audit(run_file)

    def test_mode_cannot_change_after_audit_starts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_file = self._run_file(Path(temporary))
            run_audit(run_file)
            run_audit(run_file, "combined")
            with self.assertRaisesRegex(ValueError, "cannot be changed"):
                run_audit(run_file, "entries")

    def test_cli_audit_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_file = self._run_file(Path(temporary))
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["audit", "--run-file", str(run_file)])

            self.assertEqual(code, 0)
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["audit"]["status"], "partial")


if __name__ == "__main__":
    unittest.main()
