from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from yasa_vulnagent.stages.audit.finalize.node import finalize


class AuditFinalizeTest(unittest.TestCase):
    def _write(self, path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")

    def _read(self, path: Path) -> dict:
        return json.loads(path.read_text(encoding="utf-8"))

    def _setup(self, root: Path, *, gate_status: str, business_status: str = "partial") -> tuple[dict, Path]:
        audit_dir = root / "stages" / "audit"
        audit_dir.mkdir(parents=True)
        self._write(
            audit_dir / "audit.json",
            {
                "run_id": "run-test",
                "mode": "entries",
                "status": "partial",
                "business_artifact": "business-logic.json",
                "scope": {"files": ["src/app.py"], "limitations": []},
                "entries": [],
                "patches": [],
                "tasks": [],
                "traces": [],
                "category_checks": [],
                "mechanism_checks": [],
                "summaries": [],
                "findings": [],
                "reviews": [],
                "gaps": [],
                "gate": {
                    "status": gate_status,
                    "action": "finalize",
                    "stop_reason": "gate_complete" if gate_status == "complete" else "gate_partial",
                    "blocking_count": 0 if gate_status == "complete" else 1,
                    "debts": [],
                    "validation_pending": [],
                },
            },
        )
        self._write(
            audit_dir / "business-logic.json",
            {
                "status": business_status,
                "constraints": [],
                "operations": [],
                "investigations": [],
                "gaps": [],
            },
        )
        state = {
            "run_id": "run-test",
            "artifact_dir": str(audit_dir),
            "audit_file": str(audit_dir / "audit.json"),
            "business_file": str(audit_dir / "business-logic.json"),
            "report_file": str(audit_dir / "report.md"),
            "index_file": str(audit_dir / "index.json"),
            "validation_file": str(audit_dir / "validation.json"),
            "mode": "entries",
            "status": "partial",
            "gate": {},
            "framework": {"executed": ["gate"], "visits": {}, "recon_done": True},
        }
        return state, audit_dir

    def test_finalize_uses_complete_gate_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, audit_dir = self._setup(root, gate_status="complete")

            update = finalize(state)

            self.assertEqual(update["status"], "complete")
            audit = self._read(audit_dir / "audit.json")
            self.assertNotIn("schema_version", audit)
            self.assertEqual(audit["status"], "complete")
            self.assertEqual(self._read(audit_dir / "index.json")["status"], "complete")
            self.assertEqual(self._read(audit_dir / "business-logic.json")["status"], "partial")
            report = (audit_dir / "report.md").read_text(encoding="utf-8")
            self.assertIn("# Audit (complete)", report)
            self.assertNotIn("Pending:", report)
            self.assertEqual(
                self._read(audit_dir / "validation.json")["warnings"],
                ["dynamic validation and external contract validation are pending"],
            )

    def test_finalize_keeps_gate_partial_and_business_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, audit_dir = self._setup(root, gate_status="partial", business_status="complete")

            update = finalize(state)

            self.assertEqual(update["status"], "partial")
            self.assertEqual(self._read(audit_dir / "audit.json")["status"], "partial")
            self.assertEqual(self._read(audit_dir / "index.json")["status"], "partial")
            self.assertEqual(self._read(audit_dir / "business-logic.json")["status"], "complete")
            report = (audit_dir / "report.md").read_text(encoding="utf-8")
            self.assertIn("# Audit (partial)", report)
            self.assertIn("not a security conclusion", report)

    def test_complete_gate_with_open_gap_stays_partial(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, audit_dir = self._setup(root, gate_status="complete")
            audit = self._read(audit_dir / "audit.json")
            audit["gaps"] = [
                {"id": "gap-1", "source": "trace", "reason": "unread source", "paths": []}
            ]
            self._write(audit_dir / "audit.json", audit)

            update = finalize(state)

            self.assertEqual(update["status"], "partial")
            self.assertEqual(self._read(audit_dir / "audit.json")["status"], "partial")

    def test_missing_gate_is_partial(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, audit_dir = self._setup(root, gate_status="complete")
            audit = self._read(audit_dir / "audit.json")
            audit.pop("gate")
            self._write(audit_dir / "audit.json", audit)

            update = finalize(state)

            self.assertEqual(update["status"], "partial")
            self.assertEqual(self._read(audit_dir / "audit.json")["status"], "partial")


if __name__ == "__main__":
    unittest.main()
