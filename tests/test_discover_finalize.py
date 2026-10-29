from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from yasa_vulnagent.stages.discover.finalize.node import finalize
from yasa_vulnagent.stages.discover.ledger import DiscoverLedger
from yasa_vulnagent.stages.discover.schema import empty_state


class DiscoverFinalizeTest(unittest.TestCase):
    def _state(self, root: Path):
        repository = root / "repository"
        repository.mkdir()
        (repository / "Controller.java").write_text(
            "class Controller { void handle(String input) { use(input); } }\n",
            encoding="utf-8",
        )
        artifact_dir = root / "artifacts"
        state = empty_state(
            str(repository),
            str(artifact_dir),
            str(artifact_dir / "state.json"),
            {"status": "partial"},
        )
        state["screen"] = {"initial_wave_complete": True, "wave": 1}
        state["review"] = {
            "status": "complete",
            "route": "finalize",
            "blocking_gap_count": 0,
        }
        with DiscoverLedger.open(artifact_dir / "ledger.sqlite") as ledger:
            ledger.replace_inventory(
                [
                    {
                        "path": "Controller.java",
                        "size": (repository / "Controller.java").stat().st_size,
                        "fingerprint": "fp",
                        "content_type": "text",
                        "usage_hint": "production-candidate",
                        "status": "candidate",
                    }
                ],
                [],
            )
        return state

    def test_zero_confirmed_unknown_entries_can_complete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self._state(root)
            with DiscoverLedger.open(Path(state["ledger_file"])) as ledger:
                ledger.put_entry(
                    {
                        "entry_id": "entry-unknown",
                        "status": "unknown",
                        "kind": "input-candidate",
                        "role": "source",
                        "location": {
                            "path": "Controller.java",
                            "line_start": 1,
                            "line_end": 1,
                        },
                        "summary": "unresolved entry",
                        "reason": "no visible binding",
                        "owner": "confirm",
                        "attempts": ["read source"],
                        "reopen_condition": "runtime probe",
                        "evidence_refs": [],
                    }
                )
            result = finalize(state, None)
            self.assertEqual(result["status"], "complete")
            self.assertEqual(result["confirmed_entry_count"], 0)
            self.assertEqual(result["unknown_entry_count"], 1)
            confirmed = json.loads((root / "artifacts" / "confirmed-entries.json").read_text(encoding="utf-8"))
            self.assertEqual(confirmed, [])

    def test_confirmed_entries_are_exported_separately(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self._state(root)
            with DiscoverLedger.open(Path(state["ledger_file"])) as ledger:
                ledger.put_entry(
                    {
                        "entry_id": "entry-confirmed",
                        "status": "confirmed",
                        "kind": "input-candidate",
                        "role": "source",
                        "location": {
                            "path": "Controller.java",
                            "line_start": 1,
                            "line_end": 1,
                        },
                        "summary": "confirmed",
                        "input_origin": {"summary": "input", "evidence_refs": ["source:Controller.java:1-1"]},
                        "registration": {"summary": "route", "evidence_refs": ["source:Controller.java:1-1"]},
                        "activation": {"summary": "start", "evidence_refs": ["source:Controller.java:1-1"]},
                        "input_binding": {"summary": "bind", "evidence_refs": ["source:Controller.java:1-1"]},
                        "trust_boundary": {"summary": "boundary", "evidence_refs": ["source:Controller.java:1-1"]},
                        "same_file_reviewed": True,
                        "evidence_refs": ["source:Controller.java:1-1"],
                    }
                )
            result = finalize(state, None)
            self.assertEqual(result["status"], "complete")
            confirmed = json.loads((root / "artifacts" / "confirmed-entries.json").read_text(encoding="utf-8"))
            self.assertEqual(len(confirmed), 1)
            self.assertEqual(confirmed[0]["entry_id"], "entry-confirmed")
            self.assertEqual(confirmed[0]["input_origin"]["summary"], "input")
            self.assertTrue((root / "artifacts" / "index.json").is_file())
            self.assertTrue((root / "artifacts" / "files.json").is_file())
            self.assertFalse((root / "artifacts" / "mechanisms.json").exists())
            self.assertFalse((root / "artifacts" / "feature-queries.json").exists())

    def test_open_handoff_and_pending_confirm_task_block_completion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self._state(root)
            with DiscoverLedger.open(Path(state["ledger_file"])) as ledger:
                ledger.put_entry(
                    {
                        "entry_id": "entry-candidate",
                        "status": "candidate",
                        "kind": "input-candidate",
                        "role": "source",
                        "location": {
                            "path": "Controller.java",
                            "line_start": 1,
                            "line_end": 1,
                        },
                        "summary": "candidate",
                        "evidence_refs": [],
                    }
                )
                ledger.put_disposition(
                    debt_id="candidate:entry-candidate",
                    debt_type="candidate",
                    ref_id="entry-candidate",
                    status="handoff_to_confirm",
                    reason="downstream_confirm",
                    owner="confirm",
                    evidence_refs=["entry:entry-candidate"],
                    source="review",
                )
                ledger.ensure_confirm_task(
                    path="Controller.java",
                    candidate_ids=["entry-candidate"],
                    origin="handoff",
                )
            result = finalize(state, None)
            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["stop_reason"], "partial")
            self.assertEqual(result["handoff_count"], 1)
            self.assertGreater(result["pending_task_count"], 0)
            self.assertGreater(result["open_task_count"], 0)

    def test_pending_task_debt_blocks_completion_without_open_task_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self._state(root)
            with DiscoverLedger.open(Path(state["ledger_file"])) as ledger:
                ledger.ensure_screen_task(
                    paths=["Controller.java"],
                    question="bounded check",
                    origin="review",
                    artifact_dir=str(root / "artifacts"),
                    wave=1,
                )
                ledger.set_file_status("Controller.java", "screened")
            result = finalize(state, None)
            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["stop_reason"], "partial")
            self.assertGreater(result["debt_count"], 0)
            self.assertGreater(result["open_task_count"], 0)

    def test_forced_partial_preserves_recursion_stop_reason(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self._state(root)
            state["stop_reason"] = "recursion_limit"
            result = finalize(state, None, force_partial=True)
            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["stop_reason"], "recursion_limit")
            self.assertTrue((root / "artifacts" / "index.json").is_file())
            self.assertTrue((root / "artifacts" / "confirmed-entries.json").is_file())

    def test_disposed_pending_task_does_not_block_completion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self._state(root)
            with DiscoverLedger.open(Path(state["ledger_file"])) as ledger:
                task_id = ledger.ensure_screen_task(
                    paths=["Controller.java"],
                    question="bounded check",
                    origin="review",
                    artifact_dir=str(root / "artifacts"),
                    wave=1,
                )
                ledger.set_file_status("Controller.java", "screened")
                ledger.put_disposition(
                    debt_id=f"task:{task_id}",
                    debt_type="task",
                    ref_id=task_id,
                    status="not_applicable",
                    reason="manual_review",
                    owner="review",
                    evidence_refs=["source:Controller.java:1-1"],
                    source="review",
                )
                ledger.close_task(task_id)
            result = finalize(state, None)
            self.assertEqual(result["status"], "complete")
            self.assertEqual(result["pending_task_count"], 0)
            self.assertEqual(result["open_task_count"], 0)


if __name__ == "__main__":
    unittest.main()
