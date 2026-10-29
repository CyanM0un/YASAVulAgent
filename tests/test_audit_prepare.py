from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from yasa_vulnagent.stages.audit.framework import NODE_NAMES
from yasa_vulnagent.stages.audit.prepare.node import prepare
from yasa_vulnagent.stages.audit.schema import empty_state
from yasa_vulnagent.stages.audit.storage import audit_paths

from audit_fixtures import make_run_state, references_for


SOURCE = "src/app.py"
CONTENT = "def main():\n    return 1\n"
COMMIT = "a" * 40


class AuditPrepareTest(unittest.TestCase):
    def _state(self, root: Path, **kwargs):
        run_state = make_run_state(root, **kwargs)
        paths = audit_paths(run_state["stages_dir"])
        state = empty_state(run_state, paths)
        state["references"] = references_for(run_state)
        return state, paths

    def _entry(self, **overrides):
        entry = {
            "entry_id": "entry-1",
            "status": "confirmed",
            "role": "request-handler",
            "summary": "HTTP entry",
            "location": {"path": SOURCE, "line_start": 1, "line_end": 2},
            "input_origin": {"summary": "request", "evidence_refs": ["evidence:e1"]},
            "registration": {"summary": "route", "evidence_refs": []},
            "activation": {"summary": "call", "evidence_refs": []},
            "input_binding": {"summary": "path", "evidence_refs": []},
            "trust_boundary": {"summary": "external", "evidence_refs": []},
            "evidence_refs": ["source:src/app.py:1-2"],
        }
        entry.update(overrides)
        return entry

    def _evidence(self, **overrides):
        evidence = {
            "evidence_id": "e1",
            "source_file": SOURCE,
            "line_start": 1,
            "line_end": 2,
            "summary": "main entry",
        }
        evidence.update(overrides)
        return evidence

    def _patch(self, **overrides):
        patch = {
            "commit": COMMIT,
            "parent": "b" * 40,
            "status": "complete",
            "units": [
                {
                    "id": "unit-1",
                    "kind": "guard",
                    "summary": "check input",
                    "paths": [SOURCE],
                    "source_refs": [
                        {"path": SOURCE, "start_line": 1, "end_line": 2}
                    ],
                }
            ],
            "explanations": [{"kind": "constraint", "text": "reject bad input"}],
        }
        patch.update(overrides)
        return patch

    def test_entries_are_normalized_with_current_source_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, paths = self._state(
                Path(temporary),
                mode="entries",
                entries=[self._entry()],
                evidence=[self._evidence()],
                init_status="complete",
                discover_status="complete",
                overview=True,
            )
            business = paths.business_file
            business.write_text('{"sentinel": true}\n', encoding="utf-8")

            result = prepare(state)

            self.assertEqual(result["prepare"]["status"], "complete")
            self.assertEqual(result["prepare"]["routes"]["entries"], "used")
            self.assertEqual(result["entries"][0]["entry_location"]["code"], CONTENT.rstrip())
            self.assertEqual(result["entries"][0]["evidence"][0]["path"], SOURCE)
            self.assertEqual(result["entries"][0]["discovery"]["input_origin"]["summary"], "request")
            self.assertEqual(result["scope"]["files"], [SOURCE])
            self.assertEqual(
                json.loads(business.read_text(encoding="utf-8")), {"sentinel": True}
            )

            audit = json.loads(paths.audit_file.read_text(encoding="utf-8"))
            self.assertEqual(audit["scope"]["entry_ids"], ["entry-1"])
            self.assertEqual(audit["entries"][0]["id"], "entry-1")
            self.assertEqual(audit["patches"], [])
            self.assertEqual(
                audit["execution"]["implemented_nodes"], list(NODE_NAMES)
            )
            self.assertNotIn("scaffold", audit)
            self.assertNotIn("pending_nodes", audit)
            self.assertEqual(
                json.loads(paths.prepare_file.read_text(encoding="utf-8"))["inputs"][
                    "scope_source"
                ],
                "discover-ledger",
            )

    def test_patch_graphs_are_normalized_with_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, paths = self._state(
                Path(temporary),
                mode="patches",
                patches=[self._patch()],
                init_status="complete",
                discover_status="complete",
            )

            result = prepare(state)

            self.assertEqual(result["prepare"]["status"], "complete")
            self.assertEqual(result["prepare"]["routes"]["patches"], "used")
            self.assertEqual(len(result["patches"]), 1)
            patch = result["patches"][0]
            self.assertEqual(patch["id"], f"patch-{COMMIT}")
            self.assertEqual(patch["changed_paths"], [SOURCE])
            self.assertEqual(patch["repair_unit_ids"], ["unit-1"])
            self.assertTrue(patch["artifact_file"].endswith("/graph.json"))
            self.assertFalse(paths.business_file.exists())
            self.assertEqual(
                json.loads(paths.audit_file.read_text(encoding="utf-8"))["patches"][0][
                    "id"
                ],
                f"patch-{COMMIT}",
            )

    def test_combined_uses_patches_when_entries_are_empty(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, paths = self._state(
                Path(temporary),
                mode="combined",
                entries=[],
                patches=[self._patch()],
                init_status="complete",
                discover_status="complete",
                overview=True,
            )

            result = prepare(state)

            self.assertEqual(result["prepare"]["routes"]["entries"], "empty")
            self.assertEqual(result["prepare"]["routes"]["patches"], "used")
            self.assertEqual(result["entries"], [])
            self.assertEqual(len(result["patches"]), 1)
            self.assertEqual(result["prepare"]["status"], "partial")
            self.assertTrue(
                any("patches without usable entries" in item for item in result["prepare"]["limitations"])
            )
            audit = json.loads(paths.audit_file.read_text(encoding="utf-8"))
            self.assertEqual(audit["entries"], [])
            self.assertEqual(len(audit["patches"]), 1)

    def test_empty_inputs_are_explicitly_partial(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, paths = self._state(
                Path(temporary),
                mode="combined",
                entries=[],
                patches=[],
                init_status="complete",
                discover_status="complete",
                overview=True,
            )

            result = prepare(state)

            self.assertEqual(result["prepare"]["status"], "partial")
            self.assertEqual(result["prepare"]["stop_reason"], "inputs_unavailable")
            self.assertTrue(result["prepare"]["gaps"])
            self.assertEqual(
                json.loads(paths.prepare_file.read_text(encoding="utf-8"))["stop_reason"],
                "inputs_unavailable",
            )
            audit = json.loads(paths.audit_file.read_text(encoding="utf-8"))
            self.assertTrue(audit["gaps"])
            self.assertEqual(audit["gaps"][0]["source"], "prepare")

    def test_invalid_evidence_is_dropped_and_deduplicated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source_files = {SOURCE: CONTENT, "secret.py": "x = 1\n"}
            entry = self._entry(
                input_origin={
                    "summary": "request",
                    "evidence_refs": [
                        "source:src/app.py:1-2",
                        "source:src/app.py:1-2",
                        "source:src/app.py:1-999",
                        "source:../secret.py:1-1",
                        "evidence:missing",
                    ],
                }
            )
            state, _paths = self._state(
                Path(temporary),
                mode="entries",
                entries=[entry],
                evidence=[self._evidence()],
                source_files=source_files,
                inventories=[SOURCE],
                init_status="complete",
                discover_status="complete",
                overview=True,
            )

            result = prepare(state)

            self.assertEqual(len(result["entries"]), 1)
            self.assertEqual(len(result["entries"][0]["evidence"]), 1)
            gaps = result["prepare"]["gaps"]
            self.assertTrue(any("scope" in item for item in gaps))
            self.assertTrue(any("line range" in item for item in gaps))
            self.assertTrue(any("unknown evidence" in item for item in gaps))

    def test_changed_source_revision_marks_entries_stale(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, _paths = self._state(
                Path(temporary),
                mode="entries",
                entries=[self._entry()],
                evidence=[self._evidence()],
                source_revision="deadbeef",
                init_status="complete",
                discover_status="complete",
                overview=True,
            )

            result = prepare(state)

            self.assertEqual(result["entries"], [])
            self.assertEqual(result["prepare"]["stop_reason"], "inputs_unavailable")
            self.assertTrue(
                any("revision" in item for item in result["prepare"]["limitations"])
            )

    def test_changed_fingerprint_drops_the_reference(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            evidence = self._evidence(source_fingerprint="0" * 64)
            entry = self._entry(
                input_origin={"summary": "request", "evidence_refs": ["evidence:e1"]}
            )
            state, _paths = self._state(
                Path(temporary),
                mode="entries",
                entries=[entry],
                evidence=[evidence],
                init_status="complete",
                discover_status="complete",
                overview=True,
            )

            result = prepare(state)

            self.assertEqual(len(result["entries"]), 1)
            self.assertEqual(result["entries"][0]["evidence"][0]["path"], SOURCE)
            self.assertTrue(
                any("fingerprint" in item for item in result["prepare"]["gaps"])
            )

    def test_missing_ledger_is_a_hard_input_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, paths = self._state(
                Path(temporary),
                entries=[],
                patches=[],
            )
            Path(state["references"]["discover"]["details"]["ledger_file"]).unlink()

            with self.assertRaisesRegex(ValueError, "inventory"):
                prepare(state)
            self.assertFalse(paths.audit_file.exists())

    def test_resume_is_idempotent_and_rejects_changed_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, paths = self._state(
                Path(temporary),
                mode="entries",
                entries=[self._entry()],
                evidence=[self._evidence()],
                init_status="complete",
                discover_status="complete",
                overview=True,
            )
            first = prepare(state)
            state.update(first)
            audit = json.loads(paths.audit_file.read_text(encoding="utf-8"))
            audit["tasks"] = [{"id": "sentinel"}]
            paths.audit_file.write_text(json.dumps(audit), encoding="utf-8")

            second = prepare(state)
            self.assertEqual(second["prepare"]["input_signature"], first["prepare"]["input_signature"])
            audit = json.loads(paths.audit_file.read_text(encoding="utf-8"))
            self.assertEqual(audit["tasks"], [{"id": "sentinel"}])

            (Path(state["references"]["discover"]["artifact_dir"]) / "confirmed-entries.json").write_text(
                "[]\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "changed"):
                prepare(state)


if __name__ == "__main__":
    unittest.main()
