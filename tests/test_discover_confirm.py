from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from yasa_vulnagent.config import Settings
from yasa_vulnagent.stages.discover.confirm.node import _replay_unprocessed_tasks, confirm
from yasa_vulnagent.stages.discover.ledger import DiscoverLedger
from yasa_vulnagent.stages.discover.schema import empty_state
from yasa_vulnagent.workflow.state import RunContext


class _Response:
    def __init__(self, content: str) -> None:
        self.content = content
        self.tool_calls = []


class _Model:
    def __init__(self, response: str | None = None, *, error: str = "") -> None:
        self.response = response or "{}"
        self.error = error
        self.prompts: list[str] = []
        self.calls = 0

    def bind_tools(self, tools):
        self.tools = {tool.name: tool for tool in tools}
        return self

    def invoke(self, messages):
        self.calls += 1
        self.prompts.append(str(messages[-1].content))
        if self.error:
            raise RuntimeError(self.error)
        return _Response(self.response)


class DiscoverConfirmTest(unittest.TestCase):
    def _state(self, root: Path):
        repository = root / "repository"
        repository.mkdir()
        (repository / "Controller.java").write_text(
            "@RestController\nclass Controller {\n  @GetMapping void handle(String input) { use(input); }\n}\n",
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
        with DiscoverLedger.open(artifact_dir / "ledger.sqlite") as ledger:
            ledger.replace_inventory(
                [
                    {
                        "path": "Controller.java",
                        "size": (repository / "Controller.java").stat().st_size,
                        "fingerprint": "controller-fp",
                        "content_type": "text",
                        "usage_hint": "production-candidate",
                        "status": "pending",
                    }
                ],
                [],
            )
            ledger.put_entry(
                {
                    "entry_id": "entry-source",
                    "status": "candidate",
                    "kind": "input-candidate",
                    "role": "source",
                    "location": {
                        "path": "Controller.java",
                        "line_start": 3,
                        "line_end": 3,
                    },
                    "summary": "input source",
                    "evidence_refs": ["source:Controller.java:3-3"],
                }
            )
            ledger.set_file_status("Controller.java", "candidate")
        return state

    def _context(self, root: Path, model: _Model) -> RunContext:
        settings = Settings(
            api_key="test-key",
            base_url="https://example.invalid",
            model="test-model",
            yasa_source_path=root / "missing-yasa",
            yasa_bin_path=root / "missing-bin",
            confirm_timeout=10,
            confirm_max_calls=8,
            confirm_max_tasks=2,
        )
        return RunContext(settings=settings, model=model)

    def _result(self, status: str = "confirmed", **updates):
        value = {
            "entry_id": "entry-source",
            "status": status,
            "role": "source",
            "summary": "confirmed source",
            "location": {
                "path": "Controller.java",
                "line_start": 3,
                "line_end": 3,
            },
            "input_origin": {
                "summary": "HTTP input",
                "evidence_refs": ["source:Controller.java:3-3"],
            },
            "registration": {
                "summary": "controller registration",
                "evidence_refs": ["source:Controller.java:1-1"],
            },
            "activation": {
                "summary": "request dispatch",
                "evidence_refs": ["source:Controller.java:1-1"],
            },
            "input_binding": {
                "summary": "bound to input parameter",
                "evidence_refs": ["source:Controller.java:3-3"],
            },
            "trust_boundary": {
                "summary": "external to internal",
                "evidence_refs": ["source:Controller.java:3-3"],
            },
            "evidence_refs": ["source:Controller.java:3-3"],
        }
        value.update(updates)
        return value

    def test_confirmed_entry_requires_and_persists_five_source_backed_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self._state(root)
            model = _Model(
                json.dumps(
                    {
                        "same_file_reviewed": True,
                        "entry_results": [self._result()],
                        "feature_observations": [],
                    }
                )
            )
            result = confirm(state, SimpleNamespace(context=self._context(root, model)))
            self.assertEqual(result["next_action"], "review")
            self.assertEqual(result["confirmed_entry_count"], 1)
            with DiscoverLedger.open(Path(result["ledger_file"])) as ledger:
                entry = ledger.get_entry("entry-source")
                self.assertEqual(entry["status"], "confirmed")
                self.assertEqual(entry["role"], "source")
                self.assertEqual(entry["same_file_reviewed"], True)
                for field in (
                    "input_origin",
                    "registration",
                    "activation",
                    "input_binding",
                    "trust_boundary",
                ):
                    self.assertTrue(entry[field]["summary"])
                    self.assertTrue(entry[field]["evidence_refs"])
                task = ledger.list_tasks(kind_prefix="confirm")[0]
                self.assertEqual(task["status"], "complete")
                self.assertEqual(task["entry_results"][0]["status"], "confirmed")

    def test_missing_confirmed_field_downgrades_to_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self._state(root)
            value = self._result()
            value.pop("trust_boundary")
            model = _Model(
                json.dumps(
                    {
                        "same_file_reviewed": True,
                        "entry_results": [value],
                        "feature_observations": [],
                    }
                )
            )
            result = confirm(state, SimpleNamespace(context=self._context(root, model)))
            with DiscoverLedger.open(Path(result["ledger_file"])) as ledger:
                entry = ledger.get_entry("entry-source")
                self.assertEqual(entry["status"], "unknown")
                self.assertIn("trust_boundary", entry["reason"])
                self.assertEqual(ledger.list_tasks(kind_prefix="confirm")[0]["status"], "complete")

    def test_unknown_requires_structured_evidence_and_allows_task_completion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self._state(root)
            unknown = self._result(
                status="unknown",
                reason="runtime binding is not visible in static source",
                owner="confirm",
                attempts=["read handler", "read registration"],
                reopen_condition="runtime probe is available",
                evidence_refs=["source:Controller.java:3-3"],
            )
            model = _Model(
                json.dumps(
                    {
                        "same_file_reviewed": True,
                        "entry_results": [unknown],
                        "feature_observations": [],
                    }
                )
            )
            result = confirm(state, SimpleNamespace(context=self._context(root, model)))
            with DiscoverLedger.open(Path(result["ledger_file"])) as ledger:
                entry = ledger.get_entry("entry-source")
                self.assertEqual(entry["status"], "unknown")
                self.assertEqual(entry["reopen_condition"], "runtime probe is available")
                self.assertEqual(ledger.list_tasks(kind_prefix="confirm")[0]["status"], "complete")
            self.assertEqual(result["next_action"], "review")

    def test_model_failure_keeps_candidate_pending(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self._state(root)
            model = _Model(error="temporary failure")
            result = confirm(state, SimpleNamespace(context=self._context(root, model)))
            self.assertEqual(result["next_action"], "review")
            with DiscoverLedger.open(Path(result["ledger_file"])) as ledger:
                self.assertEqual(ledger.get_entry("entry-source")["status"], "candidate")
                task = ledger.list_tasks(kind_prefix="confirm")[0]
                self.assertEqual(task["status"], "partial")
                self.assertIn("temporary failure", task["error"])

    def test_context_failure_is_recorded_as_gap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self._state(root)
            result = confirm(state)
            self.assertEqual(result["stop_reason"], "confirm_context_unavailable")
            with DiscoverLedger.open(Path(result["ledger_file"])) as ledger:
                task = ledger.list_tasks(kind_prefix="confirm")[0]
                self.assertEqual(task["status"], "pending")
                self.assertIn("confirm runtime context is unavailable", ledger.messages("gaps"))

    def test_unprocessed_feature_observation_is_replayed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self._state(root)
            artifact_dir = Path(state["artifact_dir"])
            repository = Path(state["repository"])
            receipt = {
                "tool": "read_file",
                "path": "Controller.java",
                "start_line": 3,
                "end_line": 3,
                "total_lines": 4,
                "truncated": False,
                "status": "ok",
            }
            task = {
                "task_id": "confirm-0001",
                "kind": "confirm",
                "status": "complete",
                "read_ranges": [receipt],
                "tool_receipts": [receipt],
                "feature_observations": [
                    {
                        "kind": "text",
                        "name": "use",
                        "role": "sink",
                        "definition": {
                            "path": "Controller.java",
                            "line_start": 3,
                            "line_end": 3,
                        },
                        "evidence_refs": ["source:Controller.java:3-3"],
                        "query": {
                            "kind": "text",
                            "target": "use",
                            "regex": False,
                            "scope": [],
                            "max_results": 20,
                        },
                    }
                ],
                "candidates": [],
                "unknowns": [],
                "deferred": [],
                "follow_up": [],
            }
            with DiscoverLedger.open(Path(state["ledger_file"])) as ledger:
                ledger.put_task(task)

            with DiscoverLedger.open(Path(state["ledger_file"])) as ledger:
                first = _replay_unprocessed_tasks(
                    ledger,
                    repository,
                    artifact_dir,
                    wave=1,
                    settings=None,
                )
                second = _replay_unprocessed_tasks(
                    ledger,
                    repository,
                    artifact_dir,
                    wave=1,
                    settings=None,
                )
                self.assertEqual(first["tasks"], 1)
                self.assertEqual(ledger.get_task("confirm-0001")["derived_processed"], True)
                self.assertEqual(ledger.count_mechanisms(), 1)
                self.assertEqual(ledger.count_feature_queries(), 1)
                self.assertEqual(second["tasks"], 0)

    def test_same_file_and_screen_scope_are_created_after_confirm(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self._state(root)
            model = _Model(
                json.dumps(
                    {
                        "same_file_reviewed": True,
                        "entry_results": [self._result(status="not_applicable", reason="not an entry", evidence_refs=["source:Controller.java:3-3"])],
                        "same_file_targets": [
                            {"path": "Controller.java", "question": "Inspect sibling handler."}
                        ],
                        "screen_scope": [
                            {
                                "paths": ["Controller.java"],
                                "question": "Inspect broad caller scope.",
                                "reason": "caller graph is broader",
                            }
                        ],
                        "feature_observations": [],
                    }
                )
            )
            confirm(state, SimpleNamespace(context=self._context(root, model)))
            with DiscoverLedger.open(Path(state["ledger_file"])) as ledger:
                self.assertEqual(ledger.get_entry("entry-source")["status"], "not_applicable")
                confirm_tasks = ledger.list_tasks(kind_prefix="confirm")
                self.assertTrue(any(task["origin"] == "same_file" for task in confirm_tasks))
                screen_tasks = ledger.list_tasks(kind_prefix="screen")
                self.assertTrue(any(task["origin"] == "confirm_scope" for task in screen_tasks))


    def test_confirm_review_finalize_closed_loop(self) -> None:
        from yasa_vulnagent.stages.discover.finalize.node import finalize
        from yasa_vulnagent.stages.discover.review.node import review

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self._state(root)
            model = _Model(
                json.dumps(
                    {
                        "same_file_reviewed": True,
                        "entry_results": [self._result()],
                        "feature_observations": [],
                    }
                )
            )
            context = self._context(root, model)
            confirmed = confirm(state, SimpleNamespace(context=context))
            reviewed = review(confirmed, SimpleNamespace(context=context))
            self.assertEqual(reviewed["review"]["status"], "complete")
            self.assertEqual(reviewed["next_action"], "finalize")
            finalized = finalize(reviewed, None)
            self.assertEqual(finalized["status"], "complete")
            self.assertEqual(finalized["confirmed_entry_count"], 1)
            exported = json.loads(
                (root / "artifacts" / "confirmed-entries.json").read_text(encoding="utf-8")
            )
            self.assertEqual(len(exported), 1)


if __name__ == "__main__":
    unittest.main()
