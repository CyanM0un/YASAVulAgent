from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from yasa_vulnagent.config import Settings
from yasa_vulnagent.stages.discover.finalize.node import finalize
from yasa_vulnagent.stages.discover.ledger import DiscoverLedger
from yasa_vulnagent.stages.discover.review.node import review
from yasa_vulnagent.stages.discover.review.tools import ReviewToolbox
from yasa_vulnagent.stages.discover.schema import empty_state
from yasa_vulnagent.workflow.state import RunContext


class _Response:
    def __init__(self, content: str) -> None:
        self.content = content
        self.tool_calls = []


class _Model:
    def __init__(self, response: str = "{}") -> None:
        self.response = response
        self.prompts: list[str] = []
        self.calls = 0

    def bind_tools(self, tools):
        self.tools = {tool.name: tool for tool in tools}
        return self

    def invoke(self, messages):
        self.calls += 1
        self.prompts.append(str(messages[-1].content))
        return _Response(self.response)


class DiscoverReviewTest(unittest.TestCase):
    def _state(self, root: Path, *, candidate: bool = True):
        repository = root / "repository"
        repository.mkdir()
        (repository / "main.py").write_text("value = input()\n", encoding="utf-8")
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
                        "path": "main.py",
                        "size": 15,
                        "status": "screened" if not candidate else "pending",
                        "usage_hint": "production-candidate",
                        "content_type": "text",
                    }
                ],
                [],
            )
            if candidate:
                ledger.commit_task(
                    {
                        "task_id": "screen-0001",
                        "kind": "screen",
                        "status": "complete",
                        "scope_type": "production-text",
                        "coverage_required": False,
                        "tool_receipts": [],
                        "candidates": [
                            {
                                "path": "main.py",
                                "line_start": 1,
                                "line_end": 1,
                                "kind": "input-candidate",
                                "summary": "input source",
                            }
                        ],
                        "unknowns": [],
                        "deferred": [],
                        "follow_up": [],
                    }
                )
        return state

    def _context(self, root: Path, model=None) -> RunContext:
        settings = Settings(
            api_key="test-key" if model is not None else None,
            base_url="https://example.invalid",
            model="test-model",
            review_timeout=10,
        )
        return RunContext(settings=settings, model=model)

    def test_review_without_debt_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self._state(root, candidate=False)
            model = _Model()
            result = review(
                state,
                SimpleNamespace(context=self._context(root, model)),
            )
            self.assertEqual(model.calls, 0)
            self.assertEqual(result["review"]["status"], "complete")
            self.assertEqual(result["next_action"], "finalize")
            self.assertTrue((root / "artifacts" / "review.json").is_file())

    def test_handoff_disposition_creates_confirm_task_and_blocks_finalize(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self._state(root)
            with DiscoverLedger.open(Path(state["ledger_file"])) as ledger:
                debt = ledger.debt_items()
                entry_id = debt[0]["ref_id"]
                ledger.add_messages(gaps=["2 discover screening task(s) await implementation"])
            model = _Model(
                json.dumps(
                    {
                        "route": "finalize",
                        "dispositions": [
                            {
                                "debt_id": f"candidate:{entry_id}",
                                "status": "handoff_to_confirm",
                                "reason": "downstream_confirm",
                                "owner": "confirm",
                                "evidence_refs": [f"entry:{entry_id}"],
                            }
                        ],
                        "new_tasks": [],
                    }
                )
            )
            reviewed = review(
                state,
                SimpleNamespace(context=self._context(root, model)),
            )
            self.assertEqual(reviewed["review"]["status"], "partial")
            self.assertEqual(reviewed["next_action"], "confirm")
            self.assertEqual(reviewed["handoff_count"], 0)
            with DiscoverLedger.open(Path(reviewed["ledger_file"])) as ledger:
                self.assertGreater(ledger.debt_count(), 0)
                tasks = ledger.list_tasks(kind_prefix="confirm")
                self.assertEqual(len(tasks), 1)
                self.assertEqual(tasks[0]["candidate_ids"], [entry_id])
                dispositions = ledger.disposition_rows(status="handoff_to_confirm")
                self.assertEqual(len(dispositions), 1)
                self.assertTrue(dispositions[0]["confirm_task_id"])
                self.assertTrue(dispositions[0]["consumed_at"])
            finalized = finalize(reviewed, None)
            self.assertEqual(finalized["status"], "partial")
            self.assertTrue((root / "artifacts" / "index.json").is_file())
            self.assertFalse((root / "artifacts" / "dispositions.json").exists())

    def test_valid_deferred_can_complete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self._state(root)
            with DiscoverLedger.open(Path(state["ledger_file"])) as ledger:
                entry_id = ledger.debt_items()[0]["ref_id"]
            model = _Model(
                json.dumps(
                    {
                        "route": "finalize",
                        "dispositions": [
                            {
                                "debt_id": f"candidate:{entry_id}",
                                "status": "deferred",
                                "reason": "manual_review",
                                "owner": "manual",
                                "evidence_refs": [f"entry:{entry_id}"],
                                "reopen_condition": "new candidate evidence appears",
                            }
                        ],
                        "new_tasks": [],
                    }
                )
            )
            result = review(state, SimpleNamespace(context=self._context(root, model)))
            self.assertEqual(result["review"]["status"], "complete")
            self.assertEqual(result["deferred_count"], 1)
            self.assertEqual(result["next_action"], "finalize")


    def test_review_can_create_bounded_screen_task(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self._state(root)
            with DiscoverLedger.open(Path(state["ledger_file"])) as ledger:
                entry_id = ledger.debt_items()[0]["ref_id"]
            model = _Model(
                json.dumps(
                    {
                        "route": "screen",
                        "dispositions": [],
                        "new_tasks": [
                            {
                                "source": "candidate",
                                "source_refs": [f"candidate:{entry_id}"],
                                "paths": ["main.py"],
                                "question": "Inspect the candidate boundary.",
                                "reason": "Candidate needs deeper screening.",
                            }
                        ],
                    }
                )
            )
            result = review(state, SimpleNamespace(context=self._context(root, model)))
            self.assertEqual(result["next_action"], "confirm")
            with DiscoverLedger.open(Path(result["ledger_file"])) as ledger:
                tasks = ledger.list_tasks(kind_prefix="screen")
                created = [task for task in tasks if task["status"] == "pending"]
                self.assertEqual(len(created), 1)
                self.assertEqual(created[0]["wave"], 2)
                self.assertEqual(created[0]["scope_count"], 1)
                self.assertTrue(created[0]["coverage_required"])

    def test_covered_disposition_is_rejected_and_debt_stays_open(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self._state(root)
            with DiscoverLedger.open(Path(state["ledger_file"])) as ledger:
                entry_id = ledger.debt_items()[0]["ref_id"]
            model = _Model(
                json.dumps(
                    {
                        "route": "finalize",
                        "dispositions": [
                            {
                                "debt_id": f"candidate:{entry_id}",
                                "status": "covered",
                                "reason": "manual_review",
                                "owner": "review",
                                "evidence_refs": [f"entry:{entry_id}"],
                            }
                        ],
                        "new_tasks": [],
                    }
                )
            )
            result = review(state, SimpleNamespace(context=self._context(root, model)))
            self.assertEqual(result["review"]["status"], "partial")
            self.assertEqual(result["next_action"], "confirm")
            self.assertGreater(result["debt_count"], 0)
            self.assertTrue(result["review"]["blocking_gaps"])

    def test_finalize_with_open_debt_is_partial(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self._state(root)
            model = _Model('{"route":"finalize","dispositions":[],"new_tasks":[]}')
            result = review(state, SimpleNamespace(context=self._context(root, model)))
            self.assertEqual(result["next_action"], "confirm")
            self.assertEqual(result["review"]["status"], "partial")
            finalized = finalize(result, None)
            self.assertEqual(finalized["status"], "partial")

    def test_review_model_failure_is_partial_and_does_not_loop(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self._state(root)
            result = review(state, SimpleNamespace(context=self._context(root, None)))
            self.assertEqual(result["review"]["status"], "partial")
            self.assertEqual(result["next_action"], "confirm")
            self.assertTrue(result["review"]["blocking_gaps"])

    def test_review_toolbox_reads_only_debt_paths_without_coverage_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            (repository / "main.py").write_text("a\nb\nc\n", encoding="utf-8")
            toolbox = ReviewToolbox(repository, ["main.py"])
            self.assertIn("error", toolbox.read_file("other.py"))
            first = toolbox.read_file("main.py", 1, 2)
            self.assertEqual(first["text"], "a\nb")
            self.assertTrue(toolbox.receipts)

    def test_review_closes_disposed_pending_task(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self._state(root, candidate=False)
            with DiscoverLedger.open(Path(state["ledger_file"])) as ledger:
                task_id = ledger.ensure_screen_task(
                    paths=["main.py"],
                    question="bounded review task",
                    origin="review",
                    artifact_dir=str(root / "artifacts"),
                    wave=1,
                )
            model = _Model(
                json.dumps(
                    {
                        "route": "finalize",
                        "dispositions": [
                            {
                                "debt_id": f"task:{task_id}",
                                "status": "not_applicable",
                                "reason": "manual_review",
                                "owner": "review",
                                "evidence_refs": ["source:main.py:1-1"],
                            }
                        ],
                        "new_tasks": [],
                    }
                )
            )
            result = review(state, SimpleNamespace(context=self._context(root, model)))
            self.assertEqual(result["next_action"], "finalize")
            self.assertEqual(result["pending_task_count"], 0)
            with DiscoverLedger.open(Path(result["ledger_file"])) as ledger:
                self.assertEqual(ledger.get_task(task_id)["status"], "closed")


if __name__ == "__main__":
    unittest.main()


class DiscoverReviewFeatureTest(unittest.TestCase):
    _state = DiscoverReviewTest._state
    _context = DiscoverReviewTest._context
    def test_review_auto_executes_missing_mechanism_query(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self._state(root, candidate=False)
            with DiscoverLedger.open(Path(state["ledger_file"])) as ledger:
                ledger.put_mechanism(
                    {
                        "mechanism_id": "mechanism-manual",
                        "kind": "annotation_usage",
                        "name": "@RestController",
                        "role": "registration",
                        "definition_path": "main.py",
                        "line_start": 1,
                        "line_end": 1,
                        "evidence_refs": ["source:main.py:1-1"],
                    }
                )
            model = _Model()
            result = review(state, SimpleNamespace(context=self._context(root, model)))
            self.assertEqual(result["review"]["status"], "complete")
            self.assertEqual(result["next_action"], "finalize")
            with DiscoverLedger.open(Path(result["ledger_file"])) as ledger:
                self.assertEqual(ledger.count_feature_queries(), 1)
                self.assertEqual(ledger.mechanism_rows()[0]["status"], "queried")

    def test_malformed_json_is_retried_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self._state(root)
            model = _Model("not json")
            result = review(state, SimpleNamespace(context=self._context(root, model)))
            self.assertEqual(model.calls, 2)
            self.assertEqual(result["review"]["status"], "partial")
            self.assertTrue(any("malformed" in item for item in result["review"]["warnings"]))
