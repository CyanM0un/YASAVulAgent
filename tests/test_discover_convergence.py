from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from yasa_vulnagent.config import (
    DEFAULT_CONFIRM_MAX_TASKS,
    DEFAULT_DISCOVER_TIMEOUT,
    DEFAULT_REVIEW_MAX_ROUNDS,
    load_settings,
)
from yasa_vulnagent.stages.discover.confirm.node import (
    _CONFIRM_MAX_CONSECUTIVE_WAVES,
    _expand_after_task,
    _process_confirm_observations,
    confirm,
)
from yasa_vulnagent.stages.discover.ledger import DiscoverLedger
from yasa_vulnagent.stages.discover.review.node import review
from yasa_vulnagent.stages.discover.schema import empty_state
from yasa_vulnagent.stages.discover.storage import persist
from yasa_vulnagent.workflow.state import RunContext


class _Response:
    def __init__(self, content: str) -> None:
        self.content = content
        self.tool_calls: list[dict[str, object]] = []
        self.usage_metadata = {"input_tokens": 10, "output_tokens": 10}


class _StaticModel:
    def __init__(self, content: str) -> None:
        self._content = content

    def bind_tools(self, _tools):
        return self

    def invoke(self, _messages):
        return _Response(self._content)


class DiscoverConvergenceTest(unittest.TestCase):
    def test_defaults_updated_for_discover_convergence(self) -> None:
        self.assertEqual(DEFAULT_DISCOVER_TIMEOUT, 900)
        self.assertEqual(DEFAULT_CONFIRM_MAX_TASKS, 10)
        self.assertEqual(DEFAULT_REVIEW_MAX_ROUNDS, 6)

    def test_derived_origins_do_not_spawn_second_order_expansion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            (repo / "app.py").write_text("def route():\n    pass\n", encoding="utf-8")
            ledger = DiscoverLedger.open(root / "ledger.sqlite")
            try:
                ledger.replace_inventory(
                    [
                        {
                            "path": "app.py",
                            "size": 24,
                            "fingerprint": "fp-1",
                            "content_type": "text",
                            "usage_hint": "production-candidate",
                            "status": "pending",
                        }
                    ],
                    [],
                )
                created = _expand_after_task(
                    ledger,
                    {"task_id": "confirm-sf", "origin": "same_file"},
                    {"same_file_targets": [{"path": "app.py", "question": "again"}]},
                    artifact_dir=root,
                    wave=1,
                    max_same_file=4,
                )
                self.assertEqual(created["confirm"], 0)

                summary = _process_confirm_observations(
                    ledger,
                    repo,
                    [
                        {
                            "task_id": "confirm-feat",
                            "origin": "feature",
                            "read_ranges": [{"path": "app.py", "start_line": 1, "end_line": 2}],
                            "feature_observations": [
                                {"kind": "regex", "target": "route", "evidence_refs": ["app.py:1-2"]}
                            ],
                        }
                    ],
                    artifact_dir=root,
                    wave=1,
                    settings=load_settings(),
                )
                self.assertEqual(summary, {"observations": 0})
            finally:
                ledger.close()

    def test_confirm_self_loops_while_pending_until_consecutive_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            (repo / "a.py").write_text("def a():\n    pass\n", encoding="utf-8")
            (repo / "b.py").write_text("def b():\n    pass\n", encoding="utf-8")
            artifact_dir = root / "discover"
            artifact_dir.mkdir()
            state = empty_state(str(repo), str(artifact_dir), str(artifact_dir / "state.json"), {"status": "complete"})
            with DiscoverLedger.open(Path(state["ledger_file"])) as ledger:
                ledger.replace_inventory(
                    [
                        {
                            "path": "a.py",
                            "size": 20,
                            "fingerprint": "fp-a",
                            "content_type": "text",
                            "usage_hint": "production-candidate",
                            "status": "pending",
                        },
                        {
                            "path": "b.py",
                            "size": 20,
                            "fingerprint": "fp-b",
                            "content_type": "text",
                            "usage_hint": "production-candidate",
                            "status": "pending",
                        },
                    ],
                    [],
                )
                ledger.put_entry(
                    {
                        "entry_id": "e1",
                        "status": "candidate",
                        "role": "source",
                        "location": {"path": "a.py", "line_start": 1, "line_end": 2},
                    }
                )
                ledger.put_entry(
                    {
                        "entry_id": "e2",
                        "status": "candidate",
                        "role": "source",
                        "location": {"path": "b.py", "line_start": 1, "line_end": 2},
                    }
                )
                ledger.ensure_confirm_task(
                    path="a.py",
                    candidate_ids=["e1"],
                    origin="screen",
                    question="Verify e1",
                    artifact_dir=str(artifact_dir),
                    wave=1,
                )
                ledger.ensure_confirm_task(
                    path="b.py",
                    candidate_ids=["e2"],
                    origin="screen",
                    question="Verify e2",
                    artifact_dir=str(artifact_dir),
                    wave=1,
                )
            persist(state)
            model = _StaticModel(
                json.dumps(
                    {
                        "same_file_reviewed": True,
                        "entry_results": [
                            {
                                "entry_id": "e1",
                                "status": "not_applicable",
                                "reason": "helper",
                                "evidence_refs": ["a.py:1-2"],
                                "location": {"path": "a.py", "line_start": 1, "line_end": 2},
                            }
                        ],
                        "feature_observations": [],
                    }
                )
            )
            settings = replace(load_settings(), confirm_max_tasks=1, discover_timeout=0)
            ctx = RunContext(settings=settings, model=model)
            first = confirm(state, SimpleNamespace(context=ctx))
            self.assertEqual(first["next_action"], "confirm")
            self.assertEqual(first["confirm"]["consecutive_waves"], 1)

            # At the consecutive wave cap, confirm yields back to review.
            first["confirm"]["consecutive_waves"] = _CONFIRM_MAX_CONSECUTIVE_WAVES - 1
            model_b = _StaticModel(
                json.dumps(
                    {
                        "same_file_reviewed": True,
                        "entry_results": [
                            {
                                "entry_id": "e2",
                                "status": "not_applicable",
                                "reason": "helper",
                                "evidence_refs": ["b.py:1-2"],
                                "location": {"path": "b.py", "line_start": 1, "line_end": 2},
                            }
                        ],
                        "feature_observations": [],
                    }
                )
            )
            second = confirm(first, SimpleNamespace(context=RunContext(settings=settings, model=model_b)))
            self.assertEqual(second["next_action"], "review")
            self.assertEqual(second["confirm"]["consecutive_waves"], 0)

    def test_review_finalizes_on_round_limit_or_debt_stagnation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
            artifact_dir = root / "discover"
            artifact_dir.mkdir()
            state = empty_state(str(repo), str(artifact_dir), str(artifact_dir / "state.json"), {"status": "complete"})
            with DiscoverLedger.open(Path(state["ledger_file"])) as ledger:
                ledger.replace_inventory(
                    [
                        {
                            "path": "a.py",
                            "size": 6,
                            "fingerprint": "fp-a",
                            "content_type": "text",
                            "usage_hint": "production-candidate",
                            "status": "pending",
                        }
                    ],
                    [],
                )
            persist(state)
            model = _StaticModel(json.dumps({"dispositions": [], "new_tasks": []}))

            # 1) Stagnation exit
            stagnant_state = {
                **state,
                "review_round": 2,
                "review": {"debt_remaining": 1, "stagnant_rounds": 2},
            }
            settings = replace(
                load_settings(),
                review_max_rounds=10,
                review_stagnation_waves=3,
                discover_timeout=0,
            )
            res_stagnant = review(stagnant_state, SimpleNamespace(context=RunContext(settings=settings, model=model)))
            self.assertEqual(res_stagnant["next_action"], "finalize")
            self.assertEqual(res_stagnant["stop_reason"], "review_stagnated")

            # 2) Round limit exit
            round_limit_state = {
                **state,
                "review_round": 5,
                "review": {"debt_remaining": 100, "stagnant_rounds": 0},
            }
            settings_limit = replace(
                load_settings(),
                review_max_rounds=6,
                review_stagnation_waves=10,
                discover_timeout=0,
            )
            res_limit = review(round_limit_state, SimpleNamespace(context=RunContext(settings=settings_limit, model=model)))
            self.assertEqual(res_limit["next_action"], "finalize")
            self.assertEqual(res_limit["stop_reason"], "review_round_limit")
