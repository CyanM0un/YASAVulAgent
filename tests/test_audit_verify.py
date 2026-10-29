from __future__ import annotations

import asyncio
import json
import tempfile
import time
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import patch

from yasa_vulnagent.config import Settings
from yasa_vulnagent.stages.audit.budget import AuditBudget
from yasa_vulnagent.stages.audit.storage import audit_paths, write_json
from yasa_vulnagent.stages.audit.trace.result import EvidenceIndex
from yasa_vulnagent.agent.artifacts import ToolResultStore
from yasa_vulnagent.stages.audit.budget import AuditTaskBudget
from yasa_vulnagent.stages.audit.verify.execution import (
    VerifyExecution,
    run_verify_stage,
)
from yasa_vulnagent.stages.audit.verify.inputs import VerifyInputs
from yasa_vulnagent.stages.audit.verify.model import (
    VerifyConfigurationError,
    VerifyModelError,
)
from yasa_vulnagent.stages.audit.verify.result import (
    build_candidate,
    build_review,
    verify_update,
)
from yasa_vulnagent.workflow.state import RunContext


SOURCE = "src/app.py"
TEXT = (
    "def handle(request):\n"
    "    cmd = request.args['cmd']\n"
    "    return run(cmd)\n"
)


def _flow() -> dict:
    evidence = [
        {"path": SOURCE, "start_line": 2, "end_line": 2, "explanation": "request input"},
        {"path": SOURCE, "start_line": 3, "end_line": 3, "explanation": "command sink"},
    ]
    return {
        "id": "flow-1",
        "task_id": "task-1",
        "category": "injection_interpretation",
        "kind": "dataflow",
        "completeness": "complete",
        "source": {"summary": "request input", "evidence": evidence[:1]},
        "sink": {"summary": "command sink", "evidence": evidence[1:]},
        "steps": [],
        "guards": [],
        "reachability": "reachable",
        "triggerability": "triggerable",
        "confidence": "high",
        "summary": "request reaches run",
        "impact": "command execution",
        "preconditions": ["request reaches handle"],
        "unknowns": [],
        "cwe_hints": [78],
        "evidence": evidence,
    }


def _task() -> dict:
    return {
        "id": "task-1",
        "kind": "entry",
        "status": "complete",
        "entry_ids": [],
        "patch_ids": [],
        "paths": [SOURCE],
        "business_refs": {},
    }


def _confirmed_payload(evidence: list[dict]) -> dict:
    return {
        "verdict": "confirmed",
        "title": "request command execution",
        "reason": "the request value reaches run without an effective guard",
        "lower_trust_principal": "HTTP client",
        "entry_point": "request parameter",
        "protected_asset": "host command execution",
        "violated_invariant": "untrusted input must not become a command",
        "source_to_sink": ["request parameter", "run"],
        "control": {"description": "no effective guard", "effective": False},
        "impact": "arbitrary command execution",
        "prerequisites": ["request reaches handle"],
        "severity": "high",
        "confidence": "high",
        "cwe_ids": [78],
        "evidence": evidence,
        "counterevidence": [],
        "missing_facts": [],
        "limitations": [],
    }



def _rejected_payload(evidence: list[dict]) -> dict:
    return {
        "verdict": "rejected",
        "title": "request command execution",
        "reason": "the guard prevents the request value from reaching run",
        "evidence": evidence,
        "counterevidence": [],
        "missing_facts": [],
        "limitations": [],
    }


def _rejected_finding() -> dict:
    return {
        "id": "finding-rejected",
        "task_id": "task-1",
        "candidate_key": "candidate-rejected",
        "verdict": "rejected",
        "title": "guarded query",
        "category": "injection_interpretation",
        "reason": "the guard prevents the request value from reaching run",
        "source_to_sink": ["request parameter", "run"],
        "evidence": [
            {"path": SOURCE, "start_line": 2, "end_line": 2, "explanation": "source"},
            {"path": SOURCE, "start_line": 3, "end_line": 3, "explanation": "sink"},
        ],
    }

class VerifyResultTest(unittest.TestCase):
    def test_candidate_is_deterministic_and_uses_current_code(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / SOURCE).write_text(TEXT, encoding="utf-8")
            index = EvidenceIndex(root, [SOURCE])
            candidate, gaps = build_candidate(_flow(), _task(), {"id": "trace-1"}, index, "run-1")
            self.assertIsNotNone(candidate)
            self.assertFalse(gaps)
            assert candidate is not None
            self.assertEqual(candidate["verdict"], "candidate")
            self.assertEqual(candidate["evidence"][0]["code"], "cmd = request.args['cmd']")
            self.assertTrue(candidate["id"].startswith("finding-"))

    def test_confirmed_requires_fields_and_fresh_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / SOURCE).write_text(TEXT, encoding="utf-8")
            index = EvidenceIndex(root, [SOURCE])
            candidate, _ = build_candidate(_flow(), _task(), {"id": "trace-1"}, index, "run-1")
            assert candidate is not None
            evidence = candidate["evidence"]
            payload = _confirmed_payload(evidence)

            updated, gaps = verify_update(payload, candidate, index, [])
            self.assertTrue(gaps)
            assert updated is not None
            self.assertEqual(updated["verdict"], "needs_validation")
            self.assertTrue(updated["missing_facts"])

            receipts = [
                {
                    "tool": "read_file",
                    "path": SOURCE,
                    "start_line": 1,
                    "end_line": 4,
                    "status": "ok",
                }
            ]
            updated, gaps = verify_update(payload, candidate, index, receipts)
            self.assertFalse(gaps)
            assert updated is not None
            self.assertEqual(updated["verdict"], "confirmed")
            self.assertEqual(updated["severity"], "high")

    def test_missing_confirmed_field_downgrades(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / SOURCE).write_text(TEXT, encoding="utf-8")
            index = EvidenceIndex(root, [SOURCE])
            candidate, _ = build_candidate(_flow(), _task(), {"id": "trace-1"}, index, "run-1")
            assert candidate is not None
            payload = _confirmed_payload(candidate["evidence"])
            payload["control"] = {"description": "", "effective": False}
            receipts = [
                {"tool": "read_file", "path": SOURCE, "start_line": 1, "end_line": 4, "status": "ok"}
            ]
            updated, _ = verify_update(payload, candidate, index, receipts)
            assert updated is not None
            self.assertEqual(updated["verdict"], "needs_validation")
            self.assertIn("control.description", updated["missing_facts"])

    def test_review_requires_fresh_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / SOURCE).write_text(TEXT, encoding="utf-8")
            index = EvidenceIndex(root, [SOURCE])
            candidate, _ = build_candidate(_flow(), _task(), {"id": "trace-1"}, index, "run-1")
            assert candidate is not None
            review, gaps = build_review(
                {
                    "verdict": "confirmed",
                    "reason": "source supports it",
                    "evidence": candidate["evidence"],
                },
                candidate,
                index,
                [],
                review_id_value="review-1",
                mode="independent",
                model="fake",
            )
            self.assertEqual(review["status"], "blocked")
            self.assertTrue(gaps)


class _ToolResponse:
    def __init__(self, content: str, tool_calls=None) -> None:
        self.content = content
        self.tool_calls = tool_calls or []


class _ToolModel:
    def bind_tools(self, tools):
        self.tools = {tool.name: tool for tool in tools}
        return self

    async def ainvoke(self, messages):
        if len(messages) == 2:
            return _ToolResponse(
                "",
                [
                    {
                        "id": "read-1",
                        "name": "read_file",
                        "args": {"path": SOURCE, "start_line": 1, "end_line": 4},
                    }
                ],
            )
        return _ToolResponse(
            json.dumps(
                _confirmed_payload(
                    [
                        {"path": SOURCE, "start_line": 2, "end_line": 2, "explanation": "source"},
                        {"path": SOURCE, "start_line": 3, "end_line": 3, "explanation": "sink"},
                    ]
                )
            )
        )


class VerifyAgentTest(unittest.TestCase):
    def test_agent_reads_source_and_returns_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / SOURCE).write_text(TEXT, encoding="utf-8")
            settings = Settings(api_key=None, base_url="http://localhost", model="fake")
            inputs = VerifyInputs(
                audit={}, scope={"files": [SOURCE]}, entries=[], patches=[], tasks=[_task()],
                traces=[], findings=[], reviews=[], business={}, trace_artifacts={},
                mode="combined", source_revision="working-tree", run_id="run-1",
            )
            execution = VerifyExecution(
                repository=root,
                model=_ToolModel(),
                model_label="fake",
                settings=settings,
                scope_files=[SOURCE],
                run_id="run-1",
                inputs=inputs,
                evidence=EvidenceIndex(root, [SOURCE]),
                task_budget=AuditTaskBudget(deadline=time.monotonic() + 60, max_model_calls=10),
                store=ToolResultStore(root / "tool-results"),
            )
            receipts: list[dict] = []
            payload = asyncio.run(
                execution.run_agent(
                    system_prompt="verify",
                    user_prompt="{}",
                    receipts=receipts,
                    max_rounds=4,
                    stage="audit.verify",
                    task_id="finding-1",
                )
            )
            self.assertEqual(payload["verdict"], "confirmed")
            self.assertEqual(receipts[0]["path"], SOURCE)
            self.assertEqual(receipts[0]["status"], "ok")


class VerifyStageTest(unittest.TestCase):
    def _state(self, root: Path) -> tuple[dict, object]:
        repository = root / "repository"
        (repository / "src").mkdir(parents=True)
        (repository / SOURCE).write_text(TEXT, encoding="utf-8")
        stages = root / "stages"
        paths = audit_paths(stages)
        paths.root.mkdir(parents=True)
        paths.trace_dir.mkdir(parents=True)
        state = {
            "run_id": "run-1",
            "repository": str(repository),
            "artifact_dir": str(paths.root),
            "state_file": str(paths.state_file),
            "audit_file": str(paths.audit_file),
            "scope": {"files": [SOURCE]},
            "prepare": {"source_revision": "working-tree"},
            "mode": "combined",
            "tasks": [_task()],
            "traces": [
                {
                    "id": "trace-1",
                    "task_id": "task-1",
                    "kind": "entry",
                    "status": "complete",
                }
            ],
            "framework": {},
        }
        audit = {
            "entries": [],
            "patches": [],
            "tasks": [_task()],
            "traces": state["traces"],
            "findings": [],
            "reviews": [],
            "scope": state["scope"],
        }
        write_json(paths.audit_file, audit)
        write_json(
            paths.trace_dir / "trace-1.json",
            {"id": "trace-1", "task_id": "task-1", "flows": [_flow()]},
        )
        return state, paths

    def _context(self) -> RunContext:
        return RunContext(
            settings=Settings(api_key=None, base_url="http://localhost", model="fake"),
            model=object(),
            audit_budget=AuditBudget.create(60),
        )

    @asynccontextmanager
    async def _no_yasa(self, *_args, **_kwargs):
        yield None

    def test_no_candidates_does_not_need_model(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = {
                "run_id": "run-1",
                "repository": str(Path(temporary) / "repository"),
                "artifact_dir": str(Path(temporary) / "stages" / "audit"),
                "state_file": str(Path(temporary) / "stages" / "audit" / "state.json"),
                "audit_file": str(Path(temporary) / "stages" / "audit" / "audit.json"),
                "scope": {"files": []},
                "tasks": [],
                "traces": [],
                "framework": {},
            }
            Path(state["repository"]).mkdir()
            result = asyncio.run(run_verify_stage(state, self._context()))
            self.assertEqual(result["verify"]["status"], "complete")
            self.assertEqual(result["verify"]["stop_reason"], "no_candidates")
            self.assertEqual(result["findings"], [])

    def test_stage_confirms_with_independent_review(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, paths = self._state(Path(temporary))

            async def fake_agent(self, *, system_prompt, user_prompt, receipts, **_kwargs):
                payload = json.loads(user_prompt)
                receipts.append(
                    {
                        "tool": "read_file",
                        "path": SOURCE,
                        "start_line": 1,
                        "end_line": 4,
                        "status": "ok",
                    }
                )
                evidence = payload.get("candidate", {}).get("evidence") or [
                    {"path": SOURCE, "start_line": 2, "end_line": 2, "explanation": "source"},
                    {"path": SOURCE, "start_line": 3, "end_line": 3, "explanation": "sink"},
                ]
                if "Independent finding review" in system_prompt:
                    return {
                        "verdict": "confirmed",
                        "reason": "current source supports the finding",
                        "evidence": evidence,
                    }
                return _confirmed_payload(evidence)

            with patch.object(VerifyExecution, "run_agent", fake_agent), patch(
                "yasa_vulnagent.stages.audit.verify.execution.open_yasa_mcp",
                self._no_yasa,
            ):
                result = asyncio.run(run_verify_stage(state, self._context()))

            self.assertEqual(result["verify"]["status"], "complete")
            self.assertEqual(result["verify"]["confirmed_count"], 1)
            self.assertEqual(result["verify"]["second_verifier_count"], 0)
            self.assertEqual(len(result["findings"]), 1)
            self.assertEqual(result["findings"][0]["verdict"], "confirmed")
            self.assertEqual(len(result["reviews"]), 1)
            self.assertEqual(result["reviews"][0]["status"], "complete")

    def test_stage_keeps_candidate_on_model_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, _paths = self._state(Path(temporary))

            async def fail_agent(self, **_kwargs):
                raise VerifyModelError("model unavailable")

            with patch.object(VerifyExecution, "run_agent", fail_agent), patch(
                "yasa_vulnagent.stages.audit.verify.execution.open_yasa_mcp",
                self._no_yasa,
            ):
                result = asyncio.run(run_verify_stage(state, self._context()))

            self.assertEqual(result["verify"]["status"], "partial")
            self.assertEqual(result["verify"]["unverified_count"], 1)
            self.assertEqual(result["findings"][0]["verdict"], "candidate")


    def test_rejected_finding_is_reviewed_without_reverification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, paths = self._state(Path(temporary))
            state["traces"] = []
            audit = json.loads(paths.audit_file.read_text(encoding="utf-8"))
            audit["traces"] = []
            audit["findings"] = [_rejected_finding()]
            write_json(paths.audit_file, audit)
            calls: list[str] = []

            async def fake_agent(self, *, system_prompt, user_prompt, receipts, **_kwargs):
                payload = json.loads(user_prompt)
                receipts.append(
                    {
                        "tool": "read_file",
                        "path": SOURCE,
                        "start_line": 1,
                        "end_line": 4,
                        "status": "ok",
                    }
                )
                evidence = payload.get("candidate", {}).get("evidence") or [
                    {"path": SOURCE, "start_line": 2, "end_line": 2, "explanation": "source"},
                    {"path": SOURCE, "start_line": 3, "end_line": 3, "explanation": "sink"},
                ]
                if "Independent finding review" in system_prompt:
                    calls.append("review")
                    return _rejected_payload(evidence)
                calls.append("verify")
                return _rejected_payload(evidence)

            with patch.object(VerifyExecution, "run_agent", fake_agent), patch(
                "yasa_vulnagent.stages.audit.verify.execution.open_yasa_mcp",
                self._no_yasa,
            ):
                result = asyncio.run(run_verify_stage(state, self._context()))

            self.assertEqual(calls, ["review"])
            self.assertEqual(result["verify"]["status"], "complete")
            self.assertEqual(result["verify"]["rejected_count"], 1)
            self.assertEqual(result["findings"][0]["verdict"], "rejected")
            self.assertEqual(result["reviews"][0]["status"], "complete")
            self.assertEqual(result["verify"]["second_verifier_count"], 0)

    def test_rejected_review_conflict_uses_second_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, paths = self._state(Path(temporary))
            state["traces"] = []
            audit = json.loads(paths.audit_file.read_text(encoding="utf-8"))
            audit["traces"] = []
            audit["findings"] = [_rejected_finding()]
            write_json(paths.audit_file, audit)
            calls: list[str] = []

            async def fake_agent(self, *, system_prompt, user_prompt, receipts, **_kwargs):
                payload = json.loads(user_prompt)
                receipts.append(
                    {
                        "tool": "read_file",
                        "path": SOURCE,
                        "start_line": 1,
                        "end_line": 4,
                        "status": "ok",
                    }
                )
                evidence = payload.get("candidate", {}).get("evidence") or [
                    {"path": SOURCE, "start_line": 2, "end_line": 2, "explanation": "source"},
                    {"path": SOURCE, "start_line": 3, "end_line": 3, "explanation": "sink"},
                ]
                if "Independent finding review" in system_prompt:
                    calls.append("review")
                    return _confirmed_payload(evidence)
                if payload.get("mode") == "second_verifier":
                    calls.append("second")
                    return _rejected_payload(evidence)
                calls.append("verify")
                return _rejected_payload(evidence)

            with patch.object(VerifyExecution, "run_agent", fake_agent), patch(
                "yasa_vulnagent.stages.audit.verify.execution.open_yasa_mcp",
                self._no_yasa,
            ):
                result = asyncio.run(run_verify_stage(state, self._context()))

            self.assertEqual(calls, ["review", "second"])
            self.assertEqual(result["verify"]["status"], "complete")
            self.assertEqual(result["verify"]["second_verifier_count"], 1)
            self.assertEqual(result["findings"][0]["verdict"], "rejected")
            self.assertEqual(result["reviews"][0]["mode"], "second_verifier")

    def test_verifier_rejection_is_reviewed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, _paths = self._state(Path(temporary))
            calls: list[str] = []

            async def fake_agent(self, *, system_prompt, user_prompt, receipts, **_kwargs):
                payload = json.loads(user_prompt)
                receipts.append(
                    {
                        "tool": "read_file",
                        "path": SOURCE,
                        "start_line": 1,
                        "end_line": 4,
                        "status": "ok",
                    }
                )
                evidence = payload.get("candidate", {}).get("evidence") or [
                    {"path": SOURCE, "start_line": 2, "end_line": 2, "explanation": "source"},
                    {"path": SOURCE, "start_line": 3, "end_line": 3, "explanation": "sink"},
                ]
                if "Independent finding review" in system_prompt:
                    calls.append("review")
                    return _rejected_payload(evidence)
                calls.append("verify")
                return _rejected_payload(evidence)

            with patch.object(VerifyExecution, "run_agent", fake_agent), patch(
                "yasa_vulnagent.stages.audit.verify.execution.open_yasa_mcp",
                self._no_yasa,
            ):
                result = asyncio.run(run_verify_stage(state, self._context()))

            self.assertEqual(calls, ["verify", "review"])
            self.assertEqual(result["findings"][0]["verdict"], "rejected")
            self.assertEqual(result["reviews"][0]["status"], "complete")

    def test_second_verifier_adjudicates_review_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, _paths = self._state(Path(temporary))
            calls: list[str] = []

            async def fake_agent(self, *, system_prompt, user_prompt, receipts, **_kwargs):
                payload = json.loads(user_prompt)
                receipts.append(
                    {"tool": "read_file", "path": SOURCE, "start_line": 1, "end_line": 4, "status": "ok"}
                )
                evidence = payload.get("candidate", {}).get("evidence") or [
                    {"path": SOURCE, "start_line": 2, "end_line": 2, "explanation": "source"},
                    {"path": SOURCE, "start_line": 3, "end_line": 3, "explanation": "sink"},
                ]
                if "Independent finding review" in system_prompt:
                    calls.append("review")
                    return {"verdict": "rejected", "reason": "guard blocks this path", "evidence": evidence}
                if payload.get("mode") == "second_verifier":
                    calls.append("second")
                    return _confirmed_payload(evidence)
                calls.append("verify")
                return _confirmed_payload(evidence)

            with patch.object(VerifyExecution, "run_agent", fake_agent), patch(
                "yasa_vulnagent.stages.audit.verify.execution.open_yasa_mcp",
                self._no_yasa,
            ):
                result = asyncio.run(run_verify_stage(state, self._context()))

            self.assertEqual(calls, ["verify", "review", "second"])
            self.assertEqual(result["verify"]["confirmed_count"], 1)
            self.assertEqual(result["verify"]["second_verifier_count"], 1)
            self.assertEqual(result["reviews"][0]["mode"], "second_verifier")

    def test_review_conflict_without_second_keeps_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, _paths = self._state(Path(temporary))

            async def fake_agent(self, *, system_prompt, user_prompt, receipts, **_kwargs):
                payload = json.loads(user_prompt)
                receipts.append(
                    {"tool": "read_file", "path": SOURCE, "start_line": 1, "end_line": 4, "status": "ok"}
                )
                evidence = payload.get("candidate", {}).get("evidence") or [
                    {"path": SOURCE, "start_line": 2, "end_line": 2, "explanation": "source"},
                    {"path": SOURCE, "start_line": 3, "end_line": 3, "explanation": "sink"},
                ]
                if "Independent finding review" in system_prompt:
                    return {"verdict": "rejected", "reason": "guard applies", "evidence": evidence}
                if payload.get("mode") == "second_verifier":
                    raise VerifyModelError("second unavailable")
                return _confirmed_payload(evidence)

            with patch.object(VerifyExecution, "run_agent", fake_agent), patch(
                "yasa_vulnagent.stages.audit.verify.execution.open_yasa_mcp",
                self._no_yasa,
            ):
                result = asyncio.run(run_verify_stage(state, self._context()))

            self.assertEqual(result["findings"][0]["verdict"], "candidate")
            self.assertEqual(result["reviews"][0]["status"], "deferred")
            self.assertEqual(result["verify"]["status"], "partial")

    def test_budget_exhaustion_leaves_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, _paths = self._state(Path(temporary))
            context = RunContext(
                settings=Settings(api_key=None, base_url="http://localhost", model="fake"),
                model=object(),
                audit_budget=AuditBudget(deadline=0, started_at=0),
            )
            with patch.object(VerifyExecution, "run_agent") as run_agent, patch(
                "yasa_vulnagent.stages.audit.verify.execution.open_yasa_mcp",
                self._no_yasa,
            ):
                result = asyncio.run(run_verify_stage(state, context))
            run_agent.assert_not_called()
            self.assertEqual(result["verify"]["status"], "partial")
            self.assertEqual(result["verify"]["deferred_count"], 1)

    def test_second_run_reuses_terminal_finding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, _paths = self._state(Path(temporary))
            calls = 0

            async def fake_agent(self, *, system_prompt, user_prompt, receipts, **_kwargs):
                nonlocal calls
                calls += 1
                payload = json.loads(user_prompt)
                receipts.append(
                    {"tool": "read_file", "path": SOURCE, "start_line": 1, "end_line": 4, "status": "ok"}
                )
                evidence = payload.get("candidate", {}).get("evidence") or [
                    {"path": SOURCE, "start_line": 2, "end_line": 2, "explanation": "source"},
                    {"path": SOURCE, "start_line": 3, "end_line": 3, "explanation": "sink"},
                ]
                if "Independent finding review" in system_prompt:
                    return {"verdict": "confirmed", "reason": "supported", "evidence": evidence}
                return _confirmed_payload(evidence)

            with patch.object(VerifyExecution, "run_agent", fake_agent), patch(
                "yasa_vulnagent.stages.audit.verify.execution.open_yasa_mcp",
                self._no_yasa,
            ):
                first = asyncio.run(run_verify_stage(state, self._context()))
                before = calls
                second = asyncio.run(run_verify_stage(first, self._context()))

            self.assertEqual(before, 2)
            self.assertEqual(calls, before)
            self.assertEqual(second["verify"]["confirmed_count"], 1)
            self.assertEqual(second["verify"]["status"], "complete")

    def test_source_revision_mismatch_raises(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, _paths = self._state(Path(temporary))
            state["prepare"]["source_revision"] = "different"
            with self.assertRaises(VerifyConfigurationError):
                asyncio.run(run_verify_stage(state, self._context()))


if __name__ == "__main__":
    unittest.main()
