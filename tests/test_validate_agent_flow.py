from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from langchain_core.messages import AIMessage
from langgraph.runtime import Runtime

from yasa_vulnagent.config import load_settings
from yasa_vulnagent.stages.validate.commands import ShellRunner
from yasa_vulnagent.stages.validate.node import run_stage
from yasa_vulnagent.stages.validate.notes import NoteStore
from yasa_vulnagent.stages.validate.storage import validation_paths
from yasa_vulnagent.workflow.state import RunContext

FINDING = {"id": "finding-1", "title": "x", "verdict": "confirmed"}
PRIMARY_ARTIFACT = "findings/finding-1/evidence.txt"
VERIFIER_ARTIFACT = "verifier/finding-1/verifier.txt"


def _ai(payload: dict | None = None, *, text: str = "", tool_calls: list | None = None) -> AIMessage:
    return AIMessage(
        content=json.dumps(payload) if payload is not None else text,
        tool_calls=tool_calls or [],
        usage_metadata={"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
    )


class ScriptedModel:
    def __init__(self, responses: list) -> None:
        self.responses = list(responses)
        self.seen: list[list] = []

    def bind_tools(self, tools):
        return self

    async def ainvoke(self, messages):
        self.seen.append(list(messages))
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _plan() -> dict:
    return {
        "finding_id": "finding-1",
        "claim": {
            "attacker": "authenticated user",
            "legitimate_actor": "account owner",
            "legitimate_resource": "account",
            "expected_capability": "read own account",
            "security_boundary": "ownership",
            "expected_unauthorized_effect": "read another account",
            "negative_expectation": "denied",
            "rubric": ["read own account"],
        },
        "harness": {
            "mode": "test_case",
            "level": "integration_test",
            "setup": ["start target"],
            "start": ["start target"],
            "baseline": {"description": "own account", "expected": "200"},
            "poc": {"description": "other account", "expected": "200"},
            "negative_controls": [],
            "observations": ["status code"],
            "cleanup": ["stop target"],
            "files": [],
        },
        "assumptions": [],
        "gaps": [],
    }


def _behavior() -> dict:
    return {
        "legitimate_actor": "account owner",
        "legitimate_resource": "account",
        "expected_capability": "read own account",
        "security_boundary": "ownership",
        "security_boundary_crossed": "yes",
    }


def _environment() -> dict:
    return {
        "runtime": "docker",
        "dependencies": ["image:test"],
        "configuration": ["local fixture"],
    }


def _reproduction(artifact: str) -> dict:
    return {
        "setup": ["start target"],
        "inputs": ["synthetic user"],
        "commands": ["pytest"],
        "expected": "own account",
        "observed": "other account",
        "cleanup": ["stop target"],
        "artifacts": [artifact],
    }


def _result_payload() -> dict:
    return {
        "id": "finding-1",
        "finding_id": "finding-1",
        "disposition": "confirmed",
        "execution_status": "completed",
        "validation_method": "pytest",
        "reproduction_level": "integration_test",
        "rubric": ["read own account"],
        "intended_behavior": _behavior(),
        "observed_result": "read another account",
        "environment": _environment(),
        "reproduction": _reproduction(PRIMARY_ARTIFACT),
        "evidence": [{"kind": "test", "description": "observed", "artifact": PRIMARY_ARTIFACT}],
        "negative_controls": [],
        "counterevidence_or_proof_gap": [],
        "artifacts": [PRIMARY_ARTIFACT],
    }


def _verifier_payload() -> dict:
    return {
        "id": "finding-1",
        "finding_id": "finding-1",
        "disposition": "confirmed",
        "execution_status": "completed",
        "validation_method": "pytest",
        "reproduction_level": "integration_test",
        "observed_result": "read another account",
        "environment": _environment(),
        "reproduction": _reproduction(VERIFIER_ARTIFACT),
        "evidence": [{"kind": "test", "description": "observed", "artifact": VERIFIER_ARTIFACT}],
        "verifier": {
            "disposition": "confirmed",
            "independent": True,
            "rerun": True,
            "environment": _environment(),
            "execution": _reproduction(VERIFIER_ARTIFACT),
            "evidence": [
                {"kind": "test", "description": "observed", "artifact": VERIFIER_ARTIFACT}
            ],
        },
    }


class ValidateAgentFlowTest(unittest.TestCase):
    def _state(self, root: Path) -> dict:
        repository = root / "repo"
        repository.mkdir()
        stages = root / "stages"
        (stages / "audit").mkdir(parents=True)
        (stages / "audit" / "audit.json").write_text(
            json.dumps({"findings": [FINDING]}), encoding="utf-8"
        )
        state = {
            "run_id": "run",
            "repository": str(repository),
            "stages_dir": str(stages),
            "run_file": str(root / "run.json"),
            "stages": [],
            "config": {},
        }
        (root / "run.json").write_text(json.dumps(state), encoding="utf-8")
        paths = validation_paths(stages)
        (paths.root / "findings" / "finding-1").mkdir(parents=True)
        (paths.root / "findings" / "finding-1" / "evidence.txt").write_text(
            "ok", encoding="utf-8"
        )
        (paths.root / "verifier" / "finding-1").mkdir(parents=True)
        (paths.root / "verifier" / "finding-1" / "verifier.txt").write_text(
            "ok", encoding="utf-8"
        )
        return state

    def _run(self, state: dict, model: ScriptedModel, settings=None) -> dict:
        settings = settings or load_settings()
        with patch(
            "yasa_vulnagent.stages.validate.node.docker_runtime",
            return_value={"selected": "docker", "available": True},
        ), patch(
            "yasa_vulnagent.stages.validate.node.ensure_environment",
            return_value={
                "status": "ready",
                "handle": {"image": "image:test", "image_id": "sha256:test"},
            },
        ):
            return run_stage(
                state,
                runtime=Runtime(context=RunContext(settings=settings, model=model)),
            )

    def _artifact(self, state: dict) -> dict:
        paths = validation_paths(state["stages_dir"])
        return json.loads(paths.validation_file.read_text(encoding="utf-8"))

    def test_happy_path_produces_confirmed_without_tested_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = self._state(Path(temporary))
            model = ScriptedModel([_ai(_plan()), _ai(_result_payload()), _ai(_verifier_payload())])
            update = self._run(state, model)
            artifact = self._artifact(state)
            agent = json.loads(
                (validation_paths(state["stages_dir"]).root / "findings" / "finding-1" / "agent.json")
                .read_text(encoding="utf-8")
            )
        self.assertEqual(update["validation"]["status"], "complete")
        self.assertEqual(artifact["findings"][0]["disposition"], "confirmed")
        self.assertEqual(artifact["repo_commit"], "working-tree")
        self.assertNotIn("schema_version", artifact)
        self.assertNotIn("tested_source", artifact)
        self.assertNotIn("tested_source", artifact["findings"][0])
        self.assertEqual(artifact["findings"][0]["agent_stop_reason"], "complete")
        self.assertEqual(len(model.seen), 3)
        self.assertEqual(len(agent["calls"]), 1)
        self.assertEqual(agent["calls"][0]["round"], 0)
        self.assertIn("duration_ms", agent["calls"][0])
        self.assertTrue(agent["last_text"])
        self.assertGreaterEqual(agent["elapsed_seconds"], 0)

    def test_json_repair_runs_before_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = self._state(Path(temporary))
            model = ScriptedModel(
                [_ai(_plan()), _ai(text="not json"), _ai(_result_payload()), _ai(_verifier_payload())]
            )
            update = self._run(state, model)
        self.assertEqual(update["validation"]["status"], "complete")

    def test_round_limit_finalizes_with_stop_reason(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = self._state(Path(temporary))
            call = [{"name": "list_directory", "args": {"path": "."}, "id": "call-1"}]
            model = ScriptedModel(
                [
                    _ai(_plan()),
                    _ai(tool_calls=call),
                    _ai(tool_calls=call),
                    _ai(_result_payload()),
                    _ai(_verifier_payload()),
                ]
            )
            settings = replace(load_settings(), validate_agent_max_rounds=1)
            self._run(state, model, settings=settings)
            artifact = self._artifact(state)
        self.assertEqual(artifact["findings"][0]["disposition"], "confirmed")
        self.assertEqual(artifact["findings"][0]["agent_stop_reason"], "round_limit")

    def test_auth_failure_blocks_the_stage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = self._state(Path(temporary))
            model = ScriptedModel([RuntimeError("401 unauthorized")])
            update = self._run(state, model)
            artifact = self._artifact(state)
        self.assertEqual(update["validation"]["status"], "blocked")
        self.assertEqual(artifact["stop_reason"], "model_configuration")

    def test_transient_model_failure_is_per_finding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = self._state(Path(temporary))
            model = ScriptedModel([RuntimeError("503 service unavailable")])
            settings = replace(load_settings(), agent_model_retries=1)
            update = self._run(state, model, settings=settings)
            artifact = self._artifact(state)
        self.assertEqual(update["validation"]["status"], "partial")
        finding = artifact["findings"][0]
        self.assertEqual(finding["disposition"], "unresolved")
        self.assertEqual(finding["agent_stop_reason"], "model_request")

    def test_resume_reuses_existing_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = self._state(Path(temporary))
            paths = validation_paths(state["stages_dir"])
            directory = paths.root / "findings" / "finding-1"
            plan = _plan()
            plan["agent_stop_reason"] = ""
            (directory / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
            primary = _result_payload()
            primary["agent_stop_reason"] = ""
            (directory / "result.json").write_text(json.dumps(primary), encoding="utf-8")
            verifier = _verifier_payload()
            (paths.root / "verifier" / "finding-1" / "result.json").write_text(
                json.dumps(verifier), encoding="utf-8"
            )
            model = ScriptedModel([])
            update = self._run(state, model)
            artifact = self._artifact(state)
        self.assertEqual(update["validation"]["status"], "complete")
        self.assertEqual(artifact["findings"][0]["disposition"], "confirmed")
        self.assertEqual(model.seen, [])

    def test_resume_rejects_malformed_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = self._state(Path(temporary))
            paths = validation_paths(state["stages_dir"])
            directory = paths.root / "findings" / "finding-1"
            (directory / "plan.json").write_text(json.dumps({"finding_id": "finding-1"}), encoding="utf-8")
            model = ScriptedModel([_ai(_plan()), _ai(_result_payload()), _ai(_verifier_payload())])
            update = self._run(state, model)
        self.assertEqual(update["validation"]["status"], "complete")
        self.assertEqual(len(model.seen), 3)

    def test_saved_notes_reappear_in_the_execute_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = self._state(Path(temporary))
            paths = validation_paths(state["stages_dir"])
            directory = paths.root / "findings" / "finding-1"
            notes = NoteStore(directory / "notes.jsonl")
            notes.add("target", "service listens on port 18080")
            model = ScriptedModel([_ai(_plan()), _ai(_result_payload()), _ai(_verifier_payload())])
            self._run(state, model)
            human = model.seen[1][1].content
        self.assertIn("service listens on port 18080", human)

    def test_shell_runner_continues_numbering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log_dir = Path(temporary) / "attempts" / "0001"
            log_dir.mkdir(parents=True)
            (log_dir / "commands.jsonl").write_text(
                json.dumps({"index": 7, "command": "true"}) + "\n", encoding="utf-8"
            )
            runner = ShellRunner(
                root=Path(temporary),
                repository=Path(temporary),
                settings=load_settings(),
                log_dir=log_dir,
            )
        self.assertEqual(runner.count, 7)

    def test_save_note_tool_persists_for_resume(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = self._state(Path(temporary))
            save = {
                "name": "save_note",
                "args": {"key": "target", "text": "port 18080"},
                "id": "call-1",
            }
            model = ScriptedModel(
                [
                    _ai(_plan()),
                    _ai(tool_calls=[save]),
                    _ai(_result_payload()),
                    _ai(_verifier_payload()),
                ]
            )
            self._run(state, model)
            directory = validation_paths(state["stages_dir"]).root / "findings" / "finding-1"
            entries = NoteStore(directory / "notes.jsonl").entries()
        self.assertEqual(entries, [{"key": "target", "text": "port 18080"}])

    def test_usage_cap_stops_before_the_next_call(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = self._state(Path(temporary))
            model = ScriptedModel([_ai(_plan())])
            settings = replace(
                load_settings(),
                validate_max_total_tokens=1,
                validate_agent_max_rounds=2,
            )
            update = self._run(state, model, settings=settings)
            artifact = self._artifact(state)
        self.assertEqual(update["validation"]["status"], "partial")
        finding = artifact["findings"][0]
        self.assertEqual(finding["disposition"], "unresolved")
        self.assertEqual(finding["agent_stop_reason"], "token_budget")

    def test_time_guard_skips_finding_without_calling_the_model(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = self._state(Path(temporary))
            model = ScriptedModel([])
            settings = replace(load_settings(), validate_total_timeout=1)
            update = self._run(state, model, settings=settings)
            artifact = self._artifact(state)
        self.assertEqual(update["validation"]["status"], "partial")
        self.assertEqual(artifact["findings"][0]["agent_stop_reason"], "time_budget")
        self.assertEqual(model.seen, [])

    def test_note_store_rejects_after_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            notes = NoteStore(Path(temporary) / "notes.jsonl", max_notes=1)
            self.assertEqual(notes.add("a", "first")["status"], "ok")
            self.assertIn("error", notes.add("b", "second"))
            self.assertIn("first", notes.text())


if __name__ == "__main__":
    unittest.main()
