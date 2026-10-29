from __future__ import annotations

import json
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from yasa_vulnagent.config import Settings
from yasa_vulnagent.stages.init.security_history.git_tools import GitToolbox
from yasa_vulnagent.stages.init.security_history.graph import (
    build_security_history_graph,
    discover,
    process,
    summarize,
)
from yasa_vulnagent.stages.init.security_history.model import (
    SecurityHistoryError,
    SecurityHistoryFatalError,
    invoke_model,
)
from yasa_vulnagent.stages.init.security_history.validation import validate_patch_graph
from yasa_vulnagent.workflow.state import RunContext


class _Response:
    def __init__(self, content: str) -> None:
        self.content = content


class _FakeHistoryModel:
    def __init__(self, commit: str, parent: str) -> None:
        self.commit = commit
        self.parent = parent

    def invoke(self, messages):
        system = str(messages[0].content)
        if "historical security-fix discovery agent" in system:
            payload = {"candidates": [{"commit": self.commit, "reason": "message and code"}]}
        elif "reviewing one candidate commit" in system:
            payload = {
                "decision": "security_fix",
                "fix_type": "patch",
                "confidence": "high",
                "rationale": "the changed guard is visible in the diff",
                "security_signals": ["authorization"],
            }
        elif "extracting semantically atomic" in system:
            payload = {
                "units": [
                    {
                        "id": "u1",
                        "kind": "authorization",
                        "summary": "add an authorization guard",
                        "paths": ["src/App.java"],
                        "source_refs": [
                            {
                                "side": "after",
                                "revision": self.commit,
                                "path": "src/App.java",
                                "start_line": 1,
                                "end_line": 1,
                                "text": "class App { boolean allowed(String user) { return user != null; } }",
                                "language": "java",
                            }
                        ],
                    }
                ]
            }
        elif "synthesizing a historical patch graph" in system:
            payload = {
                "schema": "patch-graph",
                "schema_version": 1,
                "commit": self.commit,
                "parent": self.parent,
                "status": "complete",
                "units": [
                    {
                        "id": "u1",
                        "kind": "authorization",
                        "summary": "add an authorization guard",
                        "paths": ["src/App.java"],
                        "source_refs": [
                            {
                                "side": "after",
                                "revision": self.commit,
                                "path": "src/App.java",
                                "start_line": 1,
                                "end_line": 1,
                                "text": "class App { boolean allowed(String user) { return user != null; } }",
                                "language": "java",
                            }
                        ],
                    }
                ],
                "relations": [],
                "subgraphs": [
                    {
                        "id": "repair-1",
                        "purpose": "authorization repair",
                        "unit_ids": ["u1"],
                        "shared_defense_unit_ids": [],
                    }
                ],
                "explanations": [
                    {"kind": "constraint", "text": "authorization is required", "source_refs": []},
                    {"kind": "defense", "text": "the guard is the reference defense", "source_refs": []},
                ],
            }
        else:
            raise AssertionError(f"unexpected model prompt: {system[:160]}")
        return _Response(json.dumps(payload))


class SecurityHistoryTest(unittest.TestCase):
    def test_git_tools_are_bounded_to_captured_head_and_safe_paths(self) -> None:
        with self._repository() as repository:
            toolbox = GitToolbox(repository)
            snapshot = toolbox.snapshot()
            self.assertTrue(snapshot["available"])
            self.assertEqual(snapshot["parent_policy"], "first_parent")
            commits = toolbox.search_commits(max_results=1)
            self.assertTrue(commits["truncated"])
            self.assertIsNotNone(commits["next_cursor"])
            self.assertEqual(toolbox.search_commits(path="../outside")["error"].startswith("path"), True)
            self.assertIn("error", toolbox.read_revision_file(snapshot["head"], "../outside.java"))
            diff = toolbox.read_diff(snapshot["head"], max_chars=40)
            self.assertTrue(diff["truncated"])
            self.assertIsNotNone(diff["next_char"])

    def test_graph_runs_review_then_patch_extraction_and_writes_artifacts(self) -> None:
        with self._repository() as repository:
            toolbox = GitToolbox(repository)
            snapshot = toolbox.snapshot()
            commit = snapshot["head"]
            parent = toolbox.commit_details(commit)["parent"]
            artifact_dir = repository / "artifacts"
            settings = Settings(
                api_key="test-only",
                base_url="https://example.invalid",
                model="fake",
                history_timeout=60,
                history_discovery_timeout=10,
                history_task_timeout=10,
                history_summary_reserve=1,
                history_max_agents=1,
            )
            initial = {
                "repository": str(repository),
                "artifact_dir": str(artifact_dir),
                "warnings": [],
                "candidates": [],
                "reviews": [],
                "patch_results": [],
            }
            result = build_security_history_graph().invoke(
                initial,
                context=RunContext(settings=settings, model=_FakeHistoryModel(commit, parent)),
            )

            index = result["security_history"]
            self.assertEqual(index["status"], "complete")
            self.assertEqual(index["candidate_count"], 1)
            self.assertEqual(index["patch_graph_count"], 1)
            self.assertTrue((artifact_dir / "snapshot.json").is_file())
            self.assertTrue((artifact_dir / "candidates.json").is_file())
            self.assertTrue((artifact_dir / "reviews" / f"{commit}.json").is_file())
            self.assertTrue((artifact_dir / "patches" / commit / "graph.json").is_file())
            graph = json.loads((artifact_dir / "patches" / commit / "graph.json").read_text())
            self.assertEqual(graph["parent"], parent)
            self.assertEqual(graph["units"][0]["source_refs"][0]["revision"], commit)

    def test_patch_graph_validator_rejects_historical_source_mismatch(self) -> None:
        with self._repository() as repository:
            toolbox = GitToolbox(repository)
            snapshot = toolbox.snapshot()
            commit = snapshot["head"]
            candidate = {
                "commit": commit,
                "parent": toolbox.commit_details(commit)["parent"],
            }
            graph = {
                "schema": "patch-graph",
                "schema_version": 1,
                "commit": commit,
                "parent": candidate["parent"],
                "status": "complete",
                "units": [
                    {
                        "id": "u1",
                        "summary": "bad source claim",
                        "paths": ["src/App.java"],
                        "source_refs": [
                            {
                                "side": "after",
                                "revision": commit,
                                "path": "src/App.java",
                                "start_line": 1,
                                "end_line": 1,
                                "text": "this is not historical source",
                                "language": "java",
                            }
                        ],
                    }
                ],
                "relations": [],
                "subgraphs": [],
                "explanations": [],
            }
            result = validate_patch_graph(toolbox, candidate, graph)
            self.assertFalse(result["valid"])
            self.assertTrue(any("source text" in error for error in result["errors"]))

    def test_summary_preserves_discovery_and_review_gaps(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact_dir = Path(temporary) / "run" / "stages" / "init" / "security_history"
            settings = Settings(
                api_key="test-only",
                base_url="https://example.invalid",
                model="fake",
            )
            result = summarize(
                {
                    "repository": temporary,
                    "artifact_dir": str(artifact_dir),
                    "snapshot": {"available": True, "shallow": True},
                    "warnings": [],
                    "discovery_unknowns": ["history search was incomplete"],
                    "discovery_truncated": True,
                    "reviews": [
                        {
                            "commit": "abc",
                            "decision": "uncertain",
                            "unknowns": ["source was not available"],
                        }
                    ],
                    "patch_results": [
                        {
                            "commit": "abc",
                            "status": "timeout",
                            "error": "per-commit task timeout",
                            "warnings": ["diff was truncated"],
                        }
                    ],
                },
                SimpleNamespace(context=RunContext(settings=settings)),
            )

            index = result["security_history"]
            self.assertEqual(index["status"], "partial")
            self.assertTrue(index["discovery_truncated"])
            self.assertIn("history search was incomplete", index["unknowns"])
            self.assertTrue(any("timeout" in gap for gap in index["gaps"]))

    def test_model_error_classifies_configuration_failures_as_fatal(self) -> None:
        class ErrorModel:
            def invoke(self, _messages):
                raise RuntimeError("temporary 503")

        class AuthModel:
            def invoke(self, _messages):
                raise RuntimeError("401 unauthorized")

        with self.assertRaises(SecurityHistoryError) as error:
            invoke_model(ErrorModel(), "system", "user")
        self.assertNotIsInstance(error.exception, SecurityHistoryFatalError)

        with self.assertRaises(SecurityHistoryFatalError):
            invoke_model(AuthModel(), "system", "user")

    def test_invalid_candidate_shape_is_retained_as_partial_discovery(self) -> None:
        class InvalidDiscoveryModel:
            def invoke(self, _messages):
                return _Response('{"candidates": {"commit": "not-an-array"}}')

        with self._repository() as repository:
            artifact_dir = repository / "artifacts"
            snapshot = GitToolbox(repository).snapshot()
            settings = Settings(
                api_key="test-only",
                base_url="https://example.invalid",
                model="fake",
                history_timeout=60,
                history_discovery_timeout=10,
                history_summary_reserve=0,
            )
            result = discover(
                {
                    "repository": str(repository),
                    "artifact_dir": str(artifact_dir),
                    "snapshot": snapshot,
                    "deadline": time.monotonic() + 30,
                    "discovery_deadline": time.monotonic() + 10,
                    "warnings": [],
                },
                SimpleNamespace(context=RunContext(settings=settings, model=InvalidDiscoveryModel())),
            )

            self.assertTrue(result["discovery_truncated"])
            self.assertEqual(result["candidates"], [])
            self.assertTrue(any("non-array" in item for item in result["discovery_unknowns"]))

    def test_process_keeps_other_candidates_after_nonfatal_model_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact_dir = Path(temporary) / "artifacts"
            (artifact_dir / "reviews").mkdir(parents=True)
            (artifact_dir / "patches").mkdir(parents=True)
            settings = Settings(
                api_key="test-only",
                base_url="https://example.invalid",
                model="fake",
                history_max_agents=1,
            )
            state = {
                "repository": temporary,
                "artifact_dir": str(artifact_dir),
                "deadline": time.monotonic() + 10,
                "candidates": [{"commit": "bad"}, {"commit": "good"}],
            }

            def fake_process(_state, candidate, _context):
                if candidate["commit"] == "bad":
                    raise SecurityHistoryError("temporary model failure")
                return {
                    "commit": "good",
                    "review": {"commit": "good", "decision": "not_security_fix"},
                    "patch": {"commit": "good", "status": "skipped"},
                }

            with patch(
                "yasa_vulnagent.stages.init.security_history.graph._process_candidate",
                side_effect=fake_process,
            ):
                result = process(
                    state,
                    SimpleNamespace(context=RunContext(settings=settings)),
                )

            statuses = {item["commit"]: item["status"] for item in result["patch_results"]}
            self.assertEqual(statuses["bad"], "failed")
            self.assertEqual(statuses["good"], "skipped")

    def _repository(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        repository = Path(temporary.name)
        self._git(repository, "init", "-q")
        self._git(repository, "config", "user.email", "test@example.invalid")
        self._git(repository, "config", "user.name", "Test")
        (repository / "src").mkdir()
        (repository / "src" / "App.java").write_text("class App {}\n", encoding="utf-8")
        self._git(repository, "add", ".")
        self._git(repository, "commit", "-qm", "initial")
        (repository / "src" / "App.java").write_text(
            "class App { boolean allowed(String user) { return user != null; } }\n"
            + "// filler for bounded diff tests\n" * 80,
            encoding="utf-8",
        )
        self._git(repository, "commit", "-qam", "fix authorization security issue")
        return _RepositoryContext(repository)

    @staticmethod
    def _git(repository: Path, *args: str) -> None:
        subprocess.run(["git", *args], cwd=repository, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class _RepositoryContext:
    def __init__(self, repository: Path) -> None:
        self.repository = repository

    def __enter__(self) -> Path:
        return self.repository

    def __exit__(self, *_args) -> None:
        return None


if __name__ == "__main__":
    unittest.main()
