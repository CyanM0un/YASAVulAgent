from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from langgraph.runtime import Runtime

from yasa_vulnagent.config import load_settings
from yasa_vulnagent.stages.validate.commands import CommandDenied, ShellRunner
from yasa_vulnagent.stages.validate.contract import canonicalize
from yasa_vulnagent.stages.validate.intake import ensure_environment, select_findings
from yasa_vulnagent.stages.validate.node import run_stage, run_validate
from yasa_vulnagent.stages.validate.schema import empty_result
from yasa_vulnagent.stages.validate.storage import validation_paths
from yasa_vulnagent.workflow.state import RunContext


class ValidateIntakeTest(unittest.TestCase):
    def test_default_selection_is_confirmed_and_needs_validation(self) -> None:
        audit = {
            "findings": [
                {"id": "a", "verdict": "confirmed"},
                {"id": "b", "verdict": "needs_validation"},
                {"id": "c", "verdict": "rejected"},
            ]
        }
        self.assertEqual([item["id"] for item in select_findings(audit)], ["a", "b"])

    def test_explicit_rejected_finding_is_rejected(self) -> None:
        audit = {"findings": [{"id": "c", "verdict": "rejected"}]}
        with self.assertRaises(ValueError):
            select_findings(audit, ["c"])

    def test_build_mode_ignores_a_ready_environment_handle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_file = root / "run.json"
            run_file.write_text("{}", encoding="utf-8")
            paths = validation_paths(root / "stages")
            with patch(
                "yasa_vulnagent.stages.validate.intake.environment_handle",
                return_value={"image": "old:tag"},
            ), patch(
                "yasa_vulnagent.stages.validate.environment.node.run_environment"
            ) as rebuild:
                result = ensure_environment(
                    {"run_file": str(run_file)},
                    paths,
                    RunContext(settings=load_settings()),
                    "build",
                )
        self.assertEqual(result["status"], "ready")
        rebuild.assert_called_once_with(run_file, rebuild=True)

    def test_repo_commit_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = validation_paths(Path(temporary) / "stages")
            paths.root.mkdir(parents=True)
            artifact = canonicalize(
                paths=paths,
                run_id="run",
                repository="/repo",
                repo_commit="working-tree",
                source_audit="/audit.json",
                selected=[],
                raw_results={},
                verifier_results={},
                runtime={"selected": "docker", "available": False},
            )
        self.assertEqual(artifact["repo_commit"], "working-tree")
        self.assertNotIn("tested_source", artifact)


class ValidateContractTest(unittest.TestCase):
    def _base(self, root: Path, finding: dict) -> dict:
        result = empty_result(finding)
        result.update(
            {
                "disposition": "confirmed",
                "execution_status": "completed",
                "reproduction_level": "integration_test",
                "intended_behavior": {
                    "legitimate_actor": "user",
                    "legitimate_resource": "account",
                    "expected_capability": "read own account",
                    "security_boundary": "ownership",
                    "security_boundary_crossed": "yes",
                },
                "reproduction": {
                    "setup": ["start local target"],
                    "inputs": ["synthetic user"],
                    "commands": ["python -m pytest"],
                    "expected": "own account",
                    "observed": "other account",
                    "cleanup": ["stop target"],
                    "artifacts": ["primary.txt"],
                },
                "environment": {
                    "runtime": "docker",
                    "dependencies": ["target image"],
                    "configuration": ["local fixture"],
                },
                "evidence": [{"kind": "test", "description": "observed", "artifact": "primary.txt"}],
            }
        )
        return result

    def test_missing_verifier_downgrades_terminal_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = validation_paths(Path(temporary) / "stages")
            paths.root.mkdir(parents=True)
            (paths.root / "primary.txt").write_text("ok", encoding="utf-8")
            finding = {"id": "finding-1"}
            raw = self._base(paths.root, finding)
            artifact = canonicalize(
                paths=paths,
                run_id="run",
                repository="/repo",
                source_audit="/audit.json",
                selected=[finding],
                raw_results={"finding-1": raw},
                verifier_results={},
                runtime={"selected": "docker", "available": True},
                repo_commit="abc",
            )
        self.assertEqual(artifact["findings"][0]["disposition"], "unresolved")
        self.assertIn(
            "fresh verifier",
            " ".join(artifact["findings"][0]["counterevidence_or_proof_gap"]),
        )

    def test_confirmed_requires_independent_verifier_with_own_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = validation_paths(Path(temporary) / "stages")
            paths.root.mkdir(parents=True)
            (paths.root / "primary.txt").write_text("ok", encoding="utf-8")
            (paths.root / "verifier.txt").write_text("ok", encoding="utf-8")
            finding = {"id": "finding-1"}
            raw = self._base(paths.root, finding)
            verifier = {
                "disposition": "confirmed",
                "execution_status": "completed",
                "reproduction": {
                    "setup": ["start local target"],
                    "inputs": ["synthetic user"],
                    "commands": ["python -m pytest"],
                    "expected": "own account",
                    "observed": "other account",
                    "cleanup": ["stop target"],
                    "artifacts": ["verifier.txt"],
                },
                "environment": {
                    "runtime": "docker",
                    "dependencies": ["target image"],
                    "configuration": ["local fixture"],
                },
                "evidence": [{"kind": "test", "description": "observed", "artifact": "verifier.txt"}],
                "verifier": {
                    "independent": True,
                    "rerun": True,
                        "environment": {
                        "runtime": "docker",
                        "dependencies": ["target image"],
                        "configuration": ["local fixture"],
                    },
                    "execution": {
                        "setup": ["start local target"],
                        "inputs": ["synthetic user"],
                        "commands": ["python -m pytest"],
                        "expected": "own account",
                        "observed": "other account",
                        "cleanup": ["stop target"],
                        "artifacts": ["verifier.txt"],
                    },
                    "evidence": [{"kind": "test", "description": "observed", "artifact": "verifier.txt"}],
                },
            }
            artifact = canonicalize(
                paths=paths,
                run_id="run",
                repository="/repo",
                source_audit="/audit.json",
                selected=[finding],
                raw_results={"finding-1": raw},
                verifier_results={"finding-1": verifier},
                runtime={"selected": "docker", "available": True},
                repo_commit="abc",
            )
        self.assertEqual(artifact["findings"][0]["disposition"], "confirmed")

    def test_verifier_disagreement_downgrades(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = validation_paths(Path(temporary) / "stages")
            paths.root.mkdir(parents=True)
            (paths.root / "primary.txt").write_text("ok", encoding="utf-8")
            (paths.root / "verifier.txt").write_text("ok", encoding="utf-8")
            finding = {"id": "finding-1"}
            raw = self._base(paths.root, finding)
            verifier = {
                "disposition": "rejected",
                "execution_status": "completed",
                "reproduction": {
                    "setup": ["start local target"],
                    "inputs": ["synthetic user"],
                    "commands": ["python -m pytest"],
                    "expected": "own account",
                    "observed": "other account",
                    "cleanup": ["stop target"],
                    "artifacts": ["verifier.txt"],
                },
                "environment": {
                    "runtime": "docker",
                    "dependencies": ["target image"],
                    "configuration": ["local fixture"],
                },
                "evidence": [{"kind": "test", "description": "observed", "artifact": "verifier.txt"}],
                "verifier": {
                    "independent": True,
                    "rerun": True,
                        "environment": {
                        "runtime": "docker",
                        "dependencies": ["target image"],
                        "configuration": ["local fixture"],
                    },
                    "execution": {
                        "setup": ["start local target"],
                        "inputs": ["synthetic user"],
                        "commands": ["python -m pytest"],
                        "expected": "own account",
                        "observed": "other account",
                        "cleanup": ["stop target"],
                        "artifacts": ["verifier.txt"],
                    },
                    "evidence": [{"kind": "test", "description": "observed", "artifact": "verifier.txt"}],
                },
            }
            artifact = canonicalize(
                paths=paths,
                run_id="run",
                repository="/repo",
                source_audit="/audit.json",
                selected=[finding],
                raw_results={"finding-1": raw},
                verifier_results={"finding-1": verifier},
                runtime={"selected": "docker", "available": True},
                repo_commit="abc",
            )
        self.assertEqual(artifact["findings"][0]["disposition"], "unresolved")


class ValidateCommandsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.runner = ShellRunner(
            root=self.root,
            repository=self.root,
            settings=load_settings(),
            log_dir=self.root / "commands",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_privileged_and_host_network_are_denied(self) -> None:
        with self.assertRaises(CommandDenied):
            self.runner.check("docker run --privileged image")
        with self.assertRaises(CommandDenied):
            self.runner.check("docker run --network host image")

    def test_host_mount_outside_workspace_is_denied(self) -> None:
        with self.assertRaises(CommandDenied):
            self.runner.check("docker run -v /etc:/etc image")
        with self.assertRaises(CommandDenied):
            self.runner.check("docker run -v $HOME:/work image")
        self.runner.check("docker run -v $VALIDATION_DIR:/work image")

    def test_regular_command_runs_and_is_logged(self) -> None:
        result = self.runner.run("printf hello")
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["stdout"], "hello")
        self.assertTrue(self.runner.commands_file.is_file())


class ValidateStageTest(unittest.TestCase):
    def _state(self, root: Path, findings: list[dict]) -> dict:
        repository = root / "repo"
        repository.mkdir()
        stages = root / "stages"
        (stages / "audit").mkdir(parents=True)
        (stages / "audit" / "audit.json").write_text(
            json.dumps({"findings": findings}), encoding="utf-8"
        )
        environment = stages / "validate" / "environment"
        environment.mkdir(parents=True)
        (environment / "handle.json").write_text(
            json.dumps({"image": "image:test", "image_id": "sha256:test"}),
            encoding="utf-8",
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
        return state

    def test_empty_selection_completes_without_docker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self._state(root, [])
            update = run_stage(
                state,
                runtime=Runtime(context=RunContext(settings=load_settings())),
            )
            paths = validation_paths(state["stages_dir"])
            artifact = json.loads(paths.validation_file.read_text(encoding="utf-8"))
        self.assertEqual(update["validation"]["status"], "complete")
        self.assertEqual(artifact["selected_finding_ids"], [])
        self.assertEqual(artifact["counts"]["selected"], 0)

    def test_docker_unavailable_blocks_without_running_agents(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            finding = {"id": "finding-1", "title": "x", "verdict": "confirmed"}
            state = self._state(root, [finding])
            with patch(
                "yasa_vulnagent.stages.validate.node.docker_runtime",
                return_value={
                    "selected": "docker",
                    "available": False,
                    "reason": "docker_unavailable",
                },
            ), patch(
                "yasa_vulnagent.stages.validate.node.run_plan"
            ) as plan_mock:
                update = run_stage(
                    state,
                    runtime=Runtime(context=RunContext(settings=load_settings())),
                )
            paths = validation_paths(state["stages_dir"])
            artifact = json.loads(paths.validation_file.read_text(encoding="utf-8"))
        self.assertEqual(update["validation"]["status"], "blocked")
        self.assertEqual(artifact["findings"][0]["disposition"], "unresolved")
        plan_mock.assert_not_called()

    def test_run_validate_entrypoint_with_empty_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = self._state(root, [])
            state["stages"] = [
                {
                    "name": "audit",
                    "status": "complete",
                    "artifact_dir": str(Path(state["stages_dir"]) / "audit"),
                }
            ]
            Path(state["run_file"]).write_text(json.dumps(state), encoding="utf-8")
            updated = run_validate(Path(state["run_file"]))
        self.assertEqual(updated["validation"]["status"], "complete")
        self.assertEqual(updated["validation"]["selected_finding_ids"], [])

    def test_patched_agents_produce_a_canonical_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            finding = {"id": "finding-1", "title": "x", "verdict": "confirmed"}
            state = self._state(root, [finding])

            def fake_plan(**kwargs):
                return {
                    "finding_id": "finding-1",
                    "claim": {"attacker": "attacker"},
                    "harness": {
                        "mode": "test_case",
                        "level": "integration_test",
                        "baseline": {"description": "ok"},
                        "poc": {"description": "bad"},
                        "observations": ["exit code"],
                    },
                }

            def fake_execute(**kwargs):
                directory = kwargs["artifact_dir"]
                artifact = directory / "evidence.txt"
                artifact.write_text("ok", encoding="utf-8")
                result = empty_result(finding)
                result.update(
                    {
                        "disposition": "confirmed",
                        "execution_status": "completed",
                        "reproduction_level": "integration_test",
                        "intended_behavior": {
                            "legitimate_actor": "user",
                            "legitimate_resource": "account",
                            "expected_capability": "read own account",
                            "security_boundary": "ownership",
                            "security_boundary_crossed": "yes",
                        },
                        "reproduction": {
                            "setup": ["start local target"],
                            "inputs": ["synthetic user"],
                            "commands": ["python -m pytest"],
                            "expected": "own account",
                            "observed": "other account",
                            "cleanup": ["stop target"],
                            "artifacts": [str(artifact.relative_to(kwargs["paths"].root))],
                        },
                                "environment": {
                            "runtime": "docker",
                            "dependencies": ["target image"],
                            "configuration": ["local fixture"],
                        },
                        "evidence": [
                            {
                                "kind": "test",
                                "description": "observed",
                                "artifact": str(artifact.relative_to(kwargs["paths"].root)),
                            }
                        ],
                    }
                )
                return result

            def fake_verify(**kwargs):
                directory = kwargs["artifact_dir"]
                artifact = directory / "verifier.txt"
                artifact.write_text("ok", encoding="utf-8")
                return {
                    "finding_id": "finding-1",
                    "id": "finding-1",
                    "disposition": "confirmed",
                    "execution_status": "completed",
                    "reproduction": {
                        "setup": ["start local target"],
                        "inputs": ["synthetic user"],
                        "commands": ["python -m pytest"],
                        "expected": "own account",
                        "observed": "other account",
                        "cleanup": ["stop target"],
                        "artifacts": [str(artifact.relative_to(kwargs["paths"].root))],
                    },
                        "environment": {
                        "runtime": "docker",
                        "dependencies": ["target image"],
                        "configuration": ["local fixture"],
                    },
                    "evidence": [
                        {
                            "kind": "test",
                            "description": "observed",
                            "artifact": str(artifact.relative_to(kwargs["paths"].root)),
                        }
                    ],
                    "verifier": {
                        "independent": True,
                        "rerun": True,
                                "environment": {
                            "runtime": "docker",
                            "dependencies": ["target image"],
                            "configuration": ["local fixture"],
                        },
                        "execution": {
                            "setup": ["start local target"],
                            "inputs": ["synthetic user"],
                            "commands": ["python -m pytest"],
                            "expected": "own account",
                            "observed": "other account",
                            "cleanup": ["stop target"],
                            "artifacts": [str(artifact.relative_to(kwargs["paths"].root))],
                        },
                        "evidence": [
                            {
                                "kind": "test",
                                "description": "observed",
                                "artifact": str(artifact.relative_to(kwargs["paths"].root)),
                            }
                        ],
                    },
                }

            with patch(
                "yasa_vulnagent.stages.validate.node.docker_runtime",
                return_value={"selected": "docker", "available": True},
            ), patch(
                "yasa_vulnagent.stages.validate.node.ensure_environment",
                return_value={
                    "status": "ready",
                    "handle": {"image": "image:test", "image_id": "sha256:test"},
                },
            ), patch(
                "yasa_vulnagent.stages.validate.node.run_plan",
                side_effect=fake_plan,
            ), patch(
                "yasa_vulnagent.stages.validate.node.run_execute",
                side_effect=fake_execute,
            ), patch(
                "yasa_vulnagent.stages.validate.node.run_verify",
                side_effect=fake_verify,
            ):
                update = run_stage(
                    state,
                    runtime=Runtime(context=RunContext(settings=load_settings())),
                )
            paths = validation_paths(state["stages_dir"])
            artifact = json.loads(paths.validation_file.read_text(encoding="utf-8"))
        self.assertEqual(update["validation"]["status"], "complete")
        self.assertEqual(artifact["findings"][0]["disposition"], "confirmed")


if __name__ == "__main__":
    unittest.main()
