from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from yasa_vulnagent.config import load_settings
from yasa_vulnagent.stages.validate.environment.docker import DockerClient


@unittest.skipUnless(
    os.environ.get("VALIDATE_DOCKER_INTEGRATION") == "1",
    "set VALIDATE_DOCKER_INTEGRATION=1 to exercise the host Docker daemon",
)
class DockerEnvironmentIntegrationTest(unittest.TestCase):
    def test_build_inspect_and_smoke(self) -> None:
        settings = load_settings()
        docker = DockerClient(settings)
        preflight = docker.preflight()
        if preflight.get("status") != "ready":
            self.skipTest(f"docker preflight unavailable: {preflight.get('failure_kind')}")
        tag = "yasa-validate-integration:latest"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            context = root / "build-context"
            context.mkdir()
            (context / "README").write_text("integration\n", encoding="utf-8")
            dockerfile = root / "Dockerfile"
            dockerfile.write_text("FROM alpine:3.20\nCMD [\"true\"]\n", encoding="utf-8")
            build = docker.build(
                context=context,
                dockerfile=dockerfile,
                tag=tag,
                labels={"yasa.test": "integration"},
                timeout=300,
                log_path=root / "build.log",
            )
            self.assertTrue(build.ok, build.tail(2000))
            inspected = docker.image_inspect(tag)
            self.assertEqual(inspected.get("status"), "ready")
            smoke = docker.run(
                image=tag,
                command=["true"],
                timeout=30,
                log_path=root / "smoke.log",
            )
            self.assertTrue(smoke.ok, smoke.tail(2000))
        subprocess.run(
            [settings.validate_docker_bin, "image", "rm", tag],
            capture_output=True,
            text=True,
            env=docker.env,
            check=False,
        )


if __name__ == "__main__":
    unittest.main()
