from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any

from ....config import (
    DEFAULT_YASA_BIN_PATH,
    DEFAULT_YASA_INIT_TIMEOUT,
    DEFAULT_YASA_MCP_TIMEOUT,
    DEFAULT_YASA_SOURCE_PATH,
    DEFAULT_YASA_STATUS_TIMEOUT,
    resolve_project_path,
)
from ....workflow.state import RunState


logger = logging.getLogger(__name__)


class YasaError(RuntimeError):
    """Raised when YASA initialization or the MCP probe cannot complete."""


class YasaRunner:
    def __init__(
        self,
        source_path: Path,
        bin_path: Path,
        init_timeout: int = DEFAULT_YASA_INIT_TIMEOUT,
        status_timeout: int = DEFAULT_YASA_STATUS_TIMEOUT,
        mcp_timeout: int = DEFAULT_YASA_MCP_TIMEOUT,
    ) -> None:
        self.source_path = source_path.expanduser().resolve()
        self.bin_path = bin_path.expanduser().resolve()
        self.init_timeout = init_timeout
        self.status_timeout = status_timeout
        self.mcp_timeout = mcp_timeout

    @classmethod
    def from_state(cls, state: RunState) -> "YasaRunner":
        config = state.get("config", {})
        return cls(
            source_path=resolve_project_path(
                config.get("yasa_source_path", DEFAULT_YASA_SOURCE_PATH)
            ),
            bin_path=resolve_project_path(config.get("yasa_bin_path", DEFAULT_YASA_BIN_PATH)),
            init_timeout=int(config.get("yasa_init_timeout", DEFAULT_YASA_INIT_TIMEOUT)),
            status_timeout=int(config.get("yasa_status_timeout", DEFAULT_YASA_STATUS_TIMEOUT)),
            mcp_timeout=int(config.get("yasa_mcp_timeout", DEFAULT_YASA_MCP_TIMEOUT)),
        )

    def run(self, repository: Path) -> dict[str, object]:
        logger.info("YASA work item start repository=%s", repository)
        self._check_paths()
        self.initialize(repository)
        status = self.status(repository)
        probe = self.probe_mcp(repository)
        logger.info(
            "YASA work item finish status_valid=%s mcp_result_count=%s",
            status["valid"],
            probe["result_count"],
        )
        return {
            "status_valid": bool(status["valid"]),
            "mcp_tool": probe["tool"],
            "mcp_result_count": probe["result_count"],
        }

    def _check_paths(self) -> None:
        source_root = self.source_path / "src" / "yasa_mcp"
        if not source_root.is_dir():
            raise YasaError(f"YASA-MCP source directory does not exist: {source_root}")
        if not self.bin_path.is_dir():
            raise YasaError(f"YASA native binary directory does not exist: {self.bin_path}")

    def _environment(self) -> dict[str, str]:
        environment = os.environ.copy()
        source = str(self.source_path / "src")
        existing = environment.get("PYTHONPATH")
        environment["PYTHONPATH"] = source if not existing else source + os.pathsep + existing
        environment["YASA_MCP_BIN_DIR"] = str(self.bin_path)
        return environment

    def _runtime_cwd(self) -> Path:
        for platform_root in sorted(self.bin_path.iterdir()):
            candidate = platform_root / "yasa"
            if (candidate / "node_modules").is_dir():
                return candidate
        return self.bin_path

    def _run_cli(self, args: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
        command = [sys.executable, "-m", "yasa_mcp", *args]
        process: subprocess.Popen[str] | None = None
        try:
            process = subprocess.Popen(
                command,
                cwd=self._runtime_cwd(),
                env=self._environment(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=os.name != "nt",
            )
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            if process is not None:
                self._terminate(process)
            raise YasaError(f"YASA command timed out after {timeout}s: {' '.join(args)}") from exc
        except OSError as exc:
            if process is not None:
                self._terminate(process)
            raise YasaError(f"unable to start YASA command: {exc}") from exc
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)

    @staticmethod
    def _terminate(process: subprocess.Popen[str]) -> None:
        if process.poll() is not None:
            return
        try:
            if os.name != "nt":
                os.killpg(process.pid, signal.SIGTERM)
            else:
                process.terminate()
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            try:
                if os.name != "nt":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
                process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass

    def initialize(self, repository: Path) -> None:
        logger.info("YASA initialization started repository=%s", repository)
        result = self._run_cli(
            ["init", str(repository.resolve()), "--bin", str(self.bin_path), "--no-progress"],
            self.init_timeout,
        )
        if result.returncode != 0:
            raise YasaError(self._failure_message("initialization", result))
        logger.info("YASA initialization completed repository=%s", repository)

    def status(self, repository: Path) -> dict[str, Any]:
        logger.info("YASA status check started repository=%s", repository)
        result = self._run_cli(
            ["status", "--project", str(repository.resolve())],
            self.status_timeout,
        )
        if result.returncode != 0:
            raise YasaError(self._failure_message("status", result))
        payload = _parse_json_output(result.stdout)
        if not isinstance(payload, dict) or not isinstance(payload.get("valid"), bool):
            raise YasaError("YASA status did not return a valid JSON payload")
        if not payload["valid"]:
            raise YasaError(f"YASA cache is invalid: {json.dumps(payload, ensure_ascii=False)}")
        logger.info("YASA status valid repository=%s", repository)
        return payload

    async def _probe_mcp(self, repository: Path) -> dict[str, object]:
        try:
            from mcp import ClientSession, StdioServerParameters
            from mcp.client.stdio import stdio_client
        except ImportError as exc:
            raise YasaError("the Python mcp package is required for the YASA probe") from exc

        server = StdioServerParameters(
            command=sys.executable,
            args=[
                "-m",
                "yasa_mcp",
                "server",
                "--transport",
                "stdio",
                "--bin",
                str(self.bin_path),
            ],
            env=self._environment(),
        )
        async with stdio_client(server) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                listed = await session.list_tools()
                names = {tool.name for tool in listed.tools}
                if "get_function" not in names:
                    raise YasaError("YASA MCP does not expose get_function")
                result = await session.call_tool(
                    "get_function",
                    {
                        "project_path": str(repository.resolve()),
                        "name": "main",
                        "max_results": 1,
                    },
                )
                payload = _mcp_content_json(result)
                if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
                    raise YasaError("YASA MCP get_function returned an invalid payload")
                logger.info(
                    "YASA MCP probe completed tool=get_function result_count=%s",
                    len(payload["results"]),
                )
                return {"tool": "get_function", "result_count": len(payload["results"])}

    def probe_mcp(self, repository: Path) -> dict[str, object]:
        logger.info("YASA MCP probe started repository=%s", repository)
        async def bounded_probe() -> dict[str, object]:
            return await asyncio.wait_for(self._probe_mcp(repository), timeout=self.mcp_timeout)

        try:
            return asyncio.run(bounded_probe())
        except YasaError:
            raise
        except asyncio.TimeoutError as exc:
            raise YasaError(f"YASA MCP probe timed out after {self.mcp_timeout}s") from exc
        except Exception as exc:
            raise YasaError(f"YASA MCP probe failed: {exc}") from exc

    @staticmethod
    def _failure_message(operation: str, result: subprocess.CompletedProcess[str]) -> str:
        stderr = (result.stderr or "").strip()[-2000:]
        stdout = (result.stdout or "").strip()[-2000:]
        return f"YASA {operation} failed returncode={result.returncode} stderr={stderr!r} stdout={stdout!r}"


def _parse_json_output(output: str) -> object:
    text = output.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        for line in reversed(text.splitlines()):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    return None


def _mcp_content_json(result: Any) -> object:
    for item in getattr(result, "content", []) or []:
        text = getattr(item, "text", None)
        if not text:
            continue
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            continue
    structured = getattr(result, "structuredContent", None)
    if structured is not None:
        return structured
    return {}
