"""Command execution with a best-effort Docker safety audit.

The validation agent runs on the host and controls Docker.  This module is the
single execution entry point: every command is logged, and obvious host escape
or unsafe container flags are rejected.  It is deliberately not a sandbox.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from langchain_core.tools import StructuredTool

from ...config import Settings


_SECRET = re.compile(
    r"(?i)((?:api[_-]?key|token|secret|password|authorization|cookie)\s*[=:]\s*)([^\s\"']+)"
)


class CommandDenied(ValueError):
    """Raised when a command matches the Docker safety deny list."""


class ShellRunner:
    def __init__(
        self,
        *,
        root: Path,
        repository: Path,
        settings: Settings,
        log_dir: Path,
    ) -> None:
        self.root = Path(root).resolve()
        self.repository = Path(repository).resolve()
        self.settings = settings
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.commands_file = self.log_dir / "commands.jsonl"
        self.count = self._existing_count()

    def _existing_count(self) -> int:
        """Continue numbering after a resumed run instead of overwriting logs."""
        if not self.commands_file.is_file():
            return 0
        highest = 0
        for line in self.commands_file.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                highest = max(highest, int(json.loads(line).get("index", 0)))
            except (ValueError, TypeError, AttributeError):
                continue
        return highest

    def langchain_tools(self) -> list[StructuredTool]:
        return [
            StructuredTool.from_function(
                func=self.run,
                name="run_bash",
                description=(
                    "Run one bounded host bash command from the validation workspace. "
                    "Use it to drive Docker, start local target services, run tests and "
                    "PoCs, and inspect saved artifacts. VALIDATION_DIR is the workspace "
                    "and REPO is the read-only target source. Do not edit the target repository."
                ),
            ),
            StructuredTool.from_function(
                func=self.read_artifact,
                name="read_artifact",
                description="Read a bounded UTF-8 text artifact under the validation run directory.",
            ),
        ]

    def check(self, command: str) -> None:
        text = str(command or "")
        lowered = text.lower()
        rules = (
            (r"--privileged\b", "privileged container"),
            (r"--network(?:=|\s+)host\b", "host network"),
            (r"--net(?:=|\s+)host\b", "host network"),
            (r"--pid(?:=|\s+)host\b", "host pid namespace"),
            (r"--ipc(?:=|\s+)host\b", "host ipc namespace"),
            (r"--uts(?:=|\s+)host\b", "host uts namespace"),
            (r"--userns(?:=|\s+)host\b", "host user namespace"),
            (r"--device(?:=|\s+)", "host device"),
            (r"/var/run/docker\.sock", "docker socket"),
            (r"--security-opt[^\n]*seccomp[^\n]*unconfined", "unconfined seccomp"),
            (r"--security-opt[^\n]*apparmor[^\n]*unconfined", "unconfined apparmor"),
            (r"(?:^|[;&|]\s*)sudo\b", "sudo"),
            (r"(?:^|[;&|]\s*)nsenter\b", "namespace enter"),
            (r"(?:^|[;&|]\s*)pivot_root\b", "pivot_root"),
            (r"(?:^|[;&|]\s*)mount\b", "host mount"),
        )
        for pattern, reason in rules:
            if re.search(pattern, lowered):
                raise CommandDenied(f"command rejected by validation audit: {reason}")
        for match in re.finditer(r"--cap-add(?:=|\s+)([A-Za-z0-9_]+)", text):
            if match.group(1).upper() != "SYS_PTRACE":
                raise CommandDenied(
                    "command rejected by validation audit: capability other than SYS_PTRACE"
                )
        for source in _mount_sources(text):
            expanded = (
                source.replace("${VALIDATION_DIR}", str(self.root))
                .replace("$VALIDATION_DIR", str(self.root))
                .replace("${PWD}", str(self.root))
                .replace("$PWD", str(self.root))
                .strip("\"'")
            )
            if "$" in expanded:
                raise CommandDenied(
                    f"command rejected by validation audit: unresolved shell variable in mount: {source}"
                )
            path = Path(expanded)
            if not path.is_absolute():
                path = (self.root / path).resolve()
            else:
                path = path.resolve()
            if not _within(path, self.root):
                raise CommandDenied(
                    f"command rejected by validation audit: host mount outside validation workspace: {source}"
                )

    def run(self, command: str, timeout: int = 120) -> dict[str, Any]:
        command = str(command or "").strip()
        if not command:
            return {"error": "empty command", "exit_code": -1}
        try:
            self.check(command)
        except CommandDenied as exc:
            return {"error": str(exc), "denied": True, "exit_code": -1}
        self.count += 1
        number = self.count
        limit = max(1, int(timeout))
        limit = min(limit, int(self.settings.validate_command_timeout))
        started = time.monotonic()
        try:
            process = subprocess.run(
                ["bash", "-lc", command],
                cwd=self.root,
                env=self._environment(),
                capture_output=True,
                text=True,
                timeout=limit,
                check=False,
            )
            stdout, stderr = process.stdout, process.stderr
            exit_code = process.returncode
            timed_out = False
        except subprocess.TimeoutExpired as exc:
            stdout = _text(exc.stdout)
            stderr = _text(exc.stderr)
            exit_code = -1
            timed_out = True
        except OSError as exc:
            stdout, stderr, exit_code, timed_out = "", str(exc), -1, False
        duration = round(time.monotonic() - started, 3)
        out_file = self.log_dir / f"{number:04d}.out"
        err_file = self.log_dir / f"{number:04d}.err"
        stdout = _redact(stdout)
        stderr = _redact(stderr)
        out_file.write_text(stdout, encoding="utf-8", errors="replace")
        err_file.write_text(stderr, encoding="utf-8", errors="replace")
        record = {
            "index": number,
            "command": _redact(command),
            "cwd": str(self.root),
            "exit_code": exit_code,
            "timed_out": timed_out,
            "duration_seconds": duration,
            "stdout_file": str(out_file),
            "stderr_file": str(err_file),
        }
        with self.commands_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        return {
            "exit_code": exit_code,
            "timed_out": timed_out,
            "duration_seconds": duration,
            "stdout": _bounded(stdout, self.settings.validate_tool_output_chars),
            "stderr": _bounded(stderr, self.settings.validate_tool_output_chars),
            "stdout_file": str(out_file),
            "stderr_file": str(err_file),
        }

    def read_artifact(self, path: str, limit: int = 8000) -> dict[str, Any]:
        target = (self.root / str(path)).resolve()
        if not _within(target, self.root):
            return {"error": "artifact path escapes the validation workspace"}
        if not target.is_file():
            return {"error": f"artifact not found: {path}"}
        text = target.read_text(encoding="utf-8", errors="replace")
        size = max(1, int(limit))
        return {
            "path": str(target.relative_to(self.root)),
            "text": text[:size],
            "truncated": len(text) > size,
        }

    def _environment(self) -> dict[str, str]:
        keys = (
            "PATH",
            "HOME",
            "USER",
            "LANG",
            "LC_ALL",
            "TMPDIR",
            "DOCKER_HOST",
            "DOCKER_CONTEXT",
            "DOCKER_CONFIG",
            "DOCKER_CERT_PATH",
            "DOCKER_TLS_VERIFY",
            "XDG_RUNTIME_DIR",
        )
        env = {key: os.environ[key] for key in keys if key in os.environ}
        env.setdefault("PATH", os.defpath)
        env.update(
            {
                "VALIDATION_DIR": str(self.root),
                "REPO": str(self.repository),
                "YASA_VALIDATION": "1",
            }
        )
        return env


def _redact(value: str) -> str:
    return _SECRET.sub(r"\1[REDACTED]", value)


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _bounded(value: str, limit: int) -> str:
    size = max(1, int(limit))
    return value if len(value) <= size else value[:size] + "\n...[truncated]"


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _mount_sources(command: str) -> list[str]:
    sources: list[str] = []
    for match in re.finditer(r"(?:^|\s)(?:-v|--volume)(?:=|\s+)([^\s]+)", command):
        source = match.group(1).split(":", 1)[0]
        if source:
            sources.append(source)
    for match in re.finditer(r"--mount(?:=|\s+)([^\s]+)", command):
        value = match.group(1)
        for part in value.split(","):
            if part.startswith("source=") or part.startswith("src="):
                sources.append(part.split("=", 1)[1])
    return sources
