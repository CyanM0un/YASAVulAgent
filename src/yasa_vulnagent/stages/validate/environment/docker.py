"""Small Docker CLI adapter used by the environment build graph."""

from __future__ import annotations

import grp
import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ....config import Settings


@dataclass(frozen=True)
class CommandResult:
    args: tuple[str, ...]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    timed_out: bool = False
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.error and not self.timed_out

    def tail(self, limit: int = 4000) -> str:
        text = "\n".join(part for part in (self.stdout, self.stderr) if part).strip()
        return text[-max(1, int(limit)) :]


class DockerClient:
    """Use the Docker CLI without a shell and with a minimal environment."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.binary = settings.validate_docker_bin
        self.env = self._environment(settings)

    @staticmethod
    def _environment(settings: Settings) -> dict[str, str]:
        keep = {
            "PATH",
            "HOME",
            "DOCKER_HOST",
            "DOCKER_CONFIG",
            "DOCKER_CONTEXT",
            "DOCKER_TLS_VERIFY",
            "DOCKER_CERT_PATH",
            "XDG_RUNTIME_DIR",
        }
        env = {key: os.environ[key] for key in keep if key in os.environ}
        env["DOCKER_BUILDKIT"] = "1"
        if settings.validate_docker_host:
            env["DOCKER_HOST"] = settings.validate_docker_host
        return env

    def _run(
        self,
        args: Sequence[str],
        *,
        timeout: int,
        log_path: Path | None = None,
        max_output_bytes: int | None = None,
    ) -> CommandResult:
        command = tuple(str(item) for item in args)
        started = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=max(1, int(timeout)),
                env=self.env,
                check=False,
            )
            stdout = completed.stdout or ""
            stderr = completed.stderr or ""
            timed_out = False
            error = ""
            returncode = int(completed.returncode)
        except subprocess.TimeoutExpired as exc:
            stdout = _as_text(exc.stdout)
            stderr = _as_text(exc.stderr)
            timed_out = True
            error = f"docker command timed out after {timeout}s"
            returncode = 124
        except FileNotFoundError:
            stdout = ""
            stderr = f"docker binary not found: {self.binary}"
            timed_out = False
            error = stderr
            returncode = 127
        except OSError as exc:
            stdout = ""
            stderr = str(exc)
            timed_out = False
            error = stderr
            returncode = 126
        duration = time.monotonic() - started
        if max_output_bytes and max_output_bytes > 0:
            stdout = stdout[-max_output_bytes:]
            stderr = stderr[-max_output_bytes:]
        result = CommandResult(
            args=command,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            duration=duration,
            timed_out=timed_out,
            error=error,
        )
        if log_path is not None:
            log_path = Path(log_path)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text(
                "\n".join(
                    part
                    for part in (
                        f"$ {' '.join(command)}",
                        stdout,
                        stderr,
                    )
                    if part
                ),
                encoding="utf-8",
            )
        return result

    def preflight(self) -> dict[str, Any]:
        if not shutil.which(self.binary):
            return _preflight_result(
                status="blocked",
                failure_kind="docker_cli_missing",
                message=f"docker binary not found: {self.binary}",
                remediation="Install Docker or set VALIDATE_DOCKER_BIN.",
            )
        version = self._run(
            [
                self.binary,
                "version",
                "--format",
                "{{.Client.Version}}|{{.Server.Version}}",
            ],
            timeout=30,
        )
        if not version.ok:
            kind = _permission_kind(classify_preflight_failure(version.stderr or version.error))
            return _preflight_result(
                status="blocked",
                failure_kind=kind,
                message=version.tail(1200),
                remediation=preflight_remediation(kind),
                raw=version.tail(2000),
            )
        info = self._run(
            [self.binary, "info", "--format", "{{json .}}"],
            timeout=30,
        )
        if not info.ok:
            kind = _permission_kind(classify_preflight_failure(info.stderr or info.error))
            return _preflight_result(
                status="blocked",
                failure_kind=kind,
                message=info.tail(1200),
                remediation=preflight_remediation(kind),
                raw=info.tail(2000),
            )
        try:
            info_data = json.loads(info.stdout)
        except json.JSONDecodeError:
            info_data = {}
        server_version = str(info_data.get("ServerVersion", "") or "")
        client_version = version.stdout.split("|", 1)[0].strip()
        buildx = self._run([self.binary, "buildx", "version"], timeout=15)
        groups = os.getgroups()
        docker_gid, docker_group_found = _docker_group()
        socket = _socket_info()
        access = "ready"
        if socket.get("path") and socket.get("uid") is not None:
            if socket.get("gid") not in groups and os.geteuid() != 0:
                access = "group_or_socket_permission"
        return _preflight_result(
            status="ready",
            failure_kind="",
            message="Docker daemon is reachable.",
            remediation="",
            client_version=client_version,
            server_version=server_version,
            api_version=str(info_data.get("ApiVersion", "") or ""),
            architecture=str(info_data.get("Architecture", "") or ""),
            os_type=str(info_data.get("OSType", "") or ""),
            driver=str(info_data.get("Driver", "") or ""),
            buildx=buildx.ok,
            socket=socket,
            current_uid=os.geteuid(),
            current_gids=groups,
            docker_group_found=docker_group_found,
            docker_group_gid=docker_gid,
            access=access,
        )

    def build(
        self,
        *,
        context: Path,
        dockerfile: Path,
        tag: str,
        labels: Mapping[str, str],
        timeout: int,
        log_path: Path,
    ) -> CommandResult:
        args = [
            self.binary,
            "build",
            "--file",
            str(dockerfile),
            "--tag",
            tag,
            "--progress",
            "plain",
        ]
        if self.settings.validate_docker_pull in {"always", "missing"}:
            args.append("--pull")
        for key, value in labels.items():
            args.extend(["--label", f"{key}={value}"])
        if self.settings.validate_docker_platform:
            args.extend(["--platform", self.settings.validate_docker_platform])
        args.append(str(context))
        return self._run(
            args,
            timeout=timeout,
            log_path=log_path,
            max_output_bytes=self.settings.validate_docker_log_bytes,
        )

    def image_inspect(self, tag: str) -> dict[str, Any]:
        result = self._run(
            [self.binary, "image", "inspect", "--format", "{{json .}}", tag],
            timeout=30,
        )
        if not result.ok:
            return {"status": "missing", "error": result.tail(1200)}
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return {"status": "invalid", "error": "docker image inspect returned invalid JSON"}
        return {
            "status": "ready",
            "id": str(data.get("Id", "") or ""),
            "repo_digests": list(data.get("RepoDigests") or []),
            "config": data.get("Config") or {},
        }

    def run(
        self,
        *,
        image: str,
        command: Sequence[str],
        timeout: int,
        log_path: Path,
    ) -> CommandResult:
        args = [
            self.binary,
            "run",
            "--rm",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(self.settings.validate_docker_pids),
            "--memory",
            self.settings.validate_docker_memory,
            "--cpus",
            str(self.settings.validate_docker_cpus),
            image,
            *[str(item) for item in command],
        ]
        return self._run(
            args,
            timeout=timeout,
            log_path=log_path,
            max_output_bytes=self.settings.validate_docker_log_bytes,
        )


def classify_preflight_failure(text: str) -> str:
    lowered = str(text or "").lower()
    if "no such file" in lowered and "docker" in lowered:
        return "docker_cli_missing"
    if "permission denied" in lowered and ("docker.sock" in lowered or "docker api" in lowered):
        return "docker_socket_permission"
    if "cannot connect" in lowered or "is the docker daemon running" in lowered:
        return "docker_unavailable"
    if "setgroups" in lowered or "operation not permitted" in lowered:
        return "sandbox_hides_docker_socket"
    return "docker_unavailable"


def _permission_kind(kind: str) -> str:
    if kind != "docker_socket_permission":
        return kind
    gid, found = _docker_group()
    if found and gid not in os.getgroups():
        return "docker_group_not_active"
    socket = _socket_info()
    if socket.get("uid") in {65534, 4294967294}:
        return "sandbox_hides_docker_socket"
    return kind


def preflight_remediation(kind: str) -> str:
    if kind == "docker_cli_missing":
        return "Install Docker or set VALIDATE_DOCKER_BIN."
    if kind == "docker_group_not_active":
        return (
            "Run `newgrp docker` (or log in again) so the current shell has the docker "
            "group; verify with `docker info`. Do not chmod 666 the socket."
        )
    if kind == "docker_socket_permission":
        return (
            "Verify /var/run/docker.sock is owned by root:docker with mode 660 and that "
            "the current user is in the docker group."
        )
    if kind == "sandbox_hides_docker_socket":
        return (
            "The current sandbox hides or rewrites the Docker socket. Run the command "
            "outside the sandbox or use full host access; do not weaken socket permissions."
        )
    return "Start the Docker daemon and verify `docker info` in the same shell."


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _docker_group() -> tuple[int | None, bool]:
    try:
        group = grp.getgrnam("docker")
    except KeyError:
        return None, False
    return int(group.gr_gid), True


def _socket_info() -> dict[str, Any]:
    host = os.environ.get("DOCKER_HOST", "")
    if host and not host.startswith("unix://"):
        return {"path": host, "kind": "tcp"}
    path = Path(host.removeprefix("unix://")) if host else Path("/var/run/docker.sock")
    try:
        stat = path.stat()
    except OSError as exc:
        return {"path": str(path), "error": str(exc)}
    return {
        "path": str(path),
        "mode": oct(stat.st_mode & 0o777),
        "uid": stat.st_uid,
        "gid": stat.st_gid,
    }


def _preflight_result(
    *,
    status: str,
    failure_kind: str,
    message: str,
    remediation: str,
    **extra: Any,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": status,
        "failure_kind": failure_kind,
        "message": message[:2000],
        "remediation": remediation,
    }
    result.update(extra)
    return result
