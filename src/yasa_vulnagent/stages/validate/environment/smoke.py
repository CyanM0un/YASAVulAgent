"""Fixed-security smoke execution for a built environment image."""

from __future__ import annotations

from typing import Any

from langgraph.runtime import Runtime

from ....workflow.state import RunContext
from .docker import DockerClient
from .schema import EnvironmentState
from .storage import attempt_dir, write_json


def smoke_node(
    state: EnvironmentState,
    runtime: Runtime[RunContext] | None = None,
) -> dict[str, Any]:
    context = runtime.context if runtime is not None else None
    if context is None:
        from ....config import load_settings

        context = RunContext(settings=load_settings())
    settings = context.settings
    docker = context.docker or DockerClient(settings)
    plan = dict(state.get("approved_plan") or state.get("plan") or {})
    commands = plan.get("smoke_commands")
    if not isinstance(commands, list) or not commands:
        return {
            **dict(state),
            "status": "blocked",
            "next_action": "classify",
            "stop_reason": "smoke_missing",
            "errors": [*state.get("errors", []), "no smoke commands are available"],
        }
    image = dict(state.get("image") or {})
    tag = str(image.get("tag", "") or "")
    if not tag:
        return {
            **dict(state),
            "status": "blocked",
            "next_action": "classify",
            "stop_reason": "image_missing",
            "errors": [*state.get("errors", []), "smoke has no image tag"],
        }
    attempt = int(state.get("attempt", 0))
    attempt_path = attempt_dir(state, attempt)
    attempt_path.mkdir(parents=True, exist_ok=True)
    log_path = attempt_path / "smoke.log"
    timeout = settings.validate_docker_smoke_timeout
    resources = plan.get("resources")
    if isinstance(resources, dict):
        try:
            requested = int(resources.get("timeout", timeout))
        except (TypeError, ValueError):
            requested = timeout
        timeout = max(1, min(timeout, requested))
    results: list[dict[str, Any]] = []
    log_chunks: list[str] = []
    all_ok = True
    for index, command in enumerate(commands, start=1):
        if not isinstance(command, list) or not command or not all(isinstance(item, str) for item in command):
            all_ok = False
            results.append({"index": index, "status": "invalid", "command": command})
            continue
        command_log = attempt_path / f"smoke-{index}.log"
        result = docker.run(
            image=tag,
            command=command,
            timeout=timeout,
            log_path=command_log,
        )
        if command_log.is_file():
            log_chunks.append(
                f"$ {' '.join(command)}\n"
                + command_log.read_text(encoding="utf-8", errors="replace")
            )
        results.append(
            {
                "index": index,
                "status": "complete" if result.ok else "failed",
                "command": list(command),
                "exit_code": result.returncode,
                "timed_out": result.timed_out,
                "duration_seconds": round(result.duration, 3),
                "output_tail": result.tail(4000),
                "error": result.error,
            }
        )
        all_ok = all_ok and result.ok
        if not result.ok:
            break
    log_path.write_text("\n".join(log_chunks), encoding="utf-8")
    record = {
        "status": "complete" if all_ok else "failed",
        "attempt": attempt,
        "image": tag,
        "commands": results,
        "log_file": str(log_path),
    }
    write_json(attempt_path / "smoke.json", record)
    if all_ok:
        return {
            **dict(state),
            "status": "running",
            "next_action": "snapshot",
            "smoke": record,
        }
    failure = {
        "phase": "smoke",
        "attempt": attempt,
        "exit_code": results[-1].get("exit_code", 1) if results else 1,
        "timed_out": bool(results[-1].get("timed_out")) if results else False,
        "log_file": str(log_path),
        "output_tail": "\n".join(
            str(item.get("output_tail", "")) for item in results if item.get("output_tail")
        )[-6000:],
        "plan_hash": str(state.get("plan_hash", "")),
    }
    return {
        **dict(state),
        "status": "running",
        "next_action": "diagnose",
        "smoke": record,
        "failure": failure,
        "failed_plan_hash": str(state.get("plan_hash", "")),
    }
