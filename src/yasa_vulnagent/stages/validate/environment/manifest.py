"""Environment manifest, handle and terminal artifacts."""

from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from langgraph.runtime import Runtime

from ....workflow.state import RunContext
from .docker import DockerClient
from .schema import EnvironmentState
from .storage import paths_from_state, write_json


def snapshot_node(
    state: EnvironmentState,
    runtime: Runtime[RunContext] | None = None,
) -> dict[str, Any]:
    context = runtime.context if runtime is not None else None
    if context is None:
        from ....config import load_settings

        context = RunContext(settings=load_settings())
    docker = context.docker or DockerClient(context.settings)
    image = dict(state.get("image") or {})
    tag = str(image.get("tag", "") or "")
    inspected = docker.image_inspect(tag) if tag else {"status": "missing"}
    if inspected.get("status") != "ready":
        return {
            **dict(state),
            "status": "failed",
            "next_action": "classify",
            "stop_reason": "image_inspect_failed",
            "errors": [
                *state.get("errors", []),
                str(inspected.get("error", "image disappeared before snapshot")),
            ],
        }
    merged_image = {**image, **inspected, "tag": tag}
    manifest = _manifest(state, merged_image, status="ready")
    write_json(paths_from_state(state).environment_file, manifest)
    handle = _handle(state, merged_image)
    write_json(paths_from_state(state).handle_file, handle)
    return {
        **dict(state),
        "status": "ready",
        "next_action": "finalize",
        "image": merged_image,
    }


def classify_node(state: EnvironmentState, runtime: Runtime[RunContext] | None = None) -> dict[str, Any]:
    status = str(state.get("status", "blocked"))
    if status not in {"blocked", "failed"}:
        status = "blocked"
    paths = paths_from_state(state)
    manifest = _manifest(state, dict(state.get("image") or {}), status=status)
    write_json(paths.environment_file, manifest)
    if paths.handle_file.exists():
        paths.handle_file.unlink()
    return {
        **dict(state),
        "status": status,
        "next_action": "finalize",
    }


def finalize_node(
    state: EnvironmentState,
    runtime: Runtime[RunContext] | None = None,
) -> dict[str, Any]:
    context = runtime.context if runtime is not None else None
    paths = paths_from_state(state)
    paths.root.mkdir(parents=True, exist_ok=True)
    status = str(state.get("status", "failed"))
    if status not in {"ready", "blocked", "failed"}:
        status = "failed"
    if context is not None and context.usage is not None:
        context.usage.write(paths.usage_file, stage_prefix="validate.environment")
    elif not paths.usage_file.exists():
        write_json(paths.usage_file, {"totals": {}, "records": []})
    stage = {
        "name": "validate.environment",
        "status": status,
        "message": _stage_message(status, state),
        "artifact_dir": str(paths.root),
        "environment_file": str(paths.environment_file),
        "handle_file": str(paths.handle_file),
        "plan_revision": int(state.get("plan_revision", 0)),
        "attempt": int(state.get("attempt", 0)),
        "stop_reason": str(state.get("stop_reason", "")),
        "warnings": list(state.get("warnings", [])),
        "gaps": list(state.get("gaps", [])),
    }
    write_json(paths.stage_file, stage)
    write_json(paths.index_file, _index(paths.root))
    final = {
        **dict(state),
        "status": status,
        "next_action": "finalize",
    }
    write_json(paths.state_file, final)
    if status == "ready":
        shutil.rmtree(paths.work_dir / "build-context", ignore_errors=True)
    return final


def _manifest(state: Mapping[str, Any], image: Mapping[str, Any], *, status: str) -> dict[str, Any]:
    return {
        "status": status,
        "run_id": state.get("run_id", ""),
        "repository": state.get("repository", ""),
        "source_revision": state.get("source_revision", ""),
        "environment_hash": state.get("environment_hash", ""),
        "context_hash": state.get("context_hash", ""),
        "image": dict(image),
        "plan_revision": int(state.get("plan_revision", 0)),
        "attempt": int(state.get("attempt", 0)),
        "plan": state.get("plan", {}),
        "gate": state.get("gate", {}),
        "build": state.get("build", {}),
        "smoke": state.get("smoke", {}),
        "diagnosis": state.get("diagnosis", {}),
        "warnings": list(state.get("warnings", [])),
        "gaps": list(state.get("gaps", [])),
        "errors": list(state.get("errors", [])),
        "limitations": list(state.get("limitations", [])) or _limitations(),
        "stop_reason": str(state.get("stop_reason", "")),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def _handle(state: Mapping[str, Any], image: Mapping[str, Any]) -> dict[str, Any]:
    config = image.get("config") if isinstance(image.get("config"), Mapping) else {}
    return {
        "environment_hash": state.get("environment_hash", ""),
        "image": image.get("tag", ""),
        "image_id": image.get("id", ""),
        "base_image": (state.get("approved_plan") or state.get("plan") or {}).get("base_image", ""),
        "workdir": str(config.get("WorkingDir", "") or ""),
        "source_revision": state.get("source_revision", ""),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def _limitations() -> list[str]:
    return [
        "the repository is read live; plan and build are not guaranteed to use the same source snapshot",
        "build steps may access the network and execute repository-provided scripts",
        "the environment smoke does not assess the application security boundary",
    ]


def _stage_message(status: str, state: Mapping[str, Any]) -> str:
    if status == "ready":
        return "environment image is built and smoke-tested"
    if status == "blocked":
        return f"environment build blocked: {state.get('stop_reason', 'unknown')}"
    return "environment build failed internally"


def _index(root: Path) -> dict[str, Any]:
    files = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or "work" in path.relative_to(root).parts:
            continue
        files.append(
            {
                "path": path.relative_to(root).as_posix(),
                "bytes": path.stat().st_size,
            }
        )
    return {"files": files, "count": len(files)}
