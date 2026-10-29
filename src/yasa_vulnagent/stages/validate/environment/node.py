"""Entry point for the validate environment-build subgraph."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from langgraph.errors import GraphRecursionError
from langgraph.runtime import Runtime

from ....agent.usage import UsageRecorder
from ....config import load_settings
from ....observability import start_run_logging
from ....storage import load_state, save_state
from ....workflow.state import RunContext, RunState
from .docker import DockerClient
from .graph import build_environment_graph
from .manifest import classify_node, finalize_node
from .schema import empty_state
from .storage import (
    environment_paths,
    git_revision,
    load_json,
    persist_state,
    write_json,
)


def run_environment(run_file: Path, *, rebuild: bool = False) -> RunState:
    """Build or reuse the base Docker environment for an existing run."""
    run_file = Path(run_file).expanduser().resolve()
    run_state = load_state(run_file)
    repository = Path(str(run_state.get("repository", "")))
    if not repository.is_dir():
        raise ValueError(f"repository is not a directory: {repository}")
    settings = load_settings()
    paths = environment_paths(str(run_state["stages_dir"]))
    for directory in (paths.root, paths.plans_dir, paths.gates_dir, paths.attempts_dir, paths.work_dir):
        directory.mkdir(parents=True, exist_ok=True)
    if not rebuild:
        reused = _reuse_ready(paths, settings)
        if reused is not None:
            return _persist_summary(run_state, reused)
    state = empty_state(run_state, paths)
    if paths.state_file.is_file():
        try:
            state.update(load_json(paths.state_file))
        except (OSError, ValueError):
            state["warnings"] = [*state.get("warnings", []), "environment state was unreadable and was rebuilt"]
    state["rebuild"] = bool(rebuild)
    if rebuild:
        state.update(
            {
                "plan": {},
                "plan_receipts": [],
                "plan_hash": "",
                "last_gate_hash": "",
                "failed_plan_hash": "",
                "plan_revision": 0,
                "plan_calls": 0,
                "gate": {},
                "gate_rejections": 0,
                "approved_plan": {},
                "attempt": 0,
                "diagnose_calls": 0,
                "failure": {},
                "diagnosis": {},
                "failure_signatures": [],
                "build": {},
                "smoke": {},
                "image": {},
                "environment_hash": "",
                "context_hash": "",
                "stop_reason": "",
                "errors": [],
                "warnings": [],
                "gaps": [],
            }
        )
    state["status"] = "running"
    state["next_action"] = "preflight"
    if not state.get("source_revision"):
        state["source_revision"] = git_revision(repository)
    write_json(paths.state_file, state)
    usage = UsageRecorder(settings.usage_price_table)
    session = start_run_logging(run_file)
    session.progress.start("workflow.validate.environment", run_file=str(run_file))
    context = RunContext(settings=settings, progress=session.progress, usage=usage)
    try:
        result = build_environment_graph().invoke(
            state,
            context=context,
            config={"recursion_limit": settings.validate_env_recursion_limit},
        )
        session.progress.finish(
            "workflow.validate.environment",
            status=str(result.get("status", "failed")),
        )
    except GraphRecursionError:
        result = _terminalize(state, context, status="blocked", reason="recursion_limit")
        session.progress.finish("workflow.validate.environment", status="blocked")
    except Exception as exc:
        _terminalize(state, context, status="failed", reason="internal_error", error=str(exc))
        session.progress.finish("workflow.validate.environment", status="failed", error_type=type(exc).__name__)
        raise
    finally:
        session.close()
    summary = _summary(result, paths)
    return _persist_summary(run_state, summary)


def _reuse_ready(paths: Any, settings: Any) -> dict[str, Any] | None:
    if not paths.environment_file.is_file() or not paths.handle_file.is_file():
        return None
    try:
        manifest = load_json(paths.environment_file)
    except (OSError, ValueError):
        return None
    if manifest.get("status") != "ready":
        return None
    image = manifest.get("image") if isinstance(manifest.get("image"), dict) else {}
    tag = str(image.get("tag", "") or "")
    if not tag:
        return None
    try:
        handle = load_json(paths.handle_file)
    except (OSError, ValueError):
        return None
    if str(handle.get("image", "")) != tag or str(handle.get("environment_hash", "")) != str(
        manifest.get("environment_hash", "")
    ):
        return None
    inspected = DockerClient(settings).image_inspect(tag)
    if inspected.get("status") != "ready":
        return None
    return _summary_from_manifest(manifest, paths)


def _terminalize(
    state: dict[str, Any],
    context: RunContext,
    *,
    status: str,
    reason: str,
    error: str = "",
) -> dict[str, Any]:
    latest = dict(state)
    try:
        if Path(str(state.get("state_file", ""))).is_file():
            latest.update(load_json(Path(str(state["state_file"]))))
    except (OSError, ValueError):
        pass
    latest["status"] = status
    latest["stop_reason"] = reason
    if error:
        latest["errors"] = [*latest.get("errors", []), error]
    runtime = Runtime(context=context)
    classified = classify_node(latest, runtime)  # type: ignore[arg-type]
    finalized = finalize_node(classified, runtime)  # type: ignore[arg-type]
    persist_state(finalized)
    return finalized


def _summary(result: dict[str, Any], paths: Any) -> dict[str, Any]:
    image = result.get("image") if isinstance(result.get("image"), dict) else {}
    return {
        "status": str(result.get("status", "failed")),
        "artifact_dir": str(paths.root),
        "state_file": str(paths.state_file),
        "environment_file": str(paths.environment_file),
        "handle_file": str(paths.handle_file),
        "image": str(image.get("tag", "") or ""),
        "image_id": str(image.get("id", "") or ""),
        "environment_hash": str(result.get("environment_hash", "") or ""),
        "plan_revision": int(result.get("plan_revision", 0)),
        "attempt": int(result.get("attempt", 0)),
        "stop_reason": str(result.get("stop_reason", "") or ""),
        "warnings": list(result.get("warnings", [])),
        "gaps": list(result.get("gaps", [])),
    }


def _summary_from_manifest(manifest: dict[str, Any], paths: Any) -> dict[str, Any]:
    image = manifest.get("image") if isinstance(manifest.get("image"), dict) else {}
    return {
        "status": "ready",
        "artifact_dir": str(paths.root),
        "state_file": str(paths.state_file),
        "environment_file": str(paths.environment_file),
        "handle_file": str(paths.handle_file),
        "image": str(image.get("tag", "") or ""),
        "image_id": str(image.get("id", "") or ""),
        "environment_hash": str(manifest.get("environment_hash", "") or ""),
        "plan_revision": int(manifest.get("plan_revision", 0)),
        "attempt": int(manifest.get("attempt", 0)),
        "stop_reason": "",
        "warnings": list(manifest.get("warnings", [])),
        "gaps": list(manifest.get("gaps", [])),
    }


def _persist_summary(run_state: RunState, summary: dict[str, Any]) -> RunState:
    updated: RunState = {**run_state, "environment": summary}
    save_state(updated)
    return updated
