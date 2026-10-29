"""Deterministic finding selection and Docker/environment intake."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from ...config import Settings
from ...storage import load_state
from ...workflow.state import RunContext
from .environment.docker import DockerClient
from .storage import ValidationPaths, load_json, write_json

ELIGIBLE_VERDICTS = ("confirmed", "needs_validation")


def audit_path(run_state: Mapping[str, Any]) -> Path:
    for record in run_state.get("stages", []):
        if record.get("name") == "audit":
            directory = record.get("artifact_dir")
            if directory:
                return Path(str(directory)) / "audit.json"
    return Path(str(run_state.get("stages_dir", ""))) / "audit" / "audit.json"


def load_audit(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"audit artifact not found: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"audit artifact is not a JSON object: {path}")
    return value


def select_findings(
    audit: Mapping[str, Any], explicit: list[str] | None = None
) -> list[dict[str, Any]]:
    findings = [item for item in (audit.get("findings") or []) if isinstance(item, dict)]
    by_id = {str(item.get("id", "")): item for item in findings}
    if explicit:
        selected: list[dict[str, Any]] = []
        seen: set[str] = set()
        for finding_id in explicit:
            finding = by_id.get(str(finding_id))
            if finding is None:
                raise ValueError(f"finding is not present in audit: {finding_id}")
            if str(finding.get("verdict", "")) not in ELIGIBLE_VERDICTS:
                raise ValueError(
                    f"finding is not eligible for validation: {finding_id} "
                    f"(verdict={finding.get('verdict', '')})"
                )
            if finding_id not in seen:
                seen.add(str(finding_id))
                selected.append(finding)
        return selected
    return [
        item
        for item in findings
        if str(item.get("verdict", "")) in ELIGIBLE_VERDICTS
    ]


def docker_runtime(settings: Settings) -> dict[str, Any]:
    preflight = DockerClient(settings).preflight()
    if preflight.get("status") != "ready":
        return {
            "selected": "docker",
            "available": False,
            "reason": str(preflight.get("failure_kind", "") or "docker_unavailable"),
            "message": str(preflight.get("message", "")),
            "preflight": preflight,
        }
    return {
        "selected": "docker",
        "available": True,
        "reason": "",
        "client_version": preflight.get("client_version", ""),
        "server_version": preflight.get("server_version", ""),
        "access": preflight.get("access", ""),
    }


def environment_handle(paths: ValidationPaths, settings: Settings) -> dict[str, Any] | None:
    handle_file = paths.environment_dir / "handle.json"
    if not handle_file.is_file():
        return None
    try:
        handle = load_json(handle_file)
    except (OSError, ValueError):
        return None
    image = str(handle.get("image", "") or "")
    if not image:
        return None
    inspected = DockerClient(settings).image_inspect(image)
    if inspected.get("status") != "ready":
        return None
    result = dict(handle)
    result["image_id"] = str(inspected.get("id", "") or handle.get("image_id", ""))
    return result


def ensure_environment(
    state: dict[str, Any],
    paths: ValidationPaths,
    context: RunContext,
    mode: str,
) -> dict[str, Any]:
    handle = None if mode == "build" else environment_handle(paths, context.settings)
    if handle is not None:
        return {"status": "ready", "handle": handle}
    if mode == "reuse":
        return {"status": "blocked", "reason": "environment_unavailable"}
    run_file = Path(str(state.get("run_file", "")))
    if not run_file.is_file():
        return {"status": "blocked", "reason": "environment_unavailable"}
    try:
        from .environment.node import run_environment

        run_environment(run_file, rebuild=mode == "build")
    except Exception as exc:  # environment graph reports its own failures
        return {"status": "blocked", "reason": "environment_failed", "error": str(exc)}
    handle = environment_handle(paths, context.settings)
    if handle is None:
        return {"status": "blocked", "reason": "environment_unavailable"}
    return {"status": "ready", "handle": handle}


def reload_environment(state: dict[str, Any]) -> None:
    run_file = Path(str(state.get("run_file", "")))
    if not run_file.is_file():
        return
    try:
        latest = load_state(run_file)
    except Exception:
        return
    if latest.get("environment"):
        state["environment"] = latest["environment"]


def record_selection(paths: ValidationPaths, payload: dict[str, Any]) -> None:
    paths.root.mkdir(parents=True, exist_ok=True)
    write_json(paths.selection_file, payload)
