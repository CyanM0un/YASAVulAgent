"""JSON-compatible state and schemas for the environment build graph."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, TypedDict

from .storage import EnvironmentPaths


class EnvironmentPlan(TypedDict, total=False):
    status: str
    base_image: str
    dockerfile: list[dict[str, str]]
    smoke_commands: list[list[str]]
    inspection: dict[str, Any]
    assumptions: list[str]
    gaps: list[str]
    confidence: str
    why: str
    changes: list[str]
    based_on: str
    resources: dict[str, Any]


class EnvironmentState(TypedDict, total=False):
    """Durable state for one environment graph invocation.

    Runtime clients live in ``RunContext``; this mapping stays JSON-compatible.
    """

    run_id: str
    repository: str
    run_file: str
    artifact_dir: str
    state_file: str
    environment_file: str
    handle_file: str
    index_file: str
    usage_file: str
    stage_file: str
    dockerfile: str
    dockerignore: str
    work_dir: str
    plans_dir: str
    gates_dir: str
    attempts_dir: str
    rebuild: bool
    status: str
    next_action: str
    stop_reason: str
    errors: list[str]
    warnings: list[str]
    limitations: list[str]
    gaps: list[str]
    plan: EnvironmentPlan
    plan_receipts: list[dict[str, Any]]
    plan_hash: str
    last_gate_hash: str
    failed_plan_hash: str
    plan_revision: int
    plan_calls: int
    plan_source: str
    gate: dict[str, Any]
    gate_rejections: int
    approved_plan: EnvironmentPlan
    attempt: int
    diagnose_calls: int
    failure: dict[str, Any]
    diagnosis: dict[str, Any]
    failure_signatures: list[str]
    build: dict[str, Any]
    smoke: dict[str, Any]
    image: dict[str, Any]
    environment_hash: str
    context_hash: str
    source_revision: str
    executed_nodes: list[str]
    visits: dict[str, int]


def empty_state(run_state: Mapping[str, Any], paths: EnvironmentPaths) -> EnvironmentState:
    return {
        "run_id": str(run_state.get("run_id", "")),
        "repository": str(run_state.get("repository", "")),
        "run_file": str(run_state.get("run_file", "")),
        "artifact_dir": str(paths.root),
        "state_file": str(paths.state_file),
        "environment_file": str(paths.environment_file),
        "handle_file": str(paths.handle_file),
        "index_file": str(paths.index_file),
        "usage_file": str(paths.usage_file),
        "stage_file": str(paths.stage_file),
        "dockerfile": str(paths.dockerfile),
        "dockerignore": str(paths.dockerignore),
        "work_dir": str(paths.work_dir),
        "plans_dir": str(paths.plans_dir),
        "gates_dir": str(paths.gates_dir),
        "attempts_dir": str(paths.attempts_dir),
        "rebuild": False,
        "status": "running",
        "next_action": "preflight",
        "stop_reason": "",
        "errors": [],
        "warnings": [],
        "limitations": [],
        "gaps": [],
        "plan": {},
        "plan_receipts": [],
        "plan_hash": "",
        "last_gate_hash": "",
        "failed_plan_hash": "",
        "plan_revision": 0,
        "plan_calls": 0,
        "plan_source": "initial",
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
        "source_revision": "",
        "executed_nodes": [],
        "visits": {},
    }


def canonical_hash(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def plan_hash(plan: Mapping[str, Any]) -> str:
    semantic = dict(plan)
    for key in ("plan_revision", "plan_source", "model", "changes", "based_on"):
        semantic.pop(key, None)
    return canonical_hash(semantic)



