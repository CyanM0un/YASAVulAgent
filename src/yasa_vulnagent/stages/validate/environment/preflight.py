"""Docker preflight node for the environment build graph."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from langgraph.runtime import Runtime

from ....workflow.state import RunContext
from .docker import DockerClient
from .schema import EnvironmentState
from .storage import git_revision, paths_from_state, write_json


def preflight_node(
    state: EnvironmentState,
    runtime: Runtime[RunContext] | None = None,
) -> dict[str, Any]:
    context = runtime.context if runtime is not None else None
    if context is None:
        from ....config import load_settings

        context = RunContext(settings=load_settings())
    settings = context.settings
    docker = context.docker or DockerClient(settings)
    result = docker.preflight()
    paths = paths_from_state(state)
    write_json(paths.root / "preflight.json", result)
    repository = Path(str(state["repository"]))
    revision = git_revision(repository)
    if result.get("status") != "ready":
        kind = str(result.get("failure_kind", "docker_unavailable"))
        return {
            **dict(state),
            "status": "blocked",
            "next_action": "classify",
            "stop_reason": kind,
            "source_revision": revision,
            "gaps": [
                *state.get("gaps", []),
                *[
                    item
                    for item in (
                        str(result.get("message", "")),
                        str(result.get("remediation", "")),
                    )
                    if item
                ],
            ],
        }
    return {
        **dict(state),
        "status": "running",
        "next_action": "plan",
        "source_revision": revision,
        "warnings": [*state.get("warnings", []), *result.get("warnings", [])],
    }
