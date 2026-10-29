"""Artifact paths and atomic persistence for the environment build graph."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


@dataclass(frozen=True)
class EnvironmentPaths:
    root: Path
    state_file: Path
    environment_file: Path
    handle_file: Path
    index_file: Path
    usage_file: Path
    stage_file: Path
    dockerfile: Path
    dockerignore: Path
    plans_dir: Path
    gates_dir: Path
    attempts_dir: Path
    work_dir: Path
    tool_results_dir: Path


def environment_paths(stages_dir: str | Path) -> EnvironmentPaths:
    root = Path(stages_dir) / "validate" / "environment"
    return EnvironmentPaths(
        root=root,
        state_file=root / "state.json",
        environment_file=root / "environment.json",
        handle_file=root / "handle.json",
        index_file=root / "index.json",
        usage_file=root / "usage.json",
        stage_file=root / "stage.json",
        dockerfile=root / "Dockerfile",
        dockerignore=root / "dockerignore",
        plans_dir=root / "plans",
        gates_dir=root / "gates",
        attempts_dir=root / "attempts",
        work_dir=root / "work",
        tool_results_dir=root / "work" / "tool-results",
    )


def paths_from_state(state: Mapping[str, Any]) -> EnvironmentPaths:
    root = Path(str(state["artifact_dir"]))
    return EnvironmentPaths(
        root=root,
        state_file=Path(str(state["state_file"])),
        environment_file=Path(str(state["environment_file"])),
        handle_file=Path(str(state["handle_file"])),
        index_file=Path(str(state["index_file"])),
        usage_file=Path(str(state["usage_file"])),
        stage_file=Path(str(state["stage_file"])),
        dockerfile=Path(str(state["dockerfile"])),
        dockerignore=Path(str(state["dockerignore"])),
        plans_dir=Path(str(state["plans_dir"])),
        gates_dir=Path(str(state["gates_dir"])),
        attempts_dir=Path(str(state["attempts_dir"])),
        work_dir=Path(str(state["work_dir"])),
        tool_results_dir=Path(str(state["work_dir"])) / "tool-results",
    )


def plan_file(state: Mapping[str, Any], revision: int | None = None) -> Path:
    rev = int(revision if revision is not None else state.get("plan_revision", 0))
    return paths_from_state(state).plans_dir / f"{rev:04d}.json"


def plan_receipts_file(state: Mapping[str, Any], revision: int | None = None) -> Path:
    rev = int(revision if revision is not None else state.get("plan_revision", 0))
    return paths_from_state(state).plans_dir / f"{rev:04d}.receipts.json"


def plan_effective_file(state: Mapping[str, Any], revision: int | None = None) -> Path:
    rev = int(revision if revision is not None else state.get("plan_revision", 0))
    return paths_from_state(state).plans_dir / f"{rev:04d}.effective.json"


def gate_file(state: Mapping[str, Any], revision: int | None = None) -> Path:
    rev = int(revision if revision is not None else state.get("plan_revision", 0))
    return paths_from_state(state).gates_dir / f"{rev:04d}.json"


def attempt_dir(state: Mapping[str, Any], attempt: int | None = None) -> Path:
    number = int(attempt if attempt is not None else state.get("attempt", 0))
    return paths_from_state(state).attempts_dir / f"{number:04d}"


def write_json(path: Path, value: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def write_text(path: Path, value: str) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(value, encoding="utf-8")
    temporary.replace(path)


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return value


def persist_state(state: Mapping[str, Any]) -> None:
    write_json(Path(str(state["state_file"])), state)


def git_revision(repository: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repository), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "working-tree"
    revision = result.stdout.strip()
    return revision if result.returncode == 0 and revision else "working-tree"
