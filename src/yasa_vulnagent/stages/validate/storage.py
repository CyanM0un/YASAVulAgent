"""Artifact paths and JSON helpers for the validate stage."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .schema import finding_key


@dataclass(frozen=True)
class ValidationPaths:
    root: Path
    state_file: Path
    validation_file: Path
    selection_file: Path
    index_file: Path
    usage_file: Path
    stage_file: Path
    findings_dir: Path
    verifier_dir: Path
    environment_dir: Path


def validation_paths(stages_dir: str | Path) -> ValidationPaths:
    root = Path(stages_dir) / "validate"
    return ValidationPaths(
        root=root,
        state_file=root / "state.json",
        validation_file=root / "validation.json",
        selection_file=root / "selection.json",
        index_file=root / "index.json",
        usage_file=root / "usage.json",
        stage_file=root / "stage.json",
        findings_dir=root / "findings",
        verifier_dir=root / "verifier",
        environment_dir=root / "environment",
    )


def paths_from_state(state: Mapping[str, Any]) -> ValidationPaths:
    return ValidationPaths(
        root=Path(str(state["artifact_dir"])),
        state_file=Path(str(state["state_file"])),
        validation_file=Path(str(state["validation_file"])),
        selection_file=Path(str(state["selection_file"])),
        index_file=Path(str(state["index_file"])),
        usage_file=Path(str(state["usage_file"])),
        stage_file=Path(str(state["stage_file"])),
        findings_dir=Path(str(state["artifact_dir"])) / "findings",
        verifier_dir=Path(str(state["artifact_dir"])) / "verifier",
        environment_dir=Path(str(state["artifact_dir"])) / "environment",
    )


def finding_dir(paths: ValidationPaths, finding_id: str) -> Path:
    return paths.findings_dir / finding_key(finding_id)


def verifier_finding_dir(paths: ValidationPaths, finding_id: str) -> Path:
    return paths.verifier_dir / finding_key(finding_id)


def write_json(path: Path, value: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return value


def write_text(path: Path, value: str) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(value, encoding="utf-8")
    temporary.replace(path)
