"""Shared fixtures for audit tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from yasa_vulnagent.stages.discover.ledger import DiscoverLedger


def make_run_state(
    root: Path,
    *,
    mode: str = "combined",
    source_files: dict[str, str] | None = None,
    inventories: list[str] | None = None,
    entries: list[dict[str, Any]] | None = None,
    evidence: list[dict[str, Any]] | None = None,
    patches: list[dict[str, Any]] | None = None,
    source_revision: str = "working-tree",
    init_status: str = "partial",
    discover_status: str = "partial",
    overview: bool = False,
) -> dict[str, Any]:
    repository = root / "repository"
    repository.mkdir()
    source_files = source_files or {"src/app.py": "def main():\n    return 1\n"}
    for path, text in source_files.items():
        target = repository / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    stages = root / "stages"
    for name in ("init", "discover", "audit", "validate", "report"):
        (stages / name).mkdir(parents=True, exist_ok=True)

    discover = stages / "discover"
    ledger = DiscoverLedger.open(discover / "ledger.sqlite")
    try:
        ledger.replace_inventory(
            [{"path": path} for path in (inventories or list(source_files))], []
        )
        for item in evidence or []:
            ledger.put_evidence(item)
    finally:
        ledger.close()
    if entries is not None:
        _write_json(discover / "confirmed-entries.json", entries)

    init = stages / "init"
    history = init / "security_history"
    history.mkdir(parents=True, exist_ok=True)
    if patches is not None:
        _write_json(history / "patch_graphs.json", {"graphs": patches, "warnings": []})
        for patch in patches:
            commit = str(patch.get("commit", ""))
            if commit:
                (history / "patches" / commit).mkdir(parents=True, exist_ok=True)
                _write_json(history / "patches" / commit / "graph.json", patch)
    if overview:
        (init / "documents").mkdir(parents=True, exist_ok=True)
        (init / "documents" / "overview.md").write_text("# Overview\n", encoding="utf-8")

    records = [
        _record("init", init, init_status, {"security_history": {"artifact_dir": str(history)}}),
        _record(
            "discover",
            discover,
            discover_status,
            {"source_revision": source_revision, "ledger_file": str(discover / "ledger.sqlite")},
        ),
    ]
    return {
        "run_id": "run-1",
        "repository": str(repository),
        "run_file": str(root / "run.json"),
        "stages_dir": str(stages),
        "stages": records,
        "audit_mode": mode,
    }


def references_for(state: dict[str, Any]) -> dict[str, Any]:
    return {
        record["name"]: {
            "status": record["status"],
            "artifact_dir": record["artifact_dir"],
            "artifact_file": record["artifact_file"],
            "details": record.get("details", {}),
        }
        for record in state.get("stages", [])
    }


def _record(name: str, path: Path, status: str, details: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": name,
        "status": status,
        "started_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:01:00+00:00",
        "message": "",
        "artifact_dir": str(path),
        "artifact_file": str(path / "stage.json"),
        "details": details,
    }


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
