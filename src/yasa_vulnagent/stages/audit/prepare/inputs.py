"""Resolve audit inputs from the run record without redoing discover work."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ....config import AUDIT_MODES


@dataclass(frozen=True)
class ResolvedInputs:
    run_root: Path
    repository: Path
    mode: str
    entries_file: Path | None
    patch_file: Path | None
    ledger_file: Path
    overview_file: Path | None
    discover_revision: str
    init_status: str
    discover_status: str
    gaps: tuple[str, ...]
    warnings: tuple[str, ...]
    limitations: tuple[str, ...]
    signature: dict[str, Any]


def resolve_inputs(state: Mapping[str, Any]) -> ResolvedInputs:
    mode = str(state.get("mode") or "combined")
    if mode not in AUDIT_MODES:
        raise ValueError(f"audit mode must be one of {', '.join(AUDIT_MODES)}")

    run_root = _run_root(state)
    repository = Path(str(state["repository"])).expanduser().resolve()
    if not repository.is_dir():
        raise ValueError(f"audit repository is not a directory: {repository}")
    references = state.get("references") or {}
    init = references.get("init") or {}
    discover = references.get("discover") or {}
    init_details = init.get("details") if isinstance(init.get("details"), dict) else {}
    discover_details = (
        discover.get("details") if isinstance(discover.get("details"), dict) else {}
    )

    init_dir = _stage_dir(run_root, init.get("artifact_dir"), "init")
    discover_dir = _stage_dir(
        run_root, discover.get("artifact_dir"), "discover"
    )
    history = init_details.get("security_history")
    history = history if isinstance(history, dict) else {}
    documents = init_details.get("documents")
    documents = documents if isinstance(documents, dict) else {}

    history_dir = _resolve_run_path(run_root, history.get("artifact_dir"))
    if history_dir is None:
        history_dir = init_dir / "security_history"
    patch_candidate = history_dir / "patch_graphs.json"
    patch_file = patch_candidate if _inside_file(patch_candidate, run_root) else None

    overview_file = _resolve_run_path(run_root, documents.get("overview_file"))
    if overview_file is None or not overview_file.is_file():
        overview_file = init_dir / "documents" / "overview.md"
        if not overview_file.is_file():
            overview_file = None

    entries_file = discover_dir / "confirmed-entries.json"
    if not _inside_file(entries_file, run_root):
        entries_file = None
    ledger_value = discover_details.get("ledger_file")
    ledger_file = (
        Path(str(ledger_value)).expanduser()
        if isinstance(ledger_value, str) and ledger_value
        else discover_dir / "ledger.sqlite"
    )
    if not ledger_file.is_absolute():
        ledger_file = run_root / ledger_file
    ledger_file = ledger_file.resolve()
    if not ledger_file.is_relative_to(run_root):
        raise ValueError(f"discover inventory is outside the run root: {ledger_file}")
    if not ledger_file.is_file():
        raise ValueError(f"discover inventory is unavailable: {ledger_file}")

    init_status = str(init.get("status") or "missing")
    discover_status = str(discover.get("status") or "missing")
    discover_revision = str(discover_details.get("source_revision") or "")
    wants_entries = mode in {"entries", "combined"}
    wants_patches = mode in {"patches", "combined"}

    gaps: list[str] = []
    warnings: list[str] = []
    limitations: list[str] = []
    if discover_status not in {"complete", "partial"}:
        limitations.append(f"discover stage is {discover_status}")
    if init_status not in {"complete", "partial"}:
        limitations.append(f"init stage is {init_status}")
    if init_status == "partial":
        limitations.append("init stage is partial")
    if discover_status == "partial":
        limitations.append("discover stage is partial")
    if wants_entries and overview_file is None:
        limitations.append("init project overview is unavailable")

    if wants_entries and entries_file is None:
        message = "discover confirmed-entries.json is unavailable"
        (gaps if mode == "entries" else limitations).append(message)
    if wants_patches and patch_file is None:
        message = "init security-history patch_graphs.json is unavailable"
        (gaps if mode == "patches" else limitations).append(message)

    signature = {
        "mode": mode,
        "discover_source_revision": discover_revision,
        "entries": _file_descriptor(entries_file, run_root),
        "patch_graphs": _file_descriptor(patch_file, run_root),
        "overview": _file_descriptor(overview_file, run_root),
        "ledger": _file_descriptor(ledger_file, run_root),
    }
    return ResolvedInputs(
        run_root=run_root,
        repository=repository,
        mode=mode,
        entries_file=entries_file,
        patch_file=patch_file,
        ledger_file=ledger_file,
        overview_file=overview_file,
        discover_revision=discover_revision,
        init_status=init_status,
        discover_status=discover_status,
        gaps=tuple(gaps),
        warnings=tuple(warnings),
        limitations=tuple(dict.fromkeys(limitations)),
        signature=signature,
    )


def _run_root(state: Mapping[str, Any]) -> Path:
    artifact_dir = Path(str(state["artifact_dir"])).resolve()
    if artifact_dir.name == "audit" and artifact_dir.parent.name == "stages":
        return artifact_dir.parent.parent
    return artifact_dir.parent


def _stage_dir(run_root: Path, value: Any, name: str) -> Path:
    path = Path(str(value or run_root / "stages" / name)).expanduser()
    if not path.is_absolute():
        path = run_root / path
    try:
        path = path.resolve()
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"{name} stage directory is unreadable: {path}") from exc
    if not path.is_relative_to(run_root):
        raise ValueError(f"{name} stage directory is outside the run root: {path}")
    return path


def _resolve_run_path(run_root: Path, value: Any) -> Path | None:
    if not isinstance(value, str) or not value.strip():
        return None
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = run_root / path
    try:
        path = path.resolve()
    except (OSError, RuntimeError):
        return None
    if not path.is_relative_to(run_root):
        return None
    return path


def _inside_file(path: Path, run_root: Path) -> bool:
    if not path.is_file():
        return False
    try:
        return path.resolve().is_relative_to(run_root)
    except (OSError, RuntimeError):
        return False


def _file_descriptor(path: Path | None, run_root: Path) -> dict[str, Any] | None:
    if path is None or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    try:
        relative = path.resolve().relative_to(run_root).as_posix()
    except ValueError:
        relative = str(path.resolve())
    return {
        "path": relative,
        "size": path.stat().st_size,
        "sha256": digest.hexdigest(),
    }
