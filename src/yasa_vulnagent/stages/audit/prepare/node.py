"""Audit prepare: resolve inputs, project scope, and normalize handoffs."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..storage import load_json, paths_from_state, unique, write_prepare_checkpoint
from .inputs import ResolvedInputs, resolve_inputs
from .inventory import current_revision, load_scope
from .normalize import normalize_entries, normalize_patches


def prepare(state: dict[str, Any], runtime: Any = None) -> dict[str, object]:
    """Build the audit input snapshot without calling a model or redoing discover."""
    del runtime
    resolved = resolve_inputs(state)
    paths = paths_from_state(state)
    existing = state.get("prepare") if isinstance(state.get("prepare"), dict) else {}
    signature = resolved.signature
    if existing.get("input_signature") == signature:
        audit = _load_existing_audit(paths.audit_file)
        if audit is not None:
            return _result(
                state,
                resolved,
                existing,
                scope=state.get("scope") or audit.get("scope") or {},
                entries=state.get("entries") or audit.get("entries") or [],
                patches=state.get("patches") or audit.get("patches") or [],
                gaps=existing.get("gaps") or [],
                warnings=state.get("warnings") or existing.get("warnings") or [],
                stop_reason=str(existing.get("stop_reason") or ""),
            )
    if existing.get("input_signature") is not None and existing.get("input_signature") != signature:
        raise ValueError(
            "audit inputs changed since prepare; start a new audit run"
        )

    scope_inventory = load_scope(resolved.ledger_file)
    current = current_revision(resolved.repository)
    gaps = list(resolved.gaps)
    warnings = list(resolved.warnings)
    limitations = list(resolved.limitations)
    if (
        resolved.discover_revision
        and current
        and resolved.discover_revision != current
    ):
        limitations.append(
            "current source revision differs from the discover revision: "
            f"{resolved.discover_revision} -> {current}"
        )

    entries: list[dict[str, Any]] = []
    patches: list[dict[str, Any]] = []
    routes = {
        "entries": "not_requested",
        "patches": "not_requested",
    }
    if resolved.mode in {"entries", "combined"}:
        routes["entries"] = "missing"
        if resolved.entries_file is not None:
            try:
                entries, entry_gaps, entry_warnings = normalize_entries(
                    resolved.entries_file,
                    resolved.ledger_file,
                    resolved.repository,
                    scope_inventory.files,
                    discover_revision=resolved.discover_revision,
                    current_revision=current,
                )
            except ValueError as exc:
                gaps.append(f"confirmed entries are invalid: {exc}")
                routes["entries"] = "invalid"
            else:
                gaps.extend(entry_gaps)
                warnings.extend(entry_warnings)
                routes["entries"] = "used" if entries else "empty"

    if resolved.mode in {"patches", "combined"}:
        routes["patches"] = "missing"
        if resolved.patch_file is not None:
            try:
                patches, patch_gaps, patch_warnings = normalize_patches(
                    resolved.patch_file,
                    resolved.run_root,
                    _history_dir(resolved),
                    scope_inventory.files,
                )
            except ValueError as exc:
                gaps.append(f"patch graphs are invalid: {exc}")
                routes["patches"] = "invalid"
            else:
                gaps.extend(patch_gaps)
                warnings.extend(patch_warnings)
                routes["patches"] = "used" if patches else "empty"

    blocking = _blocking(resolved.mode, entries, patches)
    if blocking:
        gaps.append(_blocking_message(resolved.mode))
    if resolved.mode == "combined":
        if routes["entries"] != "used" and routes["patches"] == "used":
            limitations.append("combined run is using patches without usable entries")
        if routes["patches"] != "used" and routes["entries"] == "used":
            limitations.append("combined run is using entries without usable patches")
    if scope_inventory.gaps:
        gaps.extend(scope_inventory.gaps)
    gaps = unique(gaps)
    warnings = unique(warnings)
    limitations = unique([*limitations, *gaps])
    stop_reason = "inputs_unavailable" if blocking else ""
    prepare_result = {
        "status": "partial" if (blocking or gaps or limitations) else "complete",
        "mode": resolved.mode,
        "routes": routes,
        "input_signature": signature,
        "inputs": {
            "entries_file": str(resolved.entries_file) if resolved.entries_file else "",
            "patch_file": str(resolved.patch_file) if resolved.patch_file else "",
            "ledger_file": str(resolved.ledger_file),
            "overview_file": str(resolved.overview_file) if resolved.overview_file else "",
            "scope_source": scope_inventory.source,
        },
        "source_revision": resolved.discover_revision,
        "current_source_revision": current,
        "scope_file_count": len(scope_inventory.files),
        "excluded_file_count": scope_inventory.excluded_count,
        "entries_loaded": len(entries),
        "patches_loaded": len(patches),
        "usable_patch_count": sum(1 for patch in patches if patch.get("usable")),
        "gaps": gaps,
        "warnings": warnings,
        "limitations": limitations,
        "stop_reason": stop_reason,
    }
    scope = {
        "files": scope_inventory.files,
        "entry_ids": [entry["id"] for entry in entries],
        "patch_ids": [patch["id"] for patch in patches],
        "limitations": limitations,
    }
    updated = {
        **state,
        "prepare": prepare_result,
        "scope": scope,
        "entries": entries,
        "patches": patches,
        "gaps": gaps,
        "warnings": warnings,
    }
    write_prepare_checkpoint(updated)
    return _result(
        state,
        resolved,
        prepare_result,
        scope=scope,
        entries=entries,
        patches=patches,
        gaps=gaps,
        warnings=warnings,
        stop_reason=stop_reason,
    )


def _result(
    state: dict[str, Any],
    resolved: ResolvedInputs,
    prepare_result: dict[str, Any],
    *,
    scope: dict[str, Any],
    entries: list[dict[str, Any]],
    patches: list[dict[str, Any]],
    gaps: list[str],
    warnings: list[str],
    stop_reason: str,
) -> dict[str, object]:
    framework = dict(state.get("framework") or {})
    inputs = {
        "init": resolved.init_status,
        "discover": resolved.discover_status,
        "entries": prepare_result.get("routes", {}).get("entries", "missing"),
        "patches": prepare_result.get("routes", {}).get("patches", "missing"),
    }
    framework.update(
        {
            "executed": [],
            "visits": {},
            "recon_done": bool(framework.get("recon_done", False)),
            "inputs": inputs,
        }
    )
    return {
        "prepare": prepare_result,
        "scope": scope,
        "entries": entries,
        "patches": patches,
        "gaps": list(dict.fromkeys(gaps)),
        "warnings": list(dict.fromkeys(warnings)),
        "status": "running",
        "stop_reason": stop_reason,
        "next_action": "plan",
        "framework": framework,
    }


def _load_existing_audit(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        audit = load_json(path)
    except (OSError, ValueError):
        return None
    if not isinstance(audit.get("entries"), list) or not isinstance(
        audit.get("patches"), list
    ):
        return None
    return audit


def _history_dir(resolved: ResolvedInputs) -> Path:
    if resolved.patch_file is not None:
        return resolved.patch_file.parent
    return resolved.run_root / "stages" / "init" / "security_history"


def _blocking(
    mode: str,
    entries: list[dict[str, Any]],
    patches: list[dict[str, Any]],
) -> bool:
    if mode == "entries":
        return not entries
    if mode == "patches":
        return not patches
    return not entries and not patches


def _blocking_message(mode: str) -> str:
    if mode == "entries":
        return "no confirmed entries are available for audit"
    if mode == "patches":
        return "no patch graphs are available for audit"
    return "no confirmed entries or patch graphs are available for audit"
