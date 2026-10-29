"""Artifact paths and persistence for the audit stage."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .framework import NODE_NAMES, framework_manifest
from .gaps import merge_source_messages, normalize_gaps


@dataclass(frozen=True)
class AuditPaths:
    root: Path
    state_file: Path
    audit_file: Path
    business_file: Path
    report_file: Path
    index_file: Path
    validation_file: Path
    usage_file: Path
    framework_file: Path
    stage_file: Path
    prepare_file: Path
    trace_dir: Path


def audit_paths(stages_dir: str | Path) -> AuditPaths:
    root = Path(stages_dir) / "audit"
    return AuditPaths(
        root=root,
        state_file=root / "state.json",
        audit_file=root / "audit.json",
        business_file=root / "business-logic.json",
        report_file=root / "report.md",
        index_file=root / "index.json",
        validation_file=root / "validation.json",
        usage_file=root / "usage.json",
        framework_file=root / "framework.json",
        stage_file=root / "stage.json",
        prepare_file=root / "prepare.json",
        trace_dir=root / "traces",
    )


def paths_from_state(state: Mapping[str, Any]) -> AuditPaths:
    root = Path(str(state["artifact_dir"]))
    return AuditPaths(
        root=root,
        state_file=root / "state.json",
        audit_file=root / "audit.json",
        business_file=root / "business-logic.json",
        report_file=root / "report.md",
        index_file=root / "index.json",
        validation_file=root / "validation.json",
        usage_file=root / "usage.json",
        framework_file=root / "framework.json",
        stage_file=root / "stage.json",
        prepare_file=root / "prepare.json",
        trace_dir=root / "traces",
    )


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return value


def write_json(path: Path, value: object) -> None:
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


def persist_audit_state(state: Mapping[str, Any]) -> None:
    write_json(Path(str(state["state_file"])), state)


def unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def _execution_block(
    state: Mapping[str, Any],
    node_name: str | None = None,
) -> dict[str, Any]:
    framework = state.get("framework") or {}
    executed = list(framework.get("executed", []))
    if node_name and (not executed or executed[-1] != node_name):
        executed.append(node_name)
    return {
        "executed_nodes": executed,
        "implemented_nodes": list(NODE_NAMES),
    }


def write_prepare_checkpoint(state: Mapping[str, Any]) -> None:
    """Write prepared inputs without touching the business sidecar or later nodes."""
    paths = paths_from_state(state)
    paths.root.mkdir(parents=True, exist_ok=True)
    audit = _load_or_skeleton(paths.audit_file, _audit_skeleton(state))
    audit["mode"] = str(state.get("mode", "combined"))
    audit["status"] = "partial"
    audit["business_artifact"] = "business-logic.json"
    audit["scope"] = dict(state.get("scope") or {})
    audit["entries"] = list(state.get("entries") or [])
    audit["patches"] = list(state.get("patches") or [])
    prepare = state.get("prepare") if isinstance(state.get("prepare"), dict) else {}
    audit["gaps"] = merge_source_messages(
        audit.get("gaps"), "prepare", prepare.get("gaps", [])
    )
    audit["execution"] = _execution_block(state, "prepare")
    write_json(paths.audit_file, audit)
    write_json(paths.prepare_file, prepare)


def write_plan_checkpoint(state: Mapping[str, Any]) -> None:
    """Write the first task plan without touching the business sidecar."""
    paths = paths_from_state(state)
    paths.root.mkdir(parents=True, exist_ok=True)
    audit = _load_or_skeleton(paths.audit_file, _audit_skeleton(state))
    plan = state.get("plan") if isinstance(state.get("plan"), dict) else {}
    audit["mode"] = str(state.get("mode", "combined"))
    audit["status"] = "partial"
    audit["business_artifact"] = "business-logic.json"
    audit["tasks"] = list(state.get("tasks") or [])
    audit["category_checks"] = list(state.get("category_checks") or [])
    audit["mechanism_checks"] = list(state.get("mechanism_checks") or [])
    audit["gaps"] = merge_source_messages(
        audit.get("gaps"), "plan", plan.get("gaps", [])
    )
    audit["execution"] = _execution_block(state, "plan")
    write_json(paths.audit_file, audit)


def read_business_logic(paths: AuditPaths) -> dict[str, Any]:
    """Load the canonical business sidecar; invalid content is treated as absent."""
    if not paths.business_file.is_file():
        return {}
    try:
        value = load_json(paths.business_file)
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def write_business_logic(paths: AuditPaths, business: Mapping[str, Any]) -> None:
    value = dict(business)
    # Drop implementation-status fields from older sidecars.
    value.pop("scaffold", None)
    value.pop("pending_nodes", None)
    write_json(paths.business_file, value)


def write_recon_checkpoint(
    state: Mapping[str, Any],
    business: Mapping[str, Any],
) -> None:
    """Write recon output while preserving trace, verify, and review-owned fields."""
    paths = paths_from_state(state)
    paths.root.mkdir(parents=True, exist_ok=True)
    audit = _load_or_skeleton(paths.audit_file, _audit_skeleton(state))
    audit["mode"] = str(state.get("mode", "combined"))
    audit["status"] = "partial"
    audit["business_artifact"] = "business-logic.json"
    audit["recon"] = dict(state.get("recon") or {})
    audit["tasks"] = list(state.get("tasks") or audit.get("tasks") or [])
    recon = state.get("recon") if isinstance(state.get("recon"), dict) else {}
    audit["gaps"] = merge_source_messages(
        audit.get("gaps"), "recon", recon.get("gaps", [])
    )
    audit["execution"] = _execution_block(state, "recon")
    business = dict(business)
    write_business_logic(paths, business)
    write_json(paths.audit_file, audit)


def write_trace_artifact(paths: AuditPaths, trace: Mapping[str, Any]) -> str:
    """Write one full task trace and return its run-relative artifact path."""
    trace_id = str(trace.get("id", "")).strip()
    if not trace_id:
        raise ValueError("trace id is required")
    path = paths.trace_dir / f"{trace_id}.json"
    write_json(path, dict(trace))
    return path.relative_to(paths.root).as_posix()


def read_trace_artifact(paths: AuditPaths, trace_id: str) -> dict[str, Any] | None:
    path = paths.trace_dir / f"{Path(trace_id).name}.json"
    if not path.is_file():
        return None
    try:
        return load_json(path)
    except (OSError, ValueError):
        return None


def write_trace_checkpoint(state: Mapping[str, Any]) -> None:
    """Merge trace results while preserving verify-owned findings and reviews."""
    paths = paths_from_state(state)
    paths.root.mkdir(parents=True, exist_ok=True)
    audit = _load_or_skeleton(paths.audit_file, _audit_skeleton(state))
    audit["mode"] = str(state.get("mode", "combined"))
    audit["status"] = "partial"
    audit["business_artifact"] = "business-logic.json"
    audit["tasks"] = list(state.get("tasks") or [])
    audit["category_checks"] = list(state.get("category_checks") or [])
    audit["mechanism_checks"] = list(state.get("mechanism_checks") or [])
    audit["trace"] = dict(state.get("trace") or {})
    audit["traces"] = list(state.get("traces") or [])
    audit["summaries"] = _merge_by_id(
        audit.get("summaries"),
        state.get("summaries"),
    )

    audit["gaps"] = merge_source_messages(
        audit.get("gaps"), "trace", (state.get("trace") or {}).get("gaps", [])
    )

    audit["execution"] = _execution_block(state, "trace")
    write_json(paths.audit_file, audit)


def _merge_by_id(existing: Any, incoming: Any) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for source in (existing, incoming):
        if not isinstance(source, list):
            continue
        for item in source:
            if isinstance(item, dict) and str(item.get("id", "")).strip():
                merged[str(item["id"])] = dict(item)
    return list(merged.values())


def write_verify_checkpoint(state: Mapping[str, Any]) -> None:
    """Merge verification findings while preserving earlier audit artifacts."""
    paths = paths_from_state(state)
    paths.root.mkdir(parents=True, exist_ok=True)
    audit = _load_or_skeleton(paths.audit_file, _audit_skeleton(state))
    audit["mode"] = str(state.get("mode", "combined"))
    audit["status"] = "partial"
    audit["business_artifact"] = "business-logic.json"
    audit["verify"] = dict(state.get("verify") or {})
    audit["findings"] = _merge_by_id(audit.get("findings"), state.get("findings"))
    audit["reviews"] = _merge_by_id(audit.get("reviews"), state.get("reviews"))

    verify = state.get("verify") if isinstance(state.get("verify"), dict) else {}
    audit["gaps"] = merge_source_messages(
        audit.get("gaps"), "verify", verify.get("gaps", [])
    )

    audit["execution"] = _execution_block(state, "verify")
    write_json(paths.audit_file, audit)


def write_gate_checkpoint(state: Mapping[str, Any]) -> None:
    """Merge the gate decision into the audit checkpoint without a separate artifact."""
    paths = paths_from_state(state)
    paths.root.mkdir(parents=True, exist_ok=True)
    audit = _load_or_skeleton(paths.audit_file, _audit_skeleton(state))
    audit["mode"] = str(state.get("mode", "combined"))
    gate_status = (
        str((state.get("gate") or {}).get("status", ""))
        if isinstance(state.get("gate"), dict)
        else ""
    )
    if gate_status not in {"complete", "partial"}:
        gate_status = str(state.get("status", "partial"))
    audit["status"] = gate_status if gate_status in {"complete", "partial"} else "partial"
    audit["business_artifact"] = "business-logic.json"
    audit["gate"] = dict(state.get("gate") or {})
    audit["tasks"] = list(state.get("tasks") or [])
    audit["gaps"] = normalize_gaps(state.get("gaps"))
    audit["execution"] = _execution_block(state, "gate")
    write_json(paths.audit_file, audit)


def write_final_artifacts(state: Mapping[str, Any]) -> None:
    """Write the final audit, business, index, validation, and report artifacts."""
    paths = paths_from_state(state)
    paths.root.mkdir(parents=True, exist_ok=True)

    audit = _load_or_skeleton(paths.audit_file, _audit_skeleton(state))
    final_status = _final_status(state, audit)
    audit["mode"] = str(state.get("mode", "combined"))
    audit["gaps"] = normalize_gaps(audit.get("gaps"))
    if final_status == "complete" and audit["gaps"]:
        final_status = "partial"
    audit["status"] = final_status
    if isinstance(state.get("gate"), dict) and state.get("gate"):
        audit["gate"] = dict(state["gate"])
    audit["execution"] = _execution_block(state, "finalize")

    business = _load_or_skeleton(paths.business_file, _business_skeleton(state))
    business["mode"] = str(state.get("mode", "combined"))
    business["status"] = str(business.get("status") or "partial")

    write_json(paths.audit_file, audit)
    write_json(paths.business_file, business)
    write_json(paths.framework_file, _framework(state))
    write_json(paths.index_file, _index(state, paths, final_status))
    write_json(
        paths.validation_file,
        {
            "status": "not_run",
            "valid": False,
            "errors": [],
            "warnings": [
                "dynamic validation and external contract validation are pending"
            ],
        },
    )
    write_text(paths.report_file, _report(state, audit, final_status))


def _final_status(state: Mapping[str, Any], audit: Mapping[str, Any]) -> str:
    candidates = [
        (state.get("gate") or {}).get("status")
        if isinstance(state.get("gate"), dict)
        else None,
        (audit.get("gate") or {}).get("status")
        if isinstance(audit.get("gate"), dict)
        else None,
    ]
    for value in candidates:
        if str(value) in {"complete", "partial"}:
            return str(value)
    return "partial"


def _load_or_skeleton(path: Path, skeleton: dict[str, Any]) -> dict[str, Any]:
    if not path.is_file():
        return skeleton
    try:
        value = load_json(path)
    except (OSError, ValueError):
        return skeleton
    # Drop implementation-status fields from older artifacts.
    value.pop("scaffold", None)
    value.pop("pending_nodes", None)
    return value


def _framework(state: Mapping[str, Any]) -> dict[str, Any]:
    manifest = framework_manifest()
    framework = state.get("framework") or {}
    executed = list(framework.get("executed", []))
    manifest["executed_nodes"] = executed
    manifest["implemented_nodes"] = list(NODE_NAMES)
    return manifest


def _audit_skeleton(state: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "run_id": str(state.get("run_id", "")),
        "repo": str(state.get("repository", "")),
        "mode": str(state.get("mode", "combined")),
        "status": "partial",
        "business_artifact": "business-logic.json",
        "scope": {
            "files": [],
            "entry_ids": [],
            "patch_ids": [],
            "limitations": [],
        },
        "entries": [],
        "patches": [],
        "tasks": [],
        "traces": [],
        "category_checks": [],
        "mechanism_checks": [],
        "summaries": [],
        "recon": {},
        "gate": {},
        "findings": [],
        "reviews": [],
        "gaps": [],
        "execution": _execution_block(state),
    }


def _business_skeleton(state: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "run_id": str(state.get("run_id", "")),
        "repo": str(state.get("repository", "")),
        "mode": str(state.get("mode", "combined")),
        "status": "partial",
        "scope": {
            "files": [],
            "limitations": [],
        },
        "constraints": [],
        "operations": [],
        "investigations": [],
        "gaps": [],
        "warnings": [],
        "limitations": [],
    }


def _index(
    state: Mapping[str, Any],
    paths: AuditPaths,
    status: str,
) -> dict[str, Any]:
    framework = state.get("framework") or {}
    executed = list(framework.get("executed", []))
    return {
        "stage": "audit",
        "status": status,
        "mode": str(state.get("mode", "combined")),
        "artifact_dir": str(paths.root),
        "state_file": str(paths.state_file),
        "audit_file": str(paths.audit_file),
        "prepare_file": str(paths.prepare_file),
        "business_artifact_file": str(paths.business_file),
        "report_file": str(paths.report_file),
        "validation_file": str(paths.validation_file),
        "usage_file": str(paths.usage_file),
        "executed_nodes": executed,
        "implemented_nodes": list(NODE_NAMES),
        "limitations": [
            "dynamic validation and external contract validation are pending"
        ],
    }


def _report(
    state: Mapping[str, Any],
    audit: Mapping[str, Any],
    status: str,
) -> str:
    framework = state.get("framework") or {}
    prepare = state.get("prepare") or {}
    gate = state.get("gate") if isinstance(state.get("gate"), dict) else {}
    gate = gate or (audit.get("gate") if isinstance(audit.get("gate"), dict) else {})
    executed_nodes = list(framework.get("executed", []))
    executed = ", ".join(executed_nodes) or "(none)"
    validation_pending = gate.get("validation_pending") if isinstance(gate.get("validation_pending"), list) else []
    pending_ids = [str(item.get("finding_id", "")) for item in validation_pending if isinstance(item, dict)]
    debt_reasons = [
        str(item.get("reason", ""))
        for item in gate.get("debts", [])
        if isinstance(item, dict) and item.get("blocking")
    ]
    lines = [
        f"# Audit ({status})",
        "",
        "This report records static audit coverage, not a security guarantee.",
        "Candidate flows were verified where possible; unresolved work remains visible.",
        "",
        f"- Mode: `{state.get('mode', 'combined')}`",
        f"- Prepare: `{prepare.get('status', 'not_run')}`",
        f"- Plan: `{(state.get('plan') or {}).get('status', 'not_run')}`",
        f"- Plan tasks: `{(state.get('plan') or {}).get('task_count', 0)}`",
        f"- Trace: `{(state.get('trace') or {}).get('status', 'not_run')}`",
        f"- Candidate flows: `{(state.get('trace') or {}).get('flow_count', 0)}`",
        f"- Recon: `{(state.get('recon') or {}).get('status', 'not_run')}`",
        f"- Verify: `{(state.get('verify') or {}).get('status', 'not_run')}`",
        f"- Findings: `{(state.get('verify') or {}).get('finding_count', 0)}`",
        f"- Confirmed findings: `{(state.get('verify') or {}).get('confirmed_count', 0)}`",
        f"- Needs validation: `{gate.get('needs_validation_count', 0)}`",
        f"- Business constraints: `{(state.get('recon') or {}).get('constraint_count', 0)}`",
        f"- Business operations: `{(state.get('recon') or {}).get('operation_count', 0)}`",
        f"- Business investigations: `{(state.get('recon') or {}).get('investigation_count', 0)}`",
        f"- Gate: `{gate.get('status', 'not_run')}`",
        f"- Gate action: `{gate.get('action', '')}`",
        f"- Blocking debt: `{gate.get('blocking_count', 0)}`",
        f"- Dynamic validation pending: `{', '.join(pending_ids) if pending_ids else 'none'}`",
        f"- Executed: {executed}",
        f"- Audit artifact: `{state.get('audit_file', '')}`",
        f"- Business artifact: `{state.get('business_file', '')}`",
    ]
    if debt_reasons:
        lines.extend(["", "## Open blocking debt", ""])
        lines.extend(f"- {reason}" for reason in debt_reasons)
    if status == "partial":
        lines.extend(
            [
                "",
                "This audit is not a security conclusion because the gate did not close all recorded work.",
            ]
        )
    lines.extend(["", "See `docs/audit-framework.md` for the audit method.", ""])
    return "\n".join(lines)


