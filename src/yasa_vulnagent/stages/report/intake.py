"""Read and join validation/audit material for report generation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

MAX_EVIDENCE_FILES = 5
MAX_EVIDENCE_CHARS = 4000


class ReportInputError(RuntimeError):
    """Raised when the report stage lacks required upstream material."""


def validation_file(state: Mapping[str, Any]) -> Path:
    return Path(str(state["stages_dir"])) / "validate" / "validation.json"


def load_validation(state: Mapping[str, Any]) -> tuple[dict[str, Any], Path]:
    path = validation_file(state)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ReportInputError(f"validation artifact is missing or invalid: {path}") from exc
    if not isinstance(value, dict):
        raise ReportInputError("validation artifact must be an object")
    status = value.get("status")
    if status not in {"complete", "partial"}:
        raise ReportInputError(f"validation status is not reportable: {status!r}")
    if not str(value.get("repo_commit") or "").strip():
        raise ReportInputError("validation artifact has no repo_commit")
    return value, path


def select_findings(
    validation: Mapping[str, Any],
    explicit: list[str],
    *,
    limit: int,
) -> tuple[list[dict[str, Any]], int]:
    findings = [
        item
        for item in validation.get("findings", [])
        if isinstance(item, dict) and item.get("disposition") == "confirmed"
    ]
    by_id = {str(item.get("finding_id") or item.get("id") or ""): item for item in findings}
    if explicit:
        selected: list[dict[str, Any]] = []
        for finding_id in explicit:
            finding = by_id.get(finding_id)
            if finding is None:
                raise ReportInputError(
                    f"finding is not a confirmed validation result: {finding_id}"
                )
            if finding not in selected:
                selected.append(finding)
    else:
        selected = list(findings)
    omitted = max(0, len(selected) - limit) if limit > 0 else 0
    return selected[:limit], omitted


def load_audit(validation: Mapping[str, Any], run_dir: Path) -> dict[str, Any]:
    raw = str(validation.get("source_audit") or "").strip()
    if not raw:
        raise ReportInputError("validation artifact has no source_audit")
    path = Path(raw)
    if not path.is_absolute():
        path = run_dir / path
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ReportInputError(f"audit artifact is missing or invalid: {path}") from exc
    if not isinstance(value, dict):
        raise ReportInputError("audit artifact must be an object")
    return value


def audit_finding(audit: Mapping[str, Any], finding_id: str) -> dict[str, Any] | None:
    for item in audit.get("findings", []):
        if not isinstance(item, dict):
            continue
        if str(item.get("id") or item.get("finding_id") or "") == finding_id:
            return item
    return None


def normalize_cwe(values: Any) -> list[str]:
    result: list[str] = []
    for item in values if isinstance(values, list) else []:
        text = str(item).strip().upper()
        if not text:
            continue
        if text.isdigit():
            text = f"CWE-{text}"
        if text.startswith("CWE-") and text[4:].isdigit() and text not in result:
            result.append(text)
    return result


def _artifact_text(root: Path, relative: Any) -> str:
    if not relative:
        return ""
    path = Path(str(relative))
    if not path.is_absolute():
        path = root / path
    try:
        resolved = path.resolve()
        resolved.relative_to(root.resolve())
    except (OSError, ValueError):
        return ""
    if not resolved.is_file():
        return ""
    try:
        return resolved.read_text(encoding="utf-8", errors="replace")[:MAX_EVIDENCE_CHARS]
    except OSError:
        return ""


def _evidence_texts(
    root: Path, finding: Mapping[str, Any]
) -> list[dict[str, str]]:
    items: list[Any] = []
    for key in ("evidence",):
        value = finding.get(key)
        if isinstance(value, list):
            items.extend(value)
    verifier = finding.get("verifier")
    if isinstance(verifier, dict) and isinstance(verifier.get("evidence"), list):
        items.extend(verifier["evidence"])
    reproduction = finding.get("reproduction")
    if isinstance(reproduction, dict) and isinstance(reproduction.get("artifacts"), list):
        items.extend({"artifact": item} for item in reproduction["artifacts"])
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in items:
        relative = item.get("artifact") if isinstance(item, dict) else item
        text = _artifact_text(root, relative)
        if not text:
            continue
        key = str(relative)
        if key in seen:
            continue
        seen.add(key)
        result.append({"artifact": key, "content": text})
        if len(result) >= MAX_EVIDENCE_FILES:
            break
    return result


def material(
    finding: Mapping[str, Any],
    audit: Mapping[str, Any],
    *,
    validation_root: Path,
    repo_commit: str,
    current_commit: str,
) -> tuple[dict[str, Any], list[str]]:
    finding_id = str(finding.get("finding_id") or finding.get("id") or "")
    audit_item = audit_finding(audit, finding_id)
    gaps: list[str] = []
    if audit_item is None:
        gaps.append("audit finding is missing; cannot source CWE, file, or entry point")
        audit_item = {}
    cwe = normalize_cwe(audit_item.get("cwe_ids"))
    if not cwe:
        gaps.append("audit finding has no CWE identifier")
    if finding.get("execution_status") != "completed":
        gaps.append("validation execution_status is not completed")
    if finding.get("reproduction_level") in {"internal_auxiliary", "not_attempted"}:
        gaps.append("validation reproduction level is not decisive")
    if not isinstance(finding.get("environment"), dict):
        gaps.append("validation environment record is missing")
    if not isinstance(finding.get("reproduction"), dict):
        gaps.append("validation reproduction record is missing")
    if not isinstance(finding.get("verifier"), dict):
        gaps.append("validation verifier record is missing")
    return {
        "finding_id": finding_id,
        "repo_commit": repo_commit,
        "current_commit": current_commit,
        "audit": {
            "title": audit_item.get("title", finding.get("title", "")),
            "severity": audit_item.get("severity", "unknown"),
            "confidence": audit_item.get("confidence", "unknown"),
            "cwe_ids": cwe,
            "entry_point": audit_item.get("entry_point", ""),
            "impact": audit_item.get("impact", ""),
            "prerequisites": audit_item.get("prerequisites", []),
            "violated_invariant": audit_item.get("violated_invariant", ""),
            "source_to_sink": audit_item.get("source_to_sink", []),
            "evidence": audit_item.get("evidence", []),
            "reason": audit_item.get("reason", ""),
            "protected_asset": audit_item.get("protected_asset", ""),
            "limitations": audit_item.get("limitations", []),
        },
        "validation": {
            "title": finding.get("title", ""),
            "disposition": finding.get("disposition", ""),
            "execution_status": finding.get("execution_status", ""),
            "reproduction_level": finding.get("reproduction_level", ""),
            "intended_behavior": finding.get("intended_behavior", {}),
            "observed_result": finding.get("observed_result", ""),
            "environment": finding.get("environment", {}),
            "reproduction": finding.get("reproduction", {}),
            "evidence": finding.get("evidence", []),
            "verifier": finding.get("verifier", {}),
            "agent_stop_reason": finding.get("agent_stop_reason", ""),
            "limitations": finding.get("limitations", []),
        },
        "evidence": _evidence_texts(validation_root, finding),
    }, gaps
