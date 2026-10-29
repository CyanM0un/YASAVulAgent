"""Validate trace model output and hydrate evidence from current source."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..prepare.inventory import safe_relative
from .constants import MAX_EVIDENCE_CHARS, MAX_FLOWS_PER_TASK


class TraceResultError(ValueError):
    """Raised when a trace result cannot be validated."""


class EvidenceIndex:
    """Resolve model evidence against the repository and audit scope."""

    def __init__(self, repository: Path, scope_files: Iterable[str]) -> None:
        self.repository = Path(repository).expanduser().resolve()
        self.scope = {str(path) for path in scope_files if str(path)}

    def hydrate(
        self,
        raw: Any,
        label: str,
    ) -> tuple[list[dict[str, Any]], list[str]]:
        if raw is None:
            return [], []
        if not isinstance(raw, list):
            return [], [f"{label}: evidence must be an array"]
        evidence: list[dict[str, Any]] = []
        gaps: list[str] = []
        for index, item in enumerate(raw):
            item_label = f"{label}[{index}]"
            if not isinstance(item, dict):
                gaps.append(f"{item_label}: evidence must be an object")
                continue
            path = safe_relative(str(item.get("path", "")))
            if path is None or path not in self.scope:
                gaps.append(f"{item_label}: path is outside the audit scope")
                continue
            start = _positive_int(item.get("start_line"), f"{item_label}.start_line")
            end = _positive_int(item.get("end_line"), f"{item_label}.end_line")
            if start is None or end is None or end < start:
                gaps.append(f"{item_label}: invalid line range")
                continue
            file_path = (self.repository / path).resolve()
            try:
                file_path.relative_to(self.repository)
            except ValueError:
                gaps.append(f"{item_label}: path escapes the repository")
                continue
            try:
                lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                gaps.append(f"{item_label}: file is unavailable")
                continue
            if start > len(lines) or end > len(lines):
                gaps.append(f"{item_label}: line range is outside the file")
                continue
            explanation = str(item.get("explanation", "")).strip()
            if not explanation:
                gaps.append(f"{item_label}: explanation is required")
                continue
            quote = "\n".join(lines[start - 1 : end])[:MAX_EVIDENCE_CHARS]
            evidence.append(
                {
                    "path": path,
                    "start_line": start,
                    "end_line": end,
                    "explanation": explanation,
                    "quote": quote,
                }
            )
        return evidence, gaps


def validate_flows(
    raw: Any,
    *,
    task: Mapping[str, Any],
    categories: set[str],
    evidence_index: EvidenceIndex,
) -> tuple[list[dict[str, Any]], list[str]]:
    if raw is None:
        return [], []
    if not isinstance(raw, list):
        return [], ["flows must be an array"]
    flows: list[dict[str, Any]] = []
    gaps: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(raw[: MAX_FLOWS_PER_TASK * 2]):
        label = f"flows[{index}]"
        if not isinstance(item, dict):
            gaps.append(f"{label}: flow must be an object")
            continue
        category = str(item.get("category", "")).strip()
        if category not in categories:
            gaps.append(f"{label}: unknown category {category or '(empty)'}")
            continue
        source, source_gaps = _endpoint(item.get("source"), f"{label}.source", evidence_index)
        sink, sink_gaps = _endpoint(item.get("sink"), f"{label}.sink", evidence_index)
        gaps.extend([*source_gaps, *sink_gaps])
        if not source and not sink:
            gaps.append(f"{label}: flow has neither source nor sink evidence")
            continue
        completeness = str(item.get("completeness", "")).strip()
        if completeness not in {"complete", "source_only", "sink_only"}:
            completeness = "complete" if source and sink else ("source_only" if source else "sink_only")
        if completeness == "complete" and (not source or not sink):
            gaps.append(f"{label}: complete flow is missing source or sink")
            continue
        if completeness == "source_only" and not source:
            gaps.append(f"{label}: source_only flow has no source")
            continue
        if completeness == "sink_only" and not sink:
            gaps.append(f"{label}: sink_only flow has no sink")
            continue
        if str(item.get("reachability", "")).strip() in {"unreachable", "not_reachable"}:
            gaps.append(f"{label}: proven unreachable path is not persisted")
            continue
        if str(item.get("triggerability", "")).strip() in {"not_triggerable", "untriggerable"}:
            gaps.append(f"{label}: proven non-triggerable path is not persisted")
            continue
        reachability = str(item.get("reachability", "unknown")).strip()
        if reachability not in {"reachable", "unknown"}:
            reachability = "unknown"
        if completeness != "complete":
            reachability = "unknown"
        triggerability = str(item.get("triggerability", "unknown")).strip()
        if completeness != "complete":
            triggerability = "unknown"
        if triggerability not in {"triggerable", "unknown"}:
            triggerability = "unknown"
        if reachability != "reachable":
            triggerability = "unknown"
        kind = str(item.get("kind", "dataflow")).strip()
        if kind not in {"dataflow", "control", "authz", "config", "dynamic"}:
            kind = "dataflow"
        steps, step_gaps = _steps(item.get("steps"), f"{label}.steps", evidence_index)
        guards, guard_gaps = _guards(item.get("guards"), f"{label}.guards", evidence_index)
        direct, direct_gaps = evidence_index.hydrate(item.get("evidence"), f"{label}.evidence")
        gaps.extend([*step_gaps, *guard_gaps, *direct_gaps])
        anchors = [
            str(item.get("source", {}).get("summary", ""))
            if isinstance(item.get("source"), dict)
            else "",
            str(item.get("sink", {}).get("summary", ""))
            if isinstance(item.get("sink"), dict)
            else "",
        ]
        flow_id = _stable_id(
            "flow",
            str(task.get("id", "")),
            category,
            kind,
            *anchors,
            *_evidence_anchors([*direct, *(source or {}).get("evidence", []), *(sink or {}).get("evidence", [])]),
        )
        if flow_id in seen:
            continue
        seen.add(flow_id)
        all_evidence = _dedupe_evidence([
            *direct,
            *(source or {}).get("evidence", []),
            *(sink or {}).get("evidence", []),
            *steps,
            *guards,
        ])
        if not all_evidence:
            gaps.append(f"{label}: flow has no valid current-source evidence")
            continue
        flows.append(
            {
                "id": flow_id,
                "task_id": str(task.get("id", "")),
                "entry_ids": list(task.get("entry_ids", [])),
                "patch_ids": list(task.get("patch_ids", [])),
                "category": category,
                "cwe_hints": _ints(item.get("cwe_hints")),
                "kind": kind,
                "completeness": completeness,
                "source": source,
                "sink": sink,
                "steps": steps,
                "guards": guards,
                "reachability": reachability,
                "triggerability": triggerability,
                "confidence": _choice(item.get("confidence"), {"high", "medium", "low"}, "medium"),
                "summary": str(item.get("summary", "")).strip(),
                "impact": str(item.get("impact", "")).strip(),
                "preconditions": _strings(item.get("preconditions")),
                "unknowns": _strings(item.get("unknowns")),
                "evidence": all_evidence,
            }
        )
        if len(flows) >= MAX_FLOWS_PER_TASK:
            gaps.append(f"flows truncated at {MAX_FLOWS_PER_TASK}")
            break
    return flows, gaps


def validate_category_checks(
    raw: Any,
    *,
    task: Mapping[str, Any],
    expected: list[dict[str, Any]],
    flows: list[dict[str, Any]],
    evidence_index: EvidenceIndex,
) -> tuple[list[dict[str, Any]], list[str]]:
    raw_by_category: dict[str, dict[str, Any]] = {}
    gaps: list[str] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict) and str(item.get("category", "")).strip():
                raw_by_category[str(item["category"]).strip()] = item
    known_categories = {str(item.get("category", "")) for item in expected}
    for category in set(raw_by_category) - known_categories:
        gaps.append(f"category check references unknown category: {category}")
    flow_ids = {str(flow["id"]) for flow in flows}
    result: list[dict[str, Any]] = []
    for check in expected:
        category = str(check.get("category", ""))
        raw = raw_by_category.get(category, {})
        evidence, evidence_gaps = evidence_index.hydrate(
            raw.get("evidence") if isinstance(raw, dict) else None,
            f"category[{category}].evidence",
        )
        gaps.extend(evidence_gaps)
        raw_refs = _strings(raw.get("flow_ids")) if isinstance(raw, dict) else []
        refs = [ref for ref in raw_refs if ref in flow_ids]
        for ref in set(raw_refs) - set(refs):
            gaps.append(f"category {category}: unknown flow reference {ref}")
        status = _choice(raw.get("status") if isinstance(raw, dict) else None, {"checked", "pending", "blocked", "deferred"}, "pending")
        if not raw:
            status = "pending"
            gaps.append(f"category {category}: not covered by trace output")
        applicability = _choice(
            raw.get("applicability") if isinstance(raw, dict) else None,
            {"applicable", "not_applicable", "unknown"},
            "unknown",
        )
        reason = str(raw.get("reason", "")).strip() if isinstance(raw, dict) else ""
        if not raw:
            reason = "not covered by trace output"
        if status == "checked" and not reason:
            status = "pending"
            gaps.append(f"category {category}: checked without a reason")
        if applicability == "not_applicable" and not evidence and not refs:
            applicability = "unknown"
            gaps.append(f"category {category}: not_applicable without evidence")
        result.append(
            {
                **check,
                "status": status,
                "applicability": applicability,
                "reason": reason,
                "flow_ids": refs,
                "evidence": evidence,
            }
        )
    return result, gaps


def validate_mechanism_checks(
    raw: Any,
    *,
    expected: list[dict[str, Any]],
    flows: list[dict[str, Any]],
    evidence_index: EvidenceIndex,
    unit_results: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    raw_by_kind: dict[str, dict[str, Any]] = {}
    gaps: list[str] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict) and str(item.get("kind", "")).strip():
                raw_by_kind[str(item["kind"]).strip()] = item
    expected_kinds = {str(item.get("kind", "")) for item in expected}
    for kind in set(raw_by_kind) - expected_kinds:
        gaps.append(f"mechanism check references unknown kind: {kind}")
    flow_by_id = {str(flow["id"]): flow for flow in flows}
    result: list[dict[str, Any]] = []
    for check in expected:
        kind = str(check.get("kind", ""))
        raw = raw_by_kind.get(kind, {})
        evidence, evidence_gaps = evidence_index.hydrate(
            raw.get("evidence") if isinstance(raw, dict) else None,
            f"mechanism[{kind}].evidence",
        )
        gaps.extend(evidence_gaps)
        raw_refs = _strings(raw.get("flow_ids")) if isinstance(raw, dict) else []
        refs = [ref for ref in raw_refs if ref in flow_by_id]
        for ref in set(raw_refs) - set(refs):
            gaps.append(f"mechanism {kind}: unknown flow reference {ref}")
        outcome = _choice(
            raw.get("outcome") if isinstance(raw, dict) else None,
            {"found", "not_found", "unknown", "not_applicable"},
            "unknown",
        )
        if outcome == "found" and not any(
            flow_by_id[ref].get("completeness") == "complete" for ref in refs
        ):
            outcome = "unknown"
            gaps.append(f"mechanism {kind}: found without a complete flow")
        reason = str(raw.get("reason", "")).strip() if isinstance(raw, dict) else ""
        if outcome == "not_found" and not evidence:
            outcome = "unknown"
            gaps.append(f"mechanism {kind}: not_found without evidence")
        status = _choice(
            raw.get("status") if isinstance(raw, dict) else None,
            {"checked", "pending", "blocked", "deferred"},
            "pending",
        )
        if outcome in {"found", "not_found"} and not reason:
            status = "pending"
            gaps.append(f"mechanism {kind}: outcome without a reason")
        if outcome == "unknown" and status == "checked":
            status = "pending"
            gaps.append(f"mechanism {kind}: unknown outcome cannot close the check")
        result.append(
            {
                **check,
                "status": status,
                "outcome": outcome,
                "reason": reason,
                "flow_ids": refs,
                "unit_results": list(unit_results),
                "evidence": evidence,
            }
        )
    return result, gaps


def validate_unit_results(
    raw: Any,
    *,
    task: Mapping[str, Any],
    evidence_index: EvidenceIndex,
) -> tuple[list[dict[str, Any]], list[str]]:
    if not isinstance(raw, list):
        return [], []
    expected = {
        (str(ref.get("patch_id", "")), str(ref.get("unit_id", "")))
        for ref in task.get("repair_unit_refs", [])
        if isinstance(ref, dict)
    }
    result: list[dict[str, Any]] = []
    gaps: list[str] = []
    seen: set[tuple[str, str]] = set()
    for item in raw:
        if not isinstance(item, dict):
            gaps.append("unit result must be an object")
            continue
        patch_id = str(item.get("patch_id", "")).strip()
        unit_id = str(item.get("unit_id", "")).strip()
        if (patch_id, unit_id) not in expected:
            gaps.append(f"unit result is not assigned to this task: {patch_id}/{unit_id}")
            continue
        if (patch_id, unit_id) in seen:
            continue
        seen.add((patch_id, unit_id))
        evidence, evidence_gaps = evidence_index.hydrate(
            item.get("evidence"), f"unit[{unit_id}].evidence"
        )
        gaps.extend(evidence_gaps)
        effectiveness = _choice(
            item.get("effectiveness"),
            {"effective", "bypassed", "unknown", "not_applicable"},
            "unknown",
        )
        if not evidence:
            gaps.append(f"unit[{unit_id}]: current-source evidence is required")
            effectiveness = "unknown"
        result.append(
            {
                "patch_id": patch_id,
                "unit_id": unit_id,
                "effectiveness": effectiveness,
                "reason": str(item.get("reason", "")).strip(),
                "flow_ids": _strings(item.get("flow_ids")),
                "evidence": evidence,
            }
        )
    return result, gaps


def validate_repair_responses(
    raw: Any,
    debts: list[dict[str, Any]],
    evidence_index: EvidenceIndex,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Validate the lead's acknowledgement of gate debts."""
    expected = {
        str(debt.get("id", "")): debt
        for debt in debts
        if isinstance(debt, dict) and str(debt.get("id", ""))
    }
    if not expected:
        return [], []
    if raw is None:
        return [], ["repair_responses: missing responses for gate debts"]
    if not isinstance(raw, list):
        return [], ["repair_responses: must be an array"]
    responses: list[dict[str, Any]] = []
    gaps: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            gaps.append(f"repair_responses[{index}]: must be an object")
            continue
        debt_id = str(item.get("debt_id", "")).strip()
        if debt_id not in expected:
            gaps.append(f"repair_responses[{index}]: unknown debt {debt_id!r}")
            continue
        if debt_id in seen:
            gaps.append(f"repair_responses[{index}]: duplicate debt {debt_id}")
            continue
        seen.add(debt_id)
        status = str(item.get("status", "")).strip()
        if status not in {"resolved", "unresolved", "not_applicable"}:
            gaps.append(f"repair_responses[{index}]: invalid status {status!r}")
            continue
        reason = str(item.get("reason", "")).strip()
        if not reason:
            gaps.append(f"repair_responses[{index}]: reason is required")
            continue
        evidence, evidence_gaps = evidence_index.hydrate(
            item.get("evidence"), f"repair_responses[{index}].evidence"
        )
        gaps.extend(evidence_gaps)
        responses.append(
            {
                "debt_id": debt_id,
                "status": status,
                "reason": reason[:1000],
                "evidence": evidence,
            }
        )
    missing = sorted(set(expected) - seen)
    if missing:
        gaps.append("repair_responses: missing debts " + ", ".join(missing))
    return responses, gaps


def compact_trace(
    task: Mapping[str, Any],
    result: Mapping[str, Any],
    *,
    artifact_file: str,
    triage: Mapping[str, Any],
) -> dict[str, Any]:
    flows = [flow for flow in result.get("flows", []) if isinstance(flow, dict)]
    triage_units = [unit for unit in triage.get("units", []) if isinstance(unit, dict)]
    return {
        "id": str(result.get("id", "")),
        "task_id": str(task.get("id", "")),
        "kind": str(task.get("kind", "")),
        "status": str(result.get("status", "partial")),
        "summary": str(result.get("summary", "")),
        "coverage_complete": bool(result.get("coverage_complete", False)),
        "entry_ids": list(task.get("entry_ids", [])),
        "patch_ids": list(task.get("patch_ids", [])),
        "flow_count": len(flows),
        "complete_flow_count": sum(1 for flow in flows if flow.get("completeness") == "complete"),
        "partial_flow_count": sum(1 for flow in flows if flow.get("completeness") != "complete"),
        "reachable_flow_count": sum(1 for flow in flows if flow.get("reachability") == "reachable"),
        "triage_rounds": int(triage.get("rounds", 0)),
        "triaged_unit_count": len(triage_units),
        "skipped_unit_count": sum(1 for unit in triage_units if unit.get("skip")),
        "specialist_roles": _strings(result.get("specialist_roles")),
        "summary_count": len(result.get("summaries", [])),
        "summary_reuse_count": len(result.get("summary_reuse", [])),
        "repair_debt_count": int(result.get("repair_debt_count", 0)),
        "repair_resolved_count": int(result.get("repair_resolved_count", 0)),
        "repair_unresolved_count": int(result.get("repair_unresolved_count", 0)),
        "artifact_file": artifact_file,
        "gaps": _strings(result.get("gaps")),
        "error": str(result.get("error", "")),
    }


def _endpoint(
    raw: Any,
    label: str,
    evidence_index: EvidenceIndex,
) -> tuple[dict[str, Any] | None, list[str]]:
    if not isinstance(raw, dict):
        return None, []
    evidence, gaps = evidence_index.hydrate(raw.get("evidence"), f"{label}.evidence")
    summary = str(raw.get("summary", "")).strip()
    if not summary and not evidence:
        return None, gaps
    if not evidence:
        gaps.append(f"{label}: endpoint has no current-source evidence")
        return None, gaps
    return {
        "summary": summary,
        "operation": str(raw.get("operation", "")).strip(),
        "evidence": evidence,
    }, gaps


def _steps(
    raw: Any,
    label: str,
    evidence_index: EvidenceIndex,
) -> tuple[list[dict[str, Any]], list[str]]:
    if not isinstance(raw, list):
        return [], []
    result: list[dict[str, Any]] = []
    gaps: list[str] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        evidence, evidence_gaps = evidence_index.hydrate(
            item.get("evidence"), f"{label}[{index}].evidence"
        )
        gaps.extend(evidence_gaps)
        if not evidence:
            gaps.append(f"{label}[{index}]: step has no evidence")
            continue
        result.append(
            {
                "kind": _choice(item.get("kind"), {"propagation", "control", "guard", "dynamic"}, "propagation"),
                "summary": str(item.get("summary", "")).strip(),
                "evidence": evidence,
            }
        )
    return result, gaps


def _guards(
    raw: Any,
    label: str,
    evidence_index: EvidenceIndex,
) -> tuple[list[dict[str, Any]], list[str]]:
    if not isinstance(raw, list):
        return [], []
    result: list[dict[str, Any]] = []
    gaps: list[str] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        evidence, evidence_gaps = evidence_index.hydrate(
            item.get("evidence"), f"{label}[{index}].evidence"
        )
        gaps.extend(evidence_gaps)
        if not evidence:
            gaps.append(f"{label}[{index}]: guard has no evidence")
            continue
        result.append(
            {
                "summary": str(item.get("summary", "")).strip(),
                "effect": _choice(item.get("effect"), {"effective", "ineffective", "unknown"}, "unknown"),
                "evidence": evidence,
            }
        )
    return result, gaps


def _dedupe_evidence(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, int, int]] = set()
    for item in items:
        key = (str(item.get("path", "")), int(item.get("start_line", 0)), int(item.get("end_line", 0)))
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _evidence_anchors(items: Iterable[dict[str, Any]]) -> list[str]:
    return [
        f"{item.get('path', '')}:{item.get('start_line', 0)}-{item.get('end_line', 0)}"
        for item in items
    ]


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()
    return f"{prefix}-{digest[:16]}"


def _choice(value: Any, allowed: set[str], default: str) -> str:
    text = str(value or "").strip()
    return text if text in allowed else default


def _strings(value: Any) -> list[str]:
    return [item for item in value if isinstance(item, str) and item] if isinstance(value, list) else []


def _ints(value: Any) -> list[int]:
    return [
        item for item in value
        if isinstance(item, int) and not isinstance(item, bool)
    ] if isinstance(value, list) else []


def _positive_int(value: Any, label: str) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None
