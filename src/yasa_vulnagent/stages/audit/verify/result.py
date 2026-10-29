"""Validate verify model output and turn candidate flows into findings."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from ..trace.result import EvidenceIndex
from .constants import MAX_EVIDENCE_ITEMS

VERDICTS = {"candidate", "confirmed", "rejected", "needs_validation"}
DECISIONS = {"confirmed", "rejected", "needs_validation"}
SEVERITIES = {"critical", "high", "medium", "low", "info"}
CONFIDENCES = {"high", "medium", "low"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_terminal(finding: Mapping[str, Any]) -> bool:
    return str(finding.get("verdict", "")) in DECISIONS


def verdict_counts(findings: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    counts = {"candidate": 0, "confirmed": 0, "rejected": 0, "needs_validation": 0}
    for finding in findings:
        verdict = str(finding.get("verdict", ""))
        if verdict in counts:
            counts[verdict] += 1
    return counts


def normalize_evidence(
    raw: Any,
    evidence_index: EvidenceIndex,
    label: str,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Hydrate evidence and add the contract's current-source code field."""
    evidence, gaps = evidence_index.hydrate(raw, label)
    result: list[dict[str, Any]] = []
    for item in evidence[:MAX_EVIDENCE_ITEMS]:
        code = str(item.get("quote", "")).strip()
        if not code:
            gaps.append(f"{label}: evidence has no current source text")
            continue
        result.append(
            {
                "path": str(item["path"]),
                "start_line": int(item["start_line"]),
                "end_line": int(item["end_line"]),
                "code": code,
                "explanation": str(item["explanation"]).strip(),
            }
        )
    return result, gaps


def freshly_read(
    evidence: Iterable[Mapping[str, Any]],
    receipts: Iterable[Mapping[str, Any]],
) -> tuple[bool, list[str]]:
    """Check that this agent read each evidence file at a relevant range."""
    reads = [
        item
        for item in receipts
        if item.get("tool") == "read_file" and item.get("status", "ok") == "ok"
    ]
    missing: list[str] = []
    by_path: dict[str, list[Mapping[str, Any]]] = {}
    for item in evidence:
        by_path.setdefault(str(item.get("path", "")), []).append(item)
    for path, items in by_path.items():
        covered = False
        for item in items:
            start = _int(item.get("start_line"))
            end = _int(item.get("end_line"))
            for receipt in reads:
                if str(receipt.get("path", "")) != path:
                    continue
                r_start = _int(receipt.get("start_line"))
                r_end = _int(receipt.get("end_line"))
                if r_start <= start and r_end >= end:
                    covered = True
                    break
            if covered:
                break
        if not covered:
            missing.append(path)
    return not missing, missing


def candidate_key(flow: Mapping[str, Any]) -> str:
    source = flow.get("source") if isinstance(flow.get("source"), dict) else {}
    sink = flow.get("sink") if isinstance(flow.get("sink"), dict) else {}
    payload = {
        "category": str(flow.get("category", "")),
        "kind": str(flow.get("kind", "")),
        "source": _anchors(source.get("evidence")),
        "sink": _anchors(sink.get("evidence")),
        "reachability": str(flow.get("reachability", "")),
        "triggerability": str(flow.get("triggerability", "")),
        "prerequisites": sorted(_strings(flow.get("preconditions"))),
    }
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()


def finding_id(run_id: str, key: str) -> str:
    digest = hashlib.sha256(f"{run_id}\0{key}".encode("utf-8")).hexdigest()
    return "finding-" + digest[:16]


def review_id(finding: str) -> str:
    return "review-" + str(finding)


def build_candidate(
    flow: Mapping[str, Any],
    task: Mapping[str, Any],
    trace: Mapping[str, Any],
    evidence_index: EvidenceIndex,
    run_id: str,
) -> tuple[dict[str, Any] | None, list[str]]:
    evidence, gaps = normalize_evidence(
        flow.get("evidence"), evidence_index, "candidate.evidence"
    )
    if not evidence:
        gaps.append("candidate has no valid current-source evidence")
        return None, gaps
    key = candidate_key(flow)
    source = flow.get("source") if isinstance(flow.get("source"), dict) else {}
    sink = flow.get("sink") if isinstance(flow.get("sink"), dict) else {}
    category = str(flow.get("category", "")).strip()
    title = str(flow.get("summary", "")).strip()
    if not title:
        title = f"{category or 'candidate'} at {sink.get('summary', 'unknown sink')}"
    finding = {
        "id": finding_id(run_id, key),
        "task_id": str(task.get("id", "")),
        "task_ids": [str(task.get("id", ""))],
        "trace_id": str(trace.get("id", "")),
        "trace_ids": [str(trace.get("id", ""))],
        "candidate_key": key,
        "verdict": "candidate",
        "title": title,
        "category": category,
        "kind": str(flow.get("kind", "")),
        "cwe_ids": _ints(flow.get("cwe_hints")),
        "patch_ids": _strings(task.get("patch_ids")),
        "repair_unit_refs": _objects(task.get("repair_unit_refs")),
        "business_refs": dict(task.get("business_refs") or {}),
        "severity": "unknown",
        "confidence": "unknown",
        "lower_trust_principal": "",
        "entry_point": str(source.get("summary", "")).strip(),
        "protected_asset": "",
        "violated_invariant": "",
        "source_to_sink": _explanations(evidence),
        "control": {"description": "", "effective": False},
        "impact": str(flow.get("impact", "") or sink.get("summary", "")).strip(),
        "prerequisites": sorted(_strings(flow.get("preconditions"))),
        "counterevidence": [],
        "evidence": evidence,
        "missing_facts": _strings(flow.get("unknowns")),
        "limitations": [],
        "completeness": str(flow.get("completeness", "")),
        "reachability": str(flow.get("reachability", "")),
        "triggerability": str(flow.get("triggerability", "")),
        "verification": {},
        "created_at": utc_now(),
    }
    return finding, gaps


def verify_update(
    payload: Mapping[str, Any],
    finding: Mapping[str, Any],
    evidence_index: EvidenceIndex,
    receipts: Iterable[Mapping[str, Any]],
) -> tuple[dict[str, Any] | None, list[str]]:
    """Validate one verifier result. Invalid claims are downgraded, never trusted."""
    verdict = str(payload.get("verdict", "")).strip()
    if verdict not in VERDICTS:
        return None, [f"verifier returned invalid verdict: {verdict or '(empty)'}"]
    reason = str(payload.get("reason", "")).strip()
    title = str(payload.get("title", "")).strip() or str(finding.get("title", ""))
    evidence, gaps = normalize_evidence(
        payload.get("evidence"), evidence_index, "verifier.evidence"
    )
    if not evidence:
        gaps.append("verifier returned no valid current-source evidence")
        return None, gaps

    updated = dict(finding)
    updated["title"] = title
    updated["verdict"] = verdict
    updated["evidence"] = evidence
    updated["reason"] = reason
    updated["counterevidence"] = _strings(payload.get("counterevidence"))
    updated["prerequisites"] = _strings(payload.get("prerequisites"))
    updated["missing_facts"] = _strings(payload.get("missing_facts"))
    updated["limitations"] = _strings(payload.get("limitations"))
    updated["cwe_ids"] = _ints(payload.get("cwe_ids")) or list(finding.get("cwe_ids", []))
    updated["source_to_sink"] = _strings(payload.get("source_to_sink")) or list(
        finding.get("source_to_sink", [])
    )
    for key in (
        "lower_trust_principal",
        "entry_point",
        "protected_asset",
        "violated_invariant",
        "impact",
    ):
        value = str(payload.get(key, "")).strip()
        if value:
            updated[key] = value
    control = payload.get("control")
    if isinstance(control, dict):
        updated["control"] = {
            "description": str(control.get("description", "")).strip(),
            "effective": _bool(control.get("effective")),
        }
    severity = str(payload.get("severity", "")).strip().lower()
    confidence = str(payload.get("confidence", "")).strip().lower()
    updated["severity"] = severity if severity in SEVERITIES else "unknown"
    updated["confidence"] = confidence if confidence in CONFIDENCES else "unknown"

    if verdict == "candidate":
        return None, [*gaps, "verifier did not reach a decision"]
    if verdict == "needs_validation":
        if not reason or not updated["missing_facts"]:
            return None, [
                *gaps,
                "needs_validation requires a reason and exact missing_facts",
            ]
        updated["severity"] = "unknown"
        updated["confidence"] = "unknown"
    if verdict in {"confirmed", "rejected"}:
        fresh, missing = freshly_read(evidence, receipts)
        if not fresh:
            gaps.append("current-source read is missing for: " + ", ".join(missing))
            if verdict == "confirmed":
                verdict = "needs_validation"
                updated["verdict"] = verdict
                updated["severity"] = "unknown"
                updated["confidence"] = "unknown"
                updated["missing_facts"] = ["current source not read for: " + ", ".join(missing)]
            else:
                return None, gaps
    if verdict == "confirmed":
        missing_fields = _confirmed_missing(updated, reason)
        if missing_fields:
            verdict = "needs_validation"
            updated["verdict"] = verdict
            updated["severity"] = "unknown"
            updated["confidence"] = "unknown"
            updated["missing_facts"] = missing_fields
            if not reason:
                updated["reason"] = (
                    "confirmed result is missing required fields: "
                    + ", ".join(missing_fields)
                )
            gaps.append("confirmed result downgraded: " + ", ".join(missing_fields))
    if verdict == "needs_validation" and not updated["missing_facts"]:
        return None, [*gaps, "needs_validation requires missing_facts"]
    if not reason and verdict != "candidate":
        return None, [*gaps, "verifier must provide a reason"]
    current = dict(finding.get("verification") or {})
    current["primary_verdict"] = verdict
    current["primary_reason"] = reason
    updated["verification"] = current
    return updated, gaps


def build_review(
    payload: Mapping[str, Any],
    finding: Mapping[str, Any],
    evidence_index: EvidenceIndex,
    receipts: Iterable[Mapping[str, Any]],
    *,
    review_id_value: str,
    mode: str,
    model: str,
) -> tuple[dict[str, Any], list[str]]:
    """Validate an independent review or second-verifier adjudication."""
    verdict = str(payload.get("verdict", "")).strip()
    reason = str(payload.get("reason", "")).strip()
    evidence, gaps = normalize_evidence(
        payload.get("evidence"), evidence_index, "review.evidence"
    )
    review = {
        "id": review_id_value,
        "type": "finding",
        "target_id": str(finding.get("id", "")),
        "status": "blocked",
        "verdict": verdict if verdict in DECISIONS else "",
        "mode": mode,
        "reason": reason,
        "evidence": evidence,
        "counterevidence": _strings(payload.get("counterevidence")),
        "missing_facts": _strings(payload.get("missing_facts")),
        "limitations": _strings(payload.get("limitations")),
        "second_verifier_used": mode == "second_verifier",
        "model": model,
        "created_at": utc_now(),
    }
    if verdict not in DECISIONS:
        gaps.append("review returned invalid verdict")
        return review, gaps
    if not reason:
        gaps.append("review must provide a reason")
        return review, gaps
    if not evidence:
        gaps.append("review returned no valid current-source evidence")
        return review, gaps
    fresh, missing = freshly_read(evidence, receipts)
    if not fresh:
        gaps.append("review did not read current source for: " + ", ".join(missing))
        return review, gaps
    if verdict == "needs_validation" and not review["missing_facts"]:
        gaps.append("review needs_validation requires missing_facts")
        return review, gaps
    review["status"] = "complete"
    return review, gaps


def _confirmed_missing(finding: Mapping[str, Any], reason: str) -> list[str]:
    required = {
        "reason": reason,
        "lower_trust_principal": finding.get("lower_trust_principal"),
        "entry_point": finding.get("entry_point"),
        "protected_asset": finding.get("protected_asset"),
        "violated_invariant": finding.get("violated_invariant"),
        "impact": finding.get("impact"),
    }
    missing = [key for key, value in required.items() if not str(value or "").strip()]
    if not finding.get("source_to_sink"):
        missing.append("source_to_sink")
    control = finding.get("control") if isinstance(finding.get("control"), dict) else {}
    if not str(control.get("description", "")).strip():
        missing.append("control.description")
    if control.get("effective"):
        missing.append("control.effective")
    if str(finding.get("severity", "unknown")) not in SEVERITIES:
        missing.append("severity")
    if str(finding.get("confidence", "unknown")) not in CONFIDENCES:
        missing.append("confidence")
    return missing


def compact_finding(finding: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: finding.get(key)
        for key in (
            "id",
            "task_id",
            "task_ids",
            "trace_id",
            "candidate_key",
            "verdict",
            "reason",
            "review_id",
            "title",
            "category",
            "kind",
            "cwe_ids",
            "patch_ids",
            "repair_unit_refs",
            "business_refs",
            "severity",
            "confidence",
            "lower_trust_principal",
            "entry_point",
            "protected_asset",
            "violated_invariant",
            "source_to_sink",
            "control",
            "impact",
            "prerequisites",
            "counterevidence",
            "missing_facts",
            "limitations",
            "completeness",
            "reachability",
            "triggerability",
            "verification",
        )
    }


def _anchors(raw: Any) -> list[str]:
    anchors = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                anchors.append(
                    f"{item.get('path', '')}:{item.get('start_line', '')}-{item.get('end_line', '')}"
                )
    return sorted(dict.fromkeys(anchors))


def _explanations(evidence: list[dict[str, Any]]) -> list[str]:
    return [
        str(item.get("explanation", "")).strip()
        for item in evidence
        if str(item.get("explanation", "")).strip()
    ]


def _strings(value: Any) -> list[str]:
    return (
        [item for item in value if isinstance(item, str) and item.strip()]
        if isinstance(value, list)
        else []
    )


def _objects(value: Any) -> list[dict[str, Any]]:
    return [dict(item) for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _ints(value: Any) -> list[int]:
    result: list[int] = []
    if isinstance(value, list):
        for item in value:
            try:
                result.append(int(item))
            except (TypeError, ValueError):
                continue
    return list(dict.fromkeys(result))


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "yes", "1"}


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
