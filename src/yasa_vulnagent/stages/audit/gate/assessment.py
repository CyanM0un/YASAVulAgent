"""Deterministic audit closure assessment for the gate node."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from ..categories import load_category_manifest
from ..gaps import normalize_gaps
from ..verify.inputs import VerifyInputs
from ..verify.result import candidate_key


def assess(inputs: VerifyInputs, framework: Mapping[str, Any]) -> dict[str, Any]:
    """Return gate debt, routing, and status from the persisted audit records."""
    debts: list[dict[str, Any]] = []
    reopened: list[str] = []
    accepted_blocked = 0
    tasks = [dict(item) for item in inputs.tasks if isinstance(item, dict)]
    category_checks = _records(inputs.audit.get("category_checks"))
    mechanism_checks = _records(inputs.audit.get("mechanism_checks"))
    traces = _records(inputs.audit.get("traces"))
    trace_by_task = {
        str(trace.get("task_id", "")): trace
        for trace in traces
        if str(trace.get("task_id", ""))
    }
    findings = [dict(item) for item in inputs.findings if isinstance(item, dict)]
    reviews = [dict(item) for item in inputs.reviews if isinstance(item, dict)]
    patches = {
        str(patch.get("id", "")): patch
        for patch in inputs.patches
        if isinstance(patch, dict) and str(patch.get("id", ""))
    }

    entry_categories: set[str] = set()
    patch_checks: set[str] = set()
    try:
        manifest = load_category_manifest()
        entry_categories = {category.id for category in manifest.for_kind("entry")}
        patch_checks = {check.kind for check in manifest.patch_checks}
    except Exception as exc:
        debts.append(
            _debt("artifact", "category-manifest", f"category manifest is unavailable: {exc}")
        )

    _check_input_coverage(inputs, tasks, debts)
    for task in tasks:
        _check_task(
            task,
            category_checks,
            mechanism_checks,
            trace_by_task,
            inputs,
            entry_categories,
            patch_checks,
            patches,
            debts,
            reopened,
        )
        if str(task.get("status", "")) == "blocked" and _accepted_blocked(task, patches):
            accepted_blocked += 1

    _check_finding_coverage(inputs, findings, reviews, debts)
    _check_business(inputs, tasks, framework, debts)
    for message in inputs.gaps:
        debts.append(
            _debt(
                "artifact",
                message,
                message,
                paths=_paths(inputs.scope.get("files")),
            )
        )
    audit_gaps = [
        gap
        for gap in normalize_gaps(inputs.audit.get("gaps"))
        if gap["source"] != "gate"
    ]
    for gap in audit_gaps:
        debts.append(
            _debt(
                "gap",
                gap["id"],
                gap["reason"],
                action="none",
                paths=gap.get("paths", []),
            )
        )

    counts = _finding_counts(findings)
    blocking = [debt for debt in debts if debt["blocking"]]
    action = _action(blocking)
    status = "complete" if not blocking else "partial"
    fingerprint = _fingerprint(blocking)
    return {
        "status": status,
        "mode": inputs.mode,
        "source_revision": inputs.source_revision,
        "debt_count": len(debts),
        "blocking_count": len(blocking),
        "task_debt_count": _count_kind(debts, "task"),
        "check_debt_count": _count_kind(debts, "check"),
        "trace_debt_count": _count_kind(debts, "trace"),
        "finding_debt_count": _count_kind(debts, "finding"),
        "review_debt_count": _count_kind(debts, "review"),
        "business_debt_count": _count_kind(debts, "business"),
        "blocked_count": sum(
            1 for task in tasks if str(task.get("status", "")) == "blocked"
        ),
        "accepted_blocked_count": accepted_blocked,
        "gap_count": len(audit_gaps),
        "candidate_count": counts["candidate"],
        "confirmed_count": counts["confirmed"],
        "rejected_count": counts["rejected"],
        "needs_validation_count": counts["needs_validation"],
        "validation_pending": _validation_pending(findings),
        "debts": debts,
        "action": action,
        "stop_reason": (
            "gate_complete"
            if status == "complete"
            else ("gate_pending" if action != "finalize" else "gate_partial")
        ),
        "fingerprint": fingerprint,
        "reopened": reopened,
    }


def _check_input_coverage(
    inputs: VerifyInputs,
    tasks: list[dict[str, Any]],
    debts: list[dict[str, Any]],
) -> None:
    assigned_entries = {
        str(entry_id)
        for task in tasks
        for entry_id in _strings(task.get("entry_ids"))
    }
    if inputs.mode in {"entries", "combined"}:
        for entry in inputs.entries:
            entry_id = str(entry.get("id", ""))
            if entry_id and entry_id not in assigned_entries:
                debts.append(
                    _debt(
                        "input",
                        entry_id,
                        f"entry {entry_id} has no task",
                        paths=_paths(entry.get("paths")),
                    )
                )
    assigned_patches = {
        str(patch_id)
        for task in tasks
        for patch_id in _strings(task.get("patch_ids"))
    }
    if inputs.mode in {"patches", "combined"}:
        for patch in inputs.patches:
            patch_id = str(patch.get("id", ""))
            if patch_id and patch_id not in assigned_patches:
                debts.append(
                    _debt(
                        "input",
                        patch_id,
                        f"patch {patch_id} has no task",
                        paths=_paths(patch.get("changed_paths")),
                    )
                )


def _check_task(
    task: dict[str, Any],
    category_checks: list[dict[str, Any]],
    mechanism_checks: list[dict[str, Any]],
    trace_by_task: Mapping[str, dict[str, Any]],
    inputs: VerifyInputs,
    entry_categories: set[str],
    patch_checks: set[str],
    patches: Mapping[str, dict[str, Any]],
    debts: list[dict[str, Any]],
    reopened: list[str],
) -> None:
    task_id = str(task.get("id", ""))
    if not task_id:
        debts.append(_debt("task", "", "task has no id"))
        return
    status = str(task.get("status", ""))
    kind = str(task.get("kind", "entry"))
    if status == "blocked":
        if not _accepted_blocked(task, patches):
            debts.append(
                _debt(
                    "blocked",
                    task_id,
                    f"task {task_id} is blocked and cannot be reopened automatically",
                    paths=_paths(task.get("paths")),
                )
            )
        return
    if status != "complete":
        debts.append(
            _debt(
                "task",
                task_id,
                f"task {task_id} is {status or 'unknown'}",
                action="trace" if _runnable(task) else "none",
                paths=_paths(task.get("paths")),
            )
        )
        return

    missing = _missing_obligations(task, category_checks, mechanism_checks, entry_categories, patch_checks)
    if missing:
        debts.append(
            _debt(
                "check",
                task_id,
                f"task {task_id} has incomplete obligations: {', '.join(missing)}",
                action="trace",
                paths=_paths(task.get("paths")),
            )
        )
        _reopen(task_id, reopened)
        return

    if kind == "patch":
        missing_units = _missing_repair_units(task, patches)
        if missing_units:
            debts.append(
                _debt(
                    "task",
                    task_id,
                    f"task {task_id} is missing repair-unit associations: {', '.join(missing_units)}",
                    action="trace",
                    paths=_paths(task.get("paths")),
                )
            )
            _reopen(task_id, reopened)
            return

    trace = trace_by_task.get(task_id)
    if trace is None:
        debts.append(
            _debt(
                "trace",
                task_id,
                f"task {task_id} has no trace record",
                action="trace",
                paths=_paths(task.get("paths")),
            )
        )
        _reopen(task_id, reopened)
        return
    if str(trace.get("status", "")) != "complete" or not bool(trace.get("coverage_complete")):
        debts.append(
            _debt(
                "trace",
                task_id,
                f"task {task_id} trace is not coverage-complete",
                action="trace",
                paths=_paths(task.get("paths")),
            )
        )
        _reopen(task_id, reopened)
        return
    trace_id = str(trace.get("id", ""))
    if trace_id and trace_id not in inputs.trace_artifacts:
        debts.append(
            _debt(
                "trace",
                task_id,
                f"task {task_id} trace artifact is unavailable",
                action="trace",
                paths=_paths(task.get("paths")),
            )
        )
        _reopen(task_id, reopened)


def _missing_obligations(
    task: Mapping[str, Any],
    category_checks: list[dict[str, Any]],
    mechanism_checks: list[dict[str, Any]],
    entry_categories: set[str],
    patch_checks: set[str],
) -> list[str]:
    task_id = str(task.get("id", ""))
    kind = str(task.get("kind", "entry"))
    missing: list[str] = []
    if kind == "entry":
        categories = {
            str(check.get("category", ""))
            for check in category_checks
            if str(check.get("task_id", "")) == task_id
        }
        for category in sorted(entry_categories - categories):
            missing.append(f"category:{category}")
        for check in category_checks:
            if str(check.get("task_id", "")) != task_id:
                continue
            if str(check.get("status", "")) != "checked":
                missing.append(f"category:{check.get('category', '')}:status")
    if kind == "patch":
        kinds = {
            str(check.get("kind", ""))
            for check in mechanism_checks
            if str(check.get("task_id", "")) == task_id
        }
        for check_kind in sorted(patch_checks - kinds):
            missing.append(f"mechanism:{check_kind}")
        for check in mechanism_checks:
            if str(check.get("task_id", "")) != task_id:
                continue
            if str(check.get("status", "")) != "checked":
                missing.append(f"mechanism:{check.get('kind', '')}:status")
            if str(check.get("outcome", "")) not in {"found", "not_found", "not_applicable"}:
                missing.append(f"mechanism:{check.get('kind', '')}:outcome")
    return missing


def _missing_repair_units(
    task: Mapping[str, Any],
    patches: Mapping[str, dict[str, Any]],
) -> list[str]:
    assigned = {
        (str(ref.get("patch_id", "")), str(ref.get("unit_id", "")))
        for ref in task.get("repair_unit_refs", [])
        if isinstance(ref, dict)
    }
    missing: list[str] = []
    for patch_id in _strings(task.get("patch_ids")):
        patch = patches.get(patch_id, {})
        for unit_id in _strings(patch.get("repair_unit_ids")):
            if (patch_id, unit_id) not in assigned:
                missing.append(f"{patch_id}/{unit_id}")
    return missing


def _check_finding_coverage(
    inputs: VerifyInputs,
    findings: list[dict[str, Any]],
    reviews: list[dict[str, Any]],
    debts: list[dict[str, Any]],
) -> None:
    expected: dict[str, str] = {}
    for trace in _records(inputs.audit.get("traces")):
        trace_id = str(trace.get("id", ""))
        full = inputs.trace_artifacts.get(trace_id)
        if full is None:
            continue
        for flow in _records(full.get("flows")):
            try:
                key = candidate_key(flow)
            except Exception:
                continue
            expected[key] = str(trace.get("task_id", ""))
    finding_keys = {
        str(finding.get("candidate_key", ""))
        for finding in findings
        if str(finding.get("candidate_key", ""))
    }
    for key, task_id in sorted(expected.items()):
        if key not in finding_keys:
            debts.append(
                _debt(
                    "finding",
                    key,
                    f"trace flow for task {task_id} has no finding",
                    action="verify",
                )
            )

    complete_reviews: dict[str, set[str]] = {}
    for review in reviews:
        if str(review.get("type", "finding")) != "finding":
            continue
        if str(review.get("status", "")) != "complete":
            continue
        target = str(review.get("target_id", ""))
        complete_reviews.setdefault(target, set()).add(str(review.get("verdict", "")))
    review_debt_targets: set[str] = set()
    for finding in findings:
        finding_id = str(finding.get("id", ""))
        verdict = str(finding.get("verdict", ""))
        if verdict == "candidate":
            debts.append(
                _debt(
                    "finding",
                    finding_id,
                    f"finding {finding_id} is still a candidate",
                    action="verify",
                    paths=_finding_paths(finding),
                )
            )
        elif (
            verdict in {"confirmed", "rejected"}
            and verdict not in complete_reviews.get(finding_id, set())
        ):
            debts.append(
                _debt(
                    "review",
                    finding_id,
                    f"{verdict} finding {finding_id} has no complete review",
                    action="verify",
                    paths=_finding_paths(finding),
                )
            )
            review_debt_targets.add(finding_id)
        elif verdict not in {"confirmed", "rejected", "needs_validation"}:
            debts.append(
                _debt(
                    "artifact",
                    finding_id,
                    f"finding {finding_id} has unknown verdict {verdict!r}",
                    paths=_finding_paths(finding),
                )
            )
    candidate_ids = {
        str(finding.get("id", ""))
        for finding in findings
        if str(finding.get("verdict", "")) == "candidate"
    }
    for review in reviews:
        if str(review.get("status", "")) not in {"blocked", "deferred"}:
            continue
        target = str(review.get("target_id", ""))
        if target in candidate_ids or target in review_debt_targets or target in complete_reviews:
            continue
        if target:
            debts.append(
                _debt(
                    "review",
                    target,
                    f"review for {target} is {review.get('status', '')}",
                    action="verify",
                )
            )
            review_debt_targets.add(target)


def _check_business(
    inputs: VerifyInputs,
    tasks: list[dict[str, Any]],
    framework: Mapping[str, Any],
    debts: list[dict[str, Any]],
) -> None:
    business = inputs.business if isinstance(inputs.business, dict) else {}
    if tasks and not business:
        debts.append(
            _debt(
                "business",
                "business-logic",
                "business sidecar is missing",
                action="recon" if not framework.get("recon_done") else "none",
                paths=_paths(inputs.scope.get("files")),
            )
        )
        return
    for gap in normalize_gaps(business.get("gaps"), "business"):
        debts.append(
            _debt(
                "business",
                gap["id"],
                f"business gap: {gap['reason']}",
                paths=gap.get("paths", []),
            )
        )


def _runnable(task: Mapping[str, Any]) -> bool:
    return bool(
        _strings(task.get("entry_ids"))
        or _strings(task.get("patch_ids"))
        or _strings(task.get("paths"))
    )


def _accepted_blocked(
    task: Mapping[str, Any],
    patches: Mapping[str, dict[str, Any]],
) -> bool:
    patch_ids = _strings(task.get("patch_ids"))
    return (
        bool(patch_ids)
        and not task.get("repair_unit_refs")
        and all(
            str(patches.get(patch_id, {}).get("status", "")) == "not_applicable"
            for patch_id in patch_ids
        )
    )


def _action(blocking: list[dict[str, Any]]) -> str:
    actions = {str(debt.get("action", "none")) for debt in blocking}
    for action in ("trace", "verify", "recon"):
        if action in actions:
            return action
    return "finalize"


def _fingerprint(blocking: list[dict[str, Any]]) -> str:
    payload = sorted(
        (str(debt.get("id", "")), str(debt.get("action", ""))) for debt in blocking
    )
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()


def _validation_pending(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "finding_id": str(finding.get("id", "")),
            "title": str(finding.get("title", "")),
            "missing_facts": _strings(finding.get("missing_facts")),
        }
        for finding in findings
        if str(finding.get("verdict", "")) == "needs_validation"
    ]


def _finding_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"candidate": 0, "confirmed": 0, "rejected": 0, "needs_validation": 0}
    for finding in findings:
        verdict = str(finding.get("verdict", ""))
        if verdict in counts:
            counts[verdict] += 1
    return counts


def _finding_paths(finding: Mapping[str, Any]) -> list[str]:
    return [
        str(item.get("path"))
        for item in finding.get("evidence", [])
        if isinstance(item, dict) and str(item.get("path", ""))
    ]


def _records(value: Any) -> list[dict[str, Any]]:
    return [dict(item) for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _strings(value: Any) -> list[str]:
    return [str(item) for item in value if str(item)] if isinstance(value, list) else []


def _paths(value: Any) -> list[str]:
    return _strings(value)


def _debt(
    kind: str,
    target_id: str,
    reason: str,
    *,
    action: str = "none",
    paths: list[str] | None = None,
    blocking: bool = True,
) -> dict[str, Any]:
    paths = [str(path) for path in (paths or []) if str(path)]
    digest = hashlib.sha256(
        json.dumps([kind, target_id, reason, action, paths], ensure_ascii=False).encode("utf-8")
    ).hexdigest()[:16]
    return {
        "id": f"debt-{digest}",
        "kind": kind,
        "target_id": target_id,
        "reason": reason,
        "paths": paths,
        "blocking": blocking,
        "action": action,
    }


def _count_kind(debts: list[dict[str, Any]], kind: str) -> int:
    return sum(1 for debt in debts if debt.get("kind") == kind)


def _reopen(task_id: str, reopened: list[str]) -> None:
    if task_id and task_id not in reopened:
        reopened.append(task_id)
