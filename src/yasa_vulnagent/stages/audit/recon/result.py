"""Validate recon model output and hydrate current-source evidence."""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Iterable, Mapping

from ..prepare.inventory import safe_relative
from ..trace.result import EvidenceIndex
from .constants import (
    MAX_CONSTRAINTS,
    MAX_EVIDENCE,
    MAX_INVESTIGATIONS,
    MAX_LOGIC_TASKS,
    MAX_OPERATIONS,
)
from .model import ReconModelError

LOGGER = logging.getLogger(__name__)

SOURCE_KINDS = {
    "user_statement",
    "documentation",
    "test",
    "permission_config",
    "database_constraint",
    "history",
    "code",
    "inference",
}
APPLICABILITY = {"applicable", "not_applicable", "unknown"}
OUTCOMES = {"candidate", "safe", "unknown", "not_applicable", "deferred"}
PRIORITIES = {"high", "normal", "low"}
_REF_KEYS = ("constraint_ids", "operation_ids", "investigation_ids")


def validate_payload(
    payload: Any,
    *,
    tasks: list[dict[str, Any]],
    entries: list[dict[str, Any]],
    patches: list[dict[str, Any]],
    scope_files: Iterable[str],
    evidence_index: EvidenceIndex,
    traces: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Validate one recon response as a whole; any invalid record fails recon."""
    if not isinstance(payload, dict):
        raise ReconModelError("recon output must be an object")
    task_by_id = {
        str(task.get("id", "")): task
        for task in tasks
        if isinstance(task, dict) and task.get("id")
    }
    entry_ids = {str(item.get("id", "")) for item in entries if item.get("id")}
    patch_ids = {str(item.get("id", "")) for item in patches if item.get("id")}
    scope = {str(path) for path in scope_files if str(path)}

    degraded: list[str] = []
    constraints = _constraints(
        payload.get("constraints"), evidence_index, degraded=degraded
    )
    constraint_ids = {item["id"] for item in constraints}
    operations = _operations(
        payload.get("operations"),
        evidence_index=evidence_index,
        entry_ids=entry_ids,
        patch_ids=patch_ids,
        degraded=degraded,
    )
    operation_ids = {item["id"] for item in operations}
    investigations = _investigations(
        payload.get("investigations"),
        evidence_index=evidence_index,
        task_by_id=task_by_id,
        entry_ids=entry_ids,
        patch_ids=patch_ids,
        constraint_ids=constraint_ids,
        operation_ids=operation_ids,
        degraded=degraded,
    )
    investigation_ids = {item["id"] for item in investigations}
    evidence_by_ref = _evidence_by_ref(constraints, operations, investigations)
    logic_tasks = _logic_tasks(
        payload.get("logic_tasks"),
        evidence_index=evidence_index,
        task_by_id=task_by_id,
        scope=scope,
        constraint_ids=constraint_ids,
        operation_ids=operation_ids,
        investigation_ids=investigation_ids,
        evidence_by_ref=evidence_by_ref,
        existing_tasks=tasks,
        traces=traces or [],
        degraded=degraded,
    )
    return {
        "constraints": constraints,
        "operations": operations,
        "investigations": investigations,
        "logic_tasks": logic_tasks,
        "gaps": [*_strings(payload.get("gaps"), "gaps"), *degraded],
        "warnings": _strings(payload.get("warnings"), "warnings"),
        "limitations": _strings(payload.get("limitations"), "limitations"),
    }


def _constraints(
    raw: Any, evidence_index: EvidenceIndex, *, degraded: list[str] | None = None
) -> list[dict[str, Any]]:
    values = _array(raw, "constraints", MAX_CONSTRAINTS)
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(values):
        label = f"constraints[{index}]"
        item = _object(item, label)
        record_id = _text(item.get("id"), f"{label}.id")
        _unique(record_id, seen, label)
        source_kind = _text(item.get("source_kind"), f"{label}.source_kind")
        if source_kind not in SOURCE_KINDS:
            raise ReconModelError(f"{label}: unknown source_kind {source_kind}")
        applicability = _text(item.get("applicability"), f"{label}.applicability")
        if applicability not in APPLICABILITY:
            raise ReconModelError(f"{label}: unknown applicability {applicability}")
        description = _text(item.get("description"), f"{label}.description")
        supporting = _evidence(
            item.get("supporting_evidence"),
            f"{label}.supporting_evidence",
            evidence_index,
            gaps=degraded,
        )
        counter = _evidence(
            item.get("counterevidence"),
            f"{label}.counterevidence",
            evidence_index,
            gaps=degraded,
        )
        result.append(
            {
                "id": record_id,
                "description": description,
                "source_kind": source_kind,
                "applicability": applicability,
                "reason": _optional_text(item.get("reason")),
                "supporting_evidence": supporting,
                "counterevidence": counter,
                "historical_references": _historical(item.get("historical_references"), f"{label}.historical_references"),
                "unknowns": _strings(item.get("unknowns"), f"{label}.unknowns"),
            }
        )
    return result


def _operations(
    raw: Any,
    *,
    evidence_index: EvidenceIndex,
    entry_ids: set[str],
    patch_ids: set[str],
    degraded: list[str],
) -> list[dict[str, Any]]:
    values = _array(raw, "operations", MAX_OPERATIONS)
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(values):
        label = f"operations[{index}]"
        try:
            record = _operation_record(
                item,
                label,
                evidence_index=evidence_index,
                entry_ids=entry_ids,
                patch_ids=patch_ids,
                seen=seen,
            )
        except ReconModelError as error:
            degraded.append(f"dropped {error}")
            continue
        result.append(record)
    return result


def _operation_record(
    item: Any,
    label: str,
    *,
    evidence_index: EvidenceIndex,
    entry_ids: set[str],
    patch_ids: set[str],
    seen: set[str],
) -> dict[str, Any]:
    item = _object(item, label)
    record_id = _text(item.get("id"), f"{label}.id")
    _unique(record_id, seen, label)
    name = _text(item.get("name"), f"{label}.name")
    locations = _evidence(item.get("locations"), f"{label}.locations", evidence_index)
    evidence = _evidence(item.get("evidence"), f"{label}.evidence", evidence_index)
    if not locations:
        locations = evidence
    if not evidence:
        evidence = locations
    if not evidence:
        raise ReconModelError(f"{label}: operation needs current-source evidence")
    selected_entry_ids = _known_ids(item.get("entry_ids"), entry_ids, f"{label}.entry_ids")
    selected_patch_ids = _known_ids(item.get("patch_ids"), patch_ids, f"{label}.patch_ids")
    return {
        "id": record_id,
        "name": name,
        "entry_ids": selected_entry_ids,
        "patch_ids": selected_patch_ids,
        "actor": _json_value(item.get("actor")),
        "resource": _json_value(item.get("resource")),
        "guards": _strings(item.get("guards"), f"{label}.guards"),
        "state_reads": _strings(item.get("state_reads"), f"{label}.state_reads"),
        "state_writes": _strings(item.get("state_writes"), f"{label}.state_writes"),
        "effects": _strings(item.get("effects"), f"{label}.effects"),
        "calls": _strings(item.get("calls"), f"{label}.calls"),
        "external_boundaries": _strings(
            item.get("external_boundaries"), f"{label}.external_boundaries"
        ),
        "transaction": _json_value(item.get("transaction")),
        "locations": locations,
        "evidence": evidence,
        "historical_references": _historical(
            item.get("historical_references"), f"{label}.historical_references"
        ),
        "unknowns": _strings(item.get("unknowns"), f"{label}.unknowns"),
    }


def _investigations(
    raw: Any,
    *,
    evidence_index: EvidenceIndex,
    task_by_id: Mapping[str, dict[str, Any]],
    entry_ids: set[str],
    patch_ids: set[str],
    constraint_ids: set[str],
    operation_ids: set[str],
    degraded: list[str],
) -> list[dict[str, Any]]:
    values = _array(raw, "investigations", MAX_INVESTIGATIONS)
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(values):
        label = f"investigations[{index}]"
        try:
            record = _investigation_record(
                item,
                label,
                evidence_index=evidence_index,
                task_by_id=task_by_id,
                entry_ids=entry_ids,
                patch_ids=patch_ids,
                constraint_ids=constraint_ids,
                operation_ids=operation_ids,
                seen=seen,
            )
        except ReconModelError as error:
            degraded.append(f"dropped {error}")
            continue
        result.append(record)
    return result


def _investigation_record(
    item: Any,
    label: str,
    *,
    evidence_index: EvidenceIndex,
    task_by_id: Mapping[str, dict[str, Any]],
    entry_ids: set[str],
    patch_ids: set[str],
    constraint_ids: set[str],
    operation_ids: set[str],
    seen: set[str],
) -> dict[str, Any]:
    item = _object(item, label)
    record_id = _text(item.get("id"), f"{label}.id")
    _unique(record_id, seen, label)
    task_id = _text(item.get("task_id"), f"{label}.task_id")
    if task_id not in task_by_id:
        raise ReconModelError(f"{label}: unknown task_id {task_id}")
    question = _text(item.get("question"), f"{label}.question")
    outcome = _text(item.get("outcome"), f"{label}.outcome")
    if outcome not in OUTCOMES:
        raise ReconModelError(f"{label}: unknown outcome {outcome}")
    selected_entry_ids = _known_ids(item.get("entry_ids"), entry_ids, f"{label}.entry_ids")
    selected_patch_ids = _known_ids(item.get("patch_ids"), patch_ids, f"{label}.patch_ids")
    refs = _known_refs(
        item,
        constraint_ids=constraint_ids,
        operation_ids=operation_ids,
        investigation_ids=set(),
        label=label,
    )
    evidence = _evidence(item.get("evidence"), f"{label}.evidence", evidence_index)
    if not evidence:
        raise ReconModelError(f"{label}: investigation needs current-source evidence")
    return {
        "id": record_id,
        "task_id": task_id,
        "question": question,
        "constraint_ids": refs["constraint_ids"],
        "operation_ids": refs["operation_ids"],
        "entry_ids": selected_entry_ids,
        "patch_ids": selected_patch_ids,
        "repair_unit_refs": _repair_refs(
            item.get("repair_unit_refs"), f"{label}.repair_unit_refs"
        ),
        "steps": _list_items(item.get("steps"), f"{label}.steps"),
        "resource_bindings": _list_items(
            item.get("resource_bindings"), f"{label}.resource_bindings"
        ),
        "path_conditions": _strings(
            item.get("path_conditions"), f"{label}.path_conditions"
        ),
        "outcome": outcome,
        "reason": _optional_text(item.get("reason")),
        "unknowns": _strings(item.get("unknowns"), f"{label}.unknowns"),
        "gaps": _strings(item.get("gaps"), f"{label}.gaps"),
        "evidence": evidence,
        "historical_references": _historical(
            item.get("historical_references"), f"{label}.historical_references"
        ),
    }


def _logic_tasks(
    raw: Any,
    *,
    evidence_index: EvidenceIndex,
    task_by_id: Mapping[str, dict[str, Any]],
    scope: set[str],
    constraint_ids: set[str],
    operation_ids: set[str],
    investigation_ids: set[str],
    evidence_by_ref: Mapping[str, list[dict[str, Any]]],
    existing_tasks: list[dict[str, Any]],
    traces: list[dict[str, Any]],
    degraded: list[str],
) -> list[dict[str, Any]]:
    values = _array(raw, "logic_tasks", MAX_LOGIC_TASKS)
    existing_questions = {
        _question_key(str(task.get("question", "")))
        for task in existing_tasks
        if isinstance(task, dict) and task.get("question")
    }
    existing_logic = {
        str(task.get("id", "")): task
        for task in existing_tasks
        if isinstance(task, dict) and task.get("kind") == "logic"
    }
    result: list[dict[str, Any]] = []
    seen_questions: set[str] = set()
    seen_ids: set[str] = set()
    for index, item in enumerate(values):
        label = f"logic_tasks[{index}]"
        try:
            record = _logic_task_record(
                item,
                label,
                evidence_index=evidence_index,
                task_by_id=task_by_id,
                scope=scope,
                constraint_ids=constraint_ids,
                operation_ids=operation_ids,
                investigation_ids=investigation_ids,
                evidence_by_ref=evidence_by_ref,
                existing_questions=existing_questions,
                existing_logic=existing_logic,
                traces=traces,
                seen_questions=seen_questions,
                seen_ids=seen_ids,
            )
        except ReconModelError as error:
            degraded.append(f"dropped {error}")
            continue
        if record is not None:
            result.append(record)
    return result


def _logic_task_record(
    item: Any,
    label: str,
    *,
    evidence_index: EvidenceIndex,
    task_by_id: Mapping[str, dict[str, Any]],
    scope: set[str],
    constraint_ids: set[str],
    operation_ids: set[str],
    investigation_ids: set[str],
    evidence_by_ref: Mapping[str, list[dict[str, Any]]],
    existing_questions: set[str],
    existing_logic: Mapping[str, dict[str, Any]],
    traces: list[dict[str, Any]],
    seen_questions: set[str],
    seen_ids: set[str],
) -> dict[str, Any] | None:
    item = _object(item, label)
    origin_ids = _strings(item.get("origin_task_ids"), f"{label}.origin_task_ids")
    if not origin_ids:
        raise ReconModelError(f"{label}: origin_task_ids must not be empty")
    origins: list[dict[str, Any]] = []
    for origin_id in origin_ids:
        origin = task_by_id.get(origin_id)
        if origin is None:
            raise ReconModelError(f"{label}: unknown origin task {origin_id}")
        origins.append(origin)
    question = _text(item.get("question"), f"{label}.question")
    question_key = _question_key(question)
    if (
        question_key in existing_questions
        or question_key in seen_questions
        or _answered_by_trace(question_key, origin_ids, traces)
    ):
        return None
    raw_refs = item.get("business_refs")
    if raw_refs is not None and not isinstance(raw_refs, dict):
        raise ReconModelError(f"{label}: business_refs must be an object")
    refs = _known_refs(
        raw_refs if isinstance(raw_refs, dict) else item,
        constraint_ids=constraint_ids,
        operation_ids=operation_ids,
        investigation_ids=investigation_ids,
        label=label,
    )
    if not any(refs.values()):
        raise ReconModelError(f"{label}: business_refs must not be empty")
    paths = _paths(item.get("paths"), scope, f"{label}.paths")
    if not paths:
        paths = [
            str(path)
            for origin in origins
            for path in origin.get("paths", [])
            if str(path) in scope
        ]
    paths = list(dict.fromkeys(paths))
    if not paths:
        raise ReconModelError(f"{label}: no in-scope paths for the follow-up task")
    evidence = _evidence(item.get("evidence"), f"{label}.evidence", evidence_index)
    if not evidence:
        evidence = _ref_evidence(refs, evidence_by_ref)
    task_id = _logic_id(origin_ids, question, refs, paths)
    if task_id in seen_ids:
        return None
    seen_ids.add(task_id)
    seen_questions.add(question_key)
    if task_id in existing_logic:
        # A prior run owns this task's progress; do not reset it.
        return None
    entry_ids = _union(origins, "entry_ids")
    patch_ids = _union(origins, "patch_ids")
    return {
        "id": task_id,
        "kind": "logic",
        "status": "planned",
        "entry_ids": entry_ids,
        "patch_ids": patch_ids,
        "origin_task_ids": list(dict.fromkeys(origin_ids)),
        "business_refs": refs,
        "repair_unit_refs": [],
        "paths": paths,
        "priority": _priority(item.get("priority")),
        "question": question,
        "evidence": evidence[:MAX_EVIDENCE],
    }


def _evidence(
    raw: Any,
    label: str,
    evidence_index: EvidenceIndex,
    *,
    gaps: list[str] | None = None,
) -> list[dict[str, Any]]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ReconModelError(f"{label}: evidence must be an array")
    if len(raw) > MAX_EVIDENCE:
        raise ReconModelError(f"{label}: evidence exceeds {MAX_EVIDENCE} items")
    items, rejected = evidence_index.hydrate(raw, label)
    if rejected:
        if gaps is None:
            raise ReconModelError(f"{label}: {rejected[0]}")
        # Unusable items are dropped and reported; one bad citation must not
        # discard the rest of the payload.
        gaps.extend(rejected)
    return [
        {
            "path": item["path"],
            "start_line": item["start_line"],
            "end_line": item["end_line"],
            "code": item["quote"],
            "explanation": item["explanation"],
        }
        for item in items
    ]


def _historical(raw: Any, label: str) -> list[dict[str, Any]]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ReconModelError(f"{label}: historical_references must be an array")
    result: list[dict[str, Any]] = []
    for index, item in enumerate(raw[:20]):
        item = _object(item, f"{label}[{index}]")
        source = str(item.get("source", "") or "").strip()
        if not source:
            LOGGER.warning("%s[%d]: dropping historical reference without a source", label, index)
            continue
        path = str(item.get("path", "") or "").strip()
        if path and safe_relative(path) is None:
            raise ReconModelError(f"{label}[{index}]: history path is unsafe")
        result.append(
            {
                "source": source,
                "commit": str(item.get("commit", "") or ""),
                "path": path,
                "side": str(item.get("side", "") or ""),
                "text": str(item.get("text", "") or "")[:2000],
            }
        )
    return result


def _known_refs(
    item: Mapping[str, Any],
    *,
    constraint_ids: set[str],
    operation_ids: set[str],
    investigation_ids: set[str],
    label: str,
) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for key, known in (
        ("constraint_ids", constraint_ids),
        ("operation_ids", operation_ids),
        ("investigation_ids", investigation_ids),
    ):
        values = _strings(item.get(key), f"{label}.{key}")
        missing = sorted(set(values) - known)
        if missing:
            raise ReconModelError(f"{label}: unknown {key}: {missing}")
        result[key] = list(dict.fromkeys(values))
    return result


def _evidence_by_ref(
    constraints: list[dict[str, Any]],
    operations: list[dict[str, Any]],
    investigations: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for item in constraints:
        result[item["id"]] = [
            *item.get("supporting_evidence", []),
            *item.get("counterevidence", []),
        ]
    for item in operations:
        result[item["id"]] = list(item.get("evidence", []))
    for item in investigations:
        result[item["id"]] = list(item.get("evidence", []))
    return result


def _ref_evidence(
    refs: Mapping[str, list[str]],
    evidence_by_ref: Mapping[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for key in _REF_KEYS:
        for record_id in refs.get(key, []):
            result.extend(evidence_by_ref.get(record_id, []))
    return list({(item["path"], item["start_line"], item["end_line"]): item for item in result}.values())


def _paths(raw: Any, scope: set[str], label: str) -> list[str]:
    values = _strings(raw, label)
    outside = sorted(set(values) - scope)
    if outside:
        raise ReconModelError(f"{label}: paths outside audit scope: {outside}")
    return list(dict.fromkeys(values))


def _known_ids(raw: Any, known: set[str], label: str) -> list[str]:
    values = _strings(raw, label)
    missing = sorted(set(values) - known)
    if missing:
        raise ReconModelError(f"{label}: unknown ids: {missing}")
    return list(dict.fromkeys(values))


def _repair_refs(raw: Any, label: str) -> list[dict[str, str]]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ReconModelError(f"{label}: repair_unit_refs must be an array")
    result: list[dict[str, str]] = []
    for index, item in enumerate(raw[:20]):
        item = _object(item, f"{label}[{index}]")
        result.append(
            {
                "patch_id": _text(item.get("patch_id"), f"{label}[{index}].patch_id"),
                "unit_id": _text(item.get("unit_id"), f"{label}[{index}].unit_id"),
            }
        )
    return result


def _array(raw: Any, label: str, limit: int) -> list[Any]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ReconModelError(f"{label} must be an array")
    if len(raw) > limit:
        raise ReconModelError(f"{label} exceeds {limit} items")
    return raw


def _object(raw: Any, label: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ReconModelError(f"{label} must be an object")
    return raw


def _objects(raw: Any, label: str) -> list[dict[str, Any]]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ReconModelError(f"{label} must be an array")
    return [_object(item, f"{label}[{index}]") for index, item in enumerate(raw[:30])]


def _list_items(raw: Any, label: str) -> list[Any]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ReconModelError(f"{label} must be an array")
    result: list[Any] = []
    for index, item in enumerate(raw[:30]):
        if not isinstance(item, (str, dict)):
            raise ReconModelError(f"{label}[{index}] must be a string or object")
        result.append(dict(item) if isinstance(item, dict) else item)
    return result


def _strings(raw: Any, label: str) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise ReconModelError(f"{label} must be an array of strings")
    return [item for item in raw if item]


def _text(raw: Any, label: str) -> str:
    value = str(raw or "").strip()
    if not value:
        raise ReconModelError(f"{label} must be a non-empty string")
    return value


def _optional_text(raw: Any) -> str:
    return str(raw or "").strip()


def _unique(value: str, seen: set[str], label: str) -> None:
    if value in seen:
        raise ReconModelError(f"{label}: duplicate id {value}")
    seen.add(value)


def _priority(raw: Any) -> str:
    value = str(raw or "normal").strip()
    return value if value in PRIORITIES else "normal"


def _question_key(value: str) -> str:
    return " ".join(value.lower().split())


def _answered_by_trace(
    question_key: str,
    origin_ids: list[str],
    traces: list[dict[str, Any]],
) -> bool:
    for trace in traces:
        if not isinstance(trace, dict):
            continue
        if str(trace.get("task_id", "")) not in origin_ids:
            continue
        if str(trace.get("status", "")) != "complete":
            continue
        if not trace.get("coverage_complete"):
            continue
        summary_key = _question_key(str(trace.get("summary", "")))
        if summary_key and (question_key == summary_key or question_key in summary_key):
            return True
    return False


def _logic_id(
    origin_ids: list[str],
    question: str,
    refs: Mapping[str, list[str]],
    paths: list[str],
) -> str:
    value = "\0".join(
        [
            *sorted(origin_ids),
            _question_key(question),
            *[f"{key}:{','.join(sorted(refs.get(key, [])))}" for key in _REF_KEYS],
            *sorted(paths),
        ]
    )
    return "task-logic-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def _union(tasks: list[dict[str, Any]], key: str) -> list[str]:
    result: list[str] = []
    for task in tasks:
        result.extend(str(item) for item in task.get(key, []) if str(item))
    return list(dict.fromkeys(result))


def _json_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return [_json_value(item) for item in value[:20]]
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in list(value.items())[:20]}
    return str(value)
