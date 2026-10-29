from __future__ import annotations

import re
from typing import Any

from .git_tools import GitToolbox, is_supported_source, language_for_path


DECISIONS = {"security_fix", "not_security_fix", "uncertain"}
FIX_TYPES = {"patch", "configuration", "dependency", "documentation", "unknown"}
PATCH_STATUSES = {"complete", "not_applicable"}
RELATION_KINDS = {"data_flow", "control_flow", "structural", "semantic_equivalence"}
EXPLANATION_KINDS = {"constraint", "defense"}


def normalize_candidate(payload: dict[str, Any], toolbox: GitToolbox) -> dict[str, Any]:
    raw_commit = str(payload.get("commit", payload.get("sha", ""))).strip()
    if not raw_commit:
        raise ValueError("candidate is missing commit")
    commit = toolbox.canonical_commit(raw_commit)
    details = toolbox.commit_details(commit)
    parent = details["parent"]
    requested_parent = payload.get("parent")
    if requested_parent:
        requested = toolbox.canonical_commit(str(requested_parent))
        if requested != parent:
            raise ValueError(f"candidate parent is not the fixed first parent: {commit}")
    return {
        "commit": commit,
        "parent": parent,
        "subject": details["subject"],
        "message": details["message"],
        "reason": str(payload.get("reason", "")).strip(),
        "signals": _string_list(payload.get("signals")),
        "source": str(payload.get("source", "model_discovery")),
        "parent_policy": "first_parent",
    }


def normalize_review(payload: dict[str, Any], candidate: dict[str, Any], toolbox: GitToolbox) -> dict[str, Any]:
    decision = str(payload.get("decision", "uncertain")).strip().lower()
    if decision not in DECISIONS:
        raise ValueError(f"invalid security-history decision: {decision}")
    fix_type = str(payload.get("fix_type", "unknown")).strip().lower()
    if fix_type not in FIX_TYPES:
        fix_type = "unknown"
    locations = []
    for item in payload.get("locations", []) if isinstance(payload.get("locations", []), list) else []:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path", "")).strip()
        if toolbox._safe_path(path) is None or path == ".":
            continue
        locations.append(
            {
                "path": path,
                "side": str(item.get("side", "after")).strip() or "after",
                "start_line": _positive_int(item.get("start_line")),
                "end_line": _positive_int(item.get("end_line")),
                "reason": str(item.get("reason", "")).strip(),
            }
        )
    return {
        "commit": candidate["commit"],
        "parent": candidate.get("parent"),
        "decision": decision,
        "fix_type": fix_type,
        "confidence": _confidence(payload.get("confidence")),
        "rationale": str(payload.get("rationale", "")).strip(),
        "security_signals": _string_list(payload.get("security_signals")),
        "locations": locations,
        "unknowns": _string_list(payload.get("unknowns")),
        "warnings": _string_list(payload.get("warnings")),
        "checked_at": str(payload.get("checked_at", "")),
    }


def validate_patch_graph(
    toolbox: GitToolbox,
    candidate: dict[str, Any],
    graph: Any,
) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(graph, dict):
        return {"valid": False, "errors": ["graph is not an object"], "warnings": []}
    normalized = dict(graph)
    if normalized.get("schema") != "patch-graph":
        errors.append("schema must be patch-graph")
    if normalized.get("schema_version") not in {1, "1"}:
        errors.append("schema_version must be 1")
    if normalized.get("commit") != candidate.get("commit"):
        errors.append("graph commit does not match candidate")
    expected_parent = candidate.get("parent")
    if normalized.get("parent") != expected_parent:
        errors.append("graph parent does not match the fixed first parent")
    status = str(normalized.get("status", "")).strip()
    if status not in PATCH_STATUSES:
        errors.append("status must be complete or not_applicable")
    units = normalized.get("units", [])
    relations = normalized.get("relations", [])
    subgraphs = normalized.get("subgraphs", [])
    explanations = normalized.get("explanations", [])
    if not isinstance(units, list) or not isinstance(relations, list) or not isinstance(subgraphs, list):
        errors.append("units, relations, and subgraphs must be arrays")
        return {"valid": False, "errors": errors, "warnings": warnings, "graph": normalized}
    if not isinstance(explanations, list):
        errors.append("explanations must be an array")
        explanations = []
    unit_ids: set[str] = set()
    changed = {str(item.get("path")) for item in toolbox.changed_paths(candidate["commit"], expected_parent)}
    for unit in units:
        if not isinstance(unit, dict):
            errors.append("unit must be an object")
            continue
        unit_id = str(unit.get("id", "")).strip()
        if not unit_id or unit_id in unit_ids:
            errors.append(f"unit id is missing or duplicated: {unit_id}")
        unit_ids.add(unit_id)
        if not str(unit.get("summary", "")).strip():
            errors.append(f"unit has no summary: {unit_id}")
        paths = unit.get("paths", [])
        if not isinstance(paths, list):
            errors.append(f"unit paths must be an array: {unit_id}")
            paths = []
        for path in paths:
            path_text = str(path)
            if toolbox._safe_path(path_text) is None or path_text == ".":
                errors.append(f"unsafe unit path: {unit_id}")
            elif path_text not in changed:
                warnings.append(f"unit path is not in changed paths: {path_text}")
        _validate_source_refs(toolbox, candidate, unit.get("source_refs", []), errors, warnings)
    if status == "not_applicable":
        if unit_ids or relations:
            errors.append("not_applicable graph cannot contain units or relations")
        if not str(normalized.get("reason", "")).strip():
            errors.append("not_applicable graph needs a reason")
    elif not unit_ids:
        errors.append("complete graph must contain at least one repair unit")
    for relation in relations:
        if not isinstance(relation, dict):
            errors.append("relation must be an object")
            continue
        source = str(relation.get("source", ""))
        target = str(relation.get("target", ""))
        kind = str(relation.get("kind", ""))
        if source not in unit_ids or target not in unit_ids:
            errors.append(f"relation endpoint is unknown: {source}->{target}")
        if kind not in RELATION_KINDS:
            errors.append(f"unsupported relation kind: {kind}")
    for subgraph in subgraphs:
        if not isinstance(subgraph, dict):
            errors.append("subgraph must be an object")
            continue
        members = subgraph.get("unit_ids", [])
        shared = subgraph.get("shared_defense_unit_ids", [])
        if not isinstance(members, list) or not isinstance(shared, list):
            errors.append("subgraph member fields must be arrays")
            continue
        for member in [*members, *shared]:
            if str(member) not in unit_ids:
                errors.append(f"subgraph references unknown unit: {member}")
        if not str(subgraph.get("purpose", "")).strip():
            errors.append("subgraph needs a purpose")
    for explanation in explanations:
        if not isinstance(explanation, dict):
            errors.append("explanation must be an object")
            continue
        if str(explanation.get("kind", "")) not in EXPLANATION_KINDS:
            errors.append("explanation kind must be constraint or defense")
        if not str(explanation.get("text", "")).strip():
            errors.append("explanation needs text")
        _validate_source_refs(toolbox, candidate, explanation.get("source_refs", []), errors, warnings)
    if status == "complete":
        explanation_kinds = {
            str(item.get("kind")) for item in explanations if isinstance(item, dict)
        }
        for expected_kind in ("constraint", "defense"):
            if expected_kind not in explanation_kinds:
                warnings.append(f"missing {expected_kind} explanation")
    return {"valid": not errors, "errors": errors, "warnings": warnings, "graph": normalized}


def _validate_source_refs(
    toolbox: GitToolbox,
    candidate: dict[str, Any],
    refs: Any,
    errors: list[str],
    warnings: list[str],
) -> None:
    if refs is None:
        return
    if not isinstance(refs, list):
        errors.append("source_refs must be an array")
        return
    expected_parent = candidate.get("parent")
    for ref in refs:
        if not isinstance(ref, dict):
            errors.append("source reference must be an object")
            continue
        side = str(ref.get("side", ""))
        revision = str(ref.get("revision", ""))
        path = str(ref.get("path", ""))
        if side not in {"before", "after"}:
            errors.append(f"invalid source side: {side}")
        expected_revision = candidate["commit"] if side == "after" else expected_parent
        if expected_revision is None and side == "before" and revision in {"", "EMPTY_TREE"}:
            continue
        try:
            canonical_revision = toolbox.canonical_commit(revision)
        except RuntimeError:
            canonical_revision = revision
        if canonical_revision != expected_revision:
            errors.append(f"source revision does not match side for {path}")
            continue
        ref["revision"] = canonical_revision
        if toolbox._safe_path(path) is None or path == ".":
            errors.append(f"unsafe source path: {path}")
            continue
        start = _positive_int(ref.get("start_line"))
        end = _positive_int(ref.get("end_line"))
        if start is None or end is None or end < start:
            errors.append(f"invalid source line range: {path}")
            continue
        language = str(ref.get("language", ""))
        expected_language = language_for_path(path)
        if expected_language is None:
            warnings.append(f"source language is unsupported: {path}")
        elif language and language != expected_language:
            errors.append(f"source language does not match path: {path}")
        if not is_supported_source(path):
            continue
        payload = toolbox.read_revision_file(revision, path, start, end)
        if "error" in payload:
            errors.append(f"source cannot be read: {path}: {payload['error']}")
            continue
        actual = str(payload.get("text", ""))
        expected = str(ref.get("text", ""))
        if not expected.strip():
            errors.append(f"source reference has no text: {path}")
        elif not _text_matches(expected, actual):
            errors.append(f"source text does not match revision: {path}:{start}-{end}")


def _text_matches(expected: str, actual: str) -> bool:
    def compact(value: str) -> str:
        return re.sub(r"\s+", " ", value).strip()

    expected_compact = compact(expected)
    actual_compact = compact(actual)
    if not expected_compact or not actual_compact:
        return False
    return expected_compact == actual_compact or expected_compact in actual_compact


def _positive_int(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _confidence(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text if text in {"high", "medium", "low"} else "unknown"


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]
