"""Build deterministic seed tasks and derive final audit tasks."""

from __future__ import annotations

import hashlib
import re
from typing import Any, Mapping

from ..categories import CategoryManifest

_PRIORITY_RANK = {"high": 0, "normal": 1, "low": 2}
_MAX_SUMMARY_CHARS = 600
_FIVE_FIELDS = (
    "input_origin",
    "registration",
    "activation",
    "input_binding",
    "trust_boundary",
)


def build_seed_tasks(
    entries: list[dict[str, Any]],
    patches: list[dict[str, Any]],
    scope_files: list[str],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Create one seed task per prepared entry and patch."""
    scope = set(scope_files)
    tasks: list[dict[str, Any]] = []
    gaps: list[str] = []
    seen_entries: set[str] = set()
    seen_patches: set[str] = set()

    for entry in entries:
        entry_id = str(entry.get("id", "")).strip()
        if not entry_id:
            gaps.append("entry is missing id")
            continue
        if entry_id in seen_entries:
            gaps.append(f"duplicate prepared entry: {entry_id}")
            continue
        seen_entries.add(entry_id)
        tasks.append(
            {
                "id": _entry_task_id(entry_id),
                "kind": "entry",
                "status": "planned",
                "entry_ids": [entry_id],
                "patch_ids": [],
                "origin_task_ids": [],
                "business_refs": {},
                "evidence": [],
                "repair_unit_refs": [],
                "paths": _entry_paths(entry, scope),
                "priority": "normal",
            }
        )

    for patch in patches:
        patch_id = str(patch.get("id", "")).strip()
        if not patch_id:
            gaps.append("patch is missing id")
            continue
        if patch_id in seen_patches:
            gaps.append(f"duplicate prepared patch: {patch_id}")
            continue
        seen_patches.add(patch_id)
        units = patch.get("units")
        units = [unit for unit in units if isinstance(unit, dict)] if isinstance(units, list) else []
        repair_unit_refs = [
            {"patch_id": patch_id, "unit_id": str(unit.get("id", "")).strip()}
            for unit in units
            if str(unit.get("id", "")).strip()
        ]
        status = "planned" if repair_unit_refs else "blocked"
        task = {
            "id": _patch_task_id(patch),
            "kind": "patch",
            "status": status,
            "entry_ids": [],
            "patch_ids": [patch_id],
            "origin_task_ids": [],
            "business_refs": {},
            "evidence": [],
            "repair_unit_refs": repair_unit_refs,
            "paths": _in_scope(patch.get("changed_paths"), scope),
            "priority": "normal",
        }
        tasks.append(task)
        if not repair_unit_refs and str(patch.get("status", "")) != "not_applicable":
            gaps.append(f"{patch_id} has no repair units")
    return tasks, gaps


def build_seed_views(
    tasks: list[dict[str, Any]],
    entries: list[dict[str, Any]],
    patches: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build compact, source-free task views for model batches."""
    entries_by_id = {str(entry.get("id", "")): entry for entry in entries}
    patches_by_id = {str(patch.get("id", "")): patch for patch in patches}
    views: list[dict[str, Any]] = []
    for task in tasks:
        view = {
            "id": task["id"],
            "kind": task["kind"],
            "status": task["status"],
            "entry_ids": list(task.get("entry_ids", [])),
            "patch_ids": list(task.get("patch_ids", [])),
            "paths": list(task.get("paths", [])),
        }
        if task["kind"] == "entry":
            entry = entries_by_id.get(str(task.get("entry_ids", [""])[0]), {})
            view["summary"] = _entry_summary(entry)
        else:
            patch = patches_by_id.get(str(task.get("patch_ids", [""])[0]), {})
            view["summary"] = _patch_summary(patch)
        views.append(view)
    return views


def derive_final_tasks(
    seed_tasks: list[dict[str, Any]],
    batches: list[dict[str, Any]],
    outputs: list[dict[str, Any]],
    manifest: CategoryManifest,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Derive final tasks and coverage obligations from validated model output."""
    seed_by_id = {str(task["id"]): task for task in seed_tasks}
    records: list[tuple[dict[str, Any], int, int]] = []

    for batch_index, (batch, output) in enumerate(zip(batches, outputs, strict=True)):
        for local_order, index in enumerate(output["order"]):
            group = output["groups"][index]
            seed_ids = list(group["seed_task_ids"])
            seed_items = [seed_by_id[seed_id] for seed_id in seed_ids]
            kind = str(seed_items[0]["kind"])
            if len(seed_items) == 1:
                task_id = str(seed_items[0]["id"])
            else:
                task_id = _group_task_id(kind, seed_ids)
            task = {
                "id": task_id,
                "kind": kind,
                "status": (
                    "blocked"
                    if any(item.get("status") == "blocked" for item in seed_items)
                    else "planned"
                ),
                "entry_ids": _union("entry_ids", seed_items),
                "patch_ids": _union("patch_ids", seed_items),
                "origin_task_ids": [],
                "business_refs": {},
                "evidence": [],
                "repair_unit_refs": _union_refs(seed_items),
                "paths": _union("paths", seed_items),
                "priority": str(group["priority"]),
            }
            records.append((task, batch_index, local_order))

    records.sort(
        key=lambda record: (
            _PRIORITY_RANK[str(record[0]["priority"])],
            record[1],
            record[2],
        )
    )
    tasks: list[dict[str, Any]] = []
    category_checks: list[dict[str, Any]] = []
    mechanism_checks: list[dict[str, Any]] = []
    for task, _, _ in records:
        tasks.append(task)
        category_checks.extend(_category_checks(task, manifest))
        mechanism_checks.extend(_mechanism_checks(task, manifest))
    return tasks, category_checks, mechanism_checks


def validate_final_tasks(
    seed_tasks: list[dict[str, Any]],
    tasks: list[dict[str, Any]],
    category_checks: list[dict[str, Any]],
    mechanism_checks: list[dict[str, Any]],
    scope_files: list[str],
    manifest: CategoryManifest,
) -> None:
    """Validate final invariants before writing the checkpoint."""
    scope = set(scope_files)
    task_ids = [str(task.get("id", "")) for task in tasks]
    if len(task_ids) != len(set(task_ids)):
        raise ValueError("plan produced duplicate task ids")

    expected_entries = {
        entry_id for task in seed_tasks for entry_id in task.get("entry_ids", [])
    }
    expected_patches = {
        patch_id for task in seed_tasks for patch_id in task.get("patch_ids", [])
    }
    actual_entries = [entry_id for task in tasks for entry_id in task.get("entry_ids", [])]
    actual_patches = [patch_id for task in tasks for patch_id in task.get("patch_ids", [])]
    if sorted(expected_entries) != sorted(actual_entries):
        raise ValueError("plan did not account for every prepared entry exactly once")
    if sorted(expected_patches) != sorted(actual_patches):
        raise ValueError("plan did not account for every prepared patch exactly once")

    expected_refs = {
        (str(ref.get("patch_id", "")), str(ref.get("unit_id", "")))
        for task in seed_tasks
        for ref in task.get("repair_unit_refs", [])
    }
    actual_refs = {
        (str(ref.get("patch_id", "")), str(ref.get("unit_id", "")))
        for task in tasks
        for ref in task.get("repair_unit_refs", [])
    }
    if expected_refs != actual_refs:
        raise ValueError("plan did not preserve every repair unit reference")

    category_ids = [str(check.get("id", "")) for check in category_checks]
    mechanism_ids = [str(check.get("id", "")) for check in mechanism_checks]
    check_ids = [*category_ids, *mechanism_ids]
    if len(check_ids) != len(set(check_ids)):
        raise ValueError("plan produced duplicate check ids")

    entry_categories = {
        category.id for category in manifest.for_kind("entry")
    }
    patch_kinds = {check.kind for check in manifest.patch_checks}
    for task in tasks:
        if not set(task.get("paths", [])).issubset(scope):
            raise ValueError(f"{task.get('id')}: task path is outside the audit scope")
        if task.get("kind") == "entry":
            expected = {
                (task["id"], category) for category in entry_categories
            }
            task_checks = [
                check for check in category_checks if check.get("task_id") == task["id"]
            ]
            actual = {
                (str(check.get("task_id", "")), str(check.get("category", "")))
                for check in task_checks
            }
            if len(task_checks) != len(expected) or expected != actual:
                raise ValueError(f"{task['id']}: entry category obligations are incomplete")
        elif task.get("kind") == "patch" and task.get("repair_unit_refs"):
            expected = {(task["id"], kind) for kind in patch_kinds}
            task_checks = [
                check for check in mechanism_checks if check.get("task_id") == task["id"]
            ]
            actual = {
                (str(check.get("task_id", "")), str(check.get("kind", "")))
                for check in task_checks
            }
            if len(task_checks) != len(expected) or expected != actual:
                raise ValueError(f"{task['id']}: patch mechanism obligations are incomplete")

    if any(check.get("task_id") not in set(task_ids) for check in category_checks):
        raise ValueError("category check references an unknown task")
    if any(check.get("task_id") not in set(task_ids) for check in mechanism_checks):
        raise ValueError("mechanism check references an unknown task")


def _entry_paths(entry: Mapping[str, Any], scope: set[str]) -> list[str]:
    paths: list[str] = []
    location = entry.get("entry_location")
    if isinstance(location, dict):
        _append(paths, location.get("path"), scope)
    for item in _objects(entry.get("evidence")):
        _append(paths, item.get("path"), scope)
    discovery = entry.get("discovery")
    if isinstance(discovery, dict):
        for field in _FIVE_FIELDS:
            value = discovery.get(field)
            if isinstance(value, dict):
                for item in _objects(value.get("evidence")):
                    _append(paths, item.get("path"), scope)
    return paths


def _entry_summary(entry: Mapping[str, Any]) -> dict[str, Any]:
    discovery = entry.get("discovery") if isinstance(entry.get("discovery"), dict) else {}
    summary = {
        "name": _clip(entry.get("name")),
        "role": _clip(discovery.get("role")),
        "entry": _clip(discovery.get("summary")),
    }
    for field in _FIVE_FIELDS:
        value = discovery.get(field)
        summary[field] = _clip(value.get("summary") if isinstance(value, dict) else "")
    return summary


def _patch_summary(patch: Mapping[str, Any]) -> dict[str, Any]:
    units = []
    for unit in _objects(patch.get("units")):
        units.append(
            {
                "id": str(unit.get("id", "")),
                "kind": str(unit.get("kind", "")),
                "summary": _clip(unit.get("summary")),
                "paths": [str(path) for path in _strings(unit.get("paths"))],
            }
        )
    explanations = [
        {"kind": str(item.get("kind", "")), "text": _clip(item.get("text"))}
        for item in _objects(patch.get("explanations"))
    ]
    return {
        "status": str(patch.get("status", "")),
        "changed_paths": [str(path) for path in _strings(patch.get("changed_paths"))],
        "units": units,
        "explanations": explanations,
    }


def _category_checks(
    task: dict[str, Any],
    manifest: CategoryManifest,
) -> list[dict[str, Any]]:
    return [
        {
            "id": _check_id("category", task["id"], category.id),
            "task_id": task["id"],
            "category": category.id,
            "applicability": "unknown",
            "status": "pending",
            "reason": "",
            "evidence": [],
            "source": category.source,
            "required": category.required,
            "profile_version": manifest.profile_version,
        }
        for category in manifest.for_kind(task["kind"])
    ]


def _mechanism_checks(
    task: dict[str, Any],
    manifest: CategoryManifest,
) -> list[dict[str, Any]]:
    if task["kind"] != "patch" or not task.get("repair_unit_refs"):
        return []
    return [
        {
            "id": _check_id("mechanism", task["id"], check.kind),
            "task_id": task["id"],
            "kind": check.kind,
            "status": "pending",
            "outcome": "unknown",
            "reason": "",
            "evidence": [],
        }
        for check in manifest.patch_checks
    ]


def _entry_task_id(entry_id: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", entry_id).strip("-").lower()[:48]
    return f"task-entry-{slug or 'entry'}-{_digest(entry_id)[:8]}"


def _patch_task_id(patch: Mapping[str, Any]) -> str:
    commit = str(patch.get("commit", "")).strip().lower()
    if commit:
        return f"task-patch-{commit}"
    return f"task-patch-{_digest(str(patch.get('id', '')))[:12]}"


def _group_task_id(kind: str, seed_ids: list[str]) -> str:
    return f"task-{kind}-group-{_digest(chr(0).join(sorted(seed_ids)))[:12]}"


def _check_id(prefix: str, task_id: str, key: str) -> str:
    return f"{prefix}-{_digest(f'{task_id}{chr(0)}{key}')[:16]}"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _in_scope(value: Any, scope: set[str]) -> list[str]:
    return [path for path in _strings(value) if path in scope]


def _append(paths: list[str], value: Any, scope: set[str]) -> None:
    if isinstance(value, str) and value in scope and value not in paths:
        paths.append(value)


def _union(key: str, seed_items: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    for seed in seed_items:
        for value in _strings(seed.get(key)):
            if value not in values:
                values.append(value)
    return values


def _union_refs(seed_items: list[dict[str, Any]]) -> list[dict[str, str]]:
    refs: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for seed in seed_items:
        for ref in _objects(seed.get("repair_unit_refs")):
            pair = (str(ref.get("patch_id", "")), str(ref.get("unit_id", "")))
            if pair not in seen:
                seen.add(pair)
                refs.append({"patch_id": pair[0], "unit_id": pair[1]})
    return refs


def _objects(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _strings(value: Any) -> list[str]:
    return [item for item in value if isinstance(item, str) and item] if isinstance(value, list) else []


def _clip(value: Any) -> str:
    text = str(value or "").strip()
    return text[:_MAX_SUMMARY_CHARS]
