"""Deterministically partition seed tasks into bounded model batches."""

from __future__ import annotations

from typing import Any

_KIND_ORDER = {"entry": 0, "patch": 1}


def build_seed_batches(
    tasks: list[dict[str, Any]],
    batch_size: int,
) -> list[dict[str, Any]]:
    """Return deterministic, path-coherent batches of seed tasks."""
    if not isinstance(batch_size, int) or isinstance(batch_size, bool) or batch_size <= 0:
        raise ValueError("batch_size must be a positive integer")
    if not isinstance(tasks, list):
        raise ValueError("tasks must be an array")

    seen: set[str] = set()
    buckets: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for index, task in enumerate(tasks):
        if not isinstance(task, dict):
            raise ValueError(f"tasks[{index}] must be an object")
        task_id = _task_id(task, index)
        if task_id in seen:
            raise ValueError(f"duplicate seed task id: {task_id}")
        seen.add(task_id)
        kind = task.get("kind")
        if kind not in _KIND_ORDER:
            raise ValueError(f"{task_id}: invalid kind: {kind!r}")
        paths = task.get("paths")
        if not isinstance(paths, list) or not all(
            isinstance(path, str) and path for path in paths
        ):
            raise ValueError(f"{task_id}: paths must be an array of non-empty strings")
        key = sorted(paths)[0] if paths else "<no-path>"
        buckets.setdefault((str(kind), key), []).append(task)

    batches: list[dict[str, Any]] = []
    ordered_keys = sorted(
        buckets,
        key=lambda item: (_KIND_ORDER[item[0]], item[1]),
    )
    for kind, key in ordered_keys:
        ordered = sorted(buckets[(kind, key)], key=lambda task: str(task["id"]))
        for start in range(0, len(ordered), batch_size):
            chunk = ordered[start : start + batch_size]
            batches.append(
                {
                    "id": f"batch-{len(batches) + 1:04d}",
                    "kind": kind,
                    "key": key,
                    "tasks": chunk,
                }
            )
    return batches


def _task_id(task: dict[str, Any], index: int) -> str:
    value = task.get("id")
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"tasks[{index}].id must be a non-empty string")
    return value.strip()
