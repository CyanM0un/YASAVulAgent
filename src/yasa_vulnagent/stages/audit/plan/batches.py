"""Deterministically partition seed tasks into bounded, module-packed model batches."""

from __future__ import annotations

from pathlib import Path
from typing import Any

_KIND_ORDER = {"entry": 0, "patch": 1}


def build_seed_batches(
    tasks: list[dict[str, Any]],
    batch_size: int,
) -> list[dict[str, Any]]:
    """Return deterministic, directory/module-packed batches of seed tasks."""
    if not isinstance(batch_size, int) or isinstance(batch_size, bool) or batch_size <= 0:
        raise ValueError("batch_size must be a positive integer")
    if not isinstance(tasks, list):
        raise ValueError("tasks must be an array")

    seen: set[str] = set()
    file_buckets: dict[tuple[str, str], list[dict[str, Any]]] = {}
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
        file_buckets.setdefault((str(kind), key), []).append(task)

    # Step 1: atomic per-file chunks (only split a single file when it exceeds batch_size).
    dir_chunks: dict[tuple[str, str], list[tuple[str, list[dict[str, Any]]]]] = {}
    for kind, file_key in sorted(file_buckets, key=lambda item: (_KIND_ORDER[item[0]], item[1])):
        ordered = sorted(file_buckets[(kind, file_key)], key=lambda task: str(task["id"]))
        parent_dir = _parent_dir(file_key)
        for start in range(0, len(ordered), batch_size):
            chunk = ordered[start : start + batch_size]
            dir_chunks.setdefault((kind, parent_dir), []).append((file_key, chunk))

    # Step 2: pack file chunks within the same parent directory up to batch_size.
    module_chunks: dict[tuple[str, str], list[tuple[str, list[dict[str, Any]]]]] = {}
    for kind, parent_dir in sorted(dir_chunks, key=lambda item: (_KIND_ORDER[item[0]], item[1])):
        packed = _pack_chunks(dir_chunks[(kind, parent_dir)], batch_size, fallback_key=parent_dir)
        module_key = _module_prefix(parent_dir)
        module_chunks.setdefault((kind, module_key), []).extend(packed)

    # Step 3: pack small sibling directory batches sharing the same top-level module prefix.
    batches: list[dict[str, Any]] = []
    for kind, module_key in sorted(module_chunks, key=lambda item: (_KIND_ORDER[item[0]], item[1])):
        packed = _pack_chunks(
            module_chunks[(kind, module_key)],
            batch_size,
            fallback_key=module_key,
        )
        for batch_key, chunk in packed:
            batches.append(
                {
                    "id": f"batch-{len(batches) + 1:04d}",
                    "kind": kind,
                    "key": batch_key,
                    "tasks": chunk,
                }
            )
    return batches


def _pack_chunks(
    chunks: list[tuple[str, list[dict[str, Any]]]],
    batch_size: int,
    *,
    fallback_key: str,
) -> list[tuple[str, list[dict[str, Any]]]]:
    packed: list[tuple[str, list[dict[str, Any]]]] = []
    current_tasks: list[dict[str, Any]] = []
    current_keys: list[str] = []
    for key, chunk in chunks:
        if current_tasks and len(current_tasks) + len(chunk) > batch_size:
            label = current_keys[0] if len(set(current_keys)) == 1 else fallback_key
            packed.append((label, current_tasks))
            current_tasks = []
            current_keys = []
        current_tasks.extend(chunk)
        current_keys.append(key)
    if current_tasks:
        label = current_keys[0] if len(set(current_keys)) == 1 else fallback_key
        packed.append((label, current_tasks))
    return packed


def _parent_dir(file_key: str) -> str:
    if file_key == "<no-path>":
        return "<no-path>"
    parent = str(Path(file_key).parent).replace("\\", "/")
    return "<root>" if parent in {"", "."} else parent


def _module_prefix(parent_dir: str) -> str:
    if parent_dir in {"<no-path>", "<root>"}:
        return parent_dir
    parts = [part for part in parent_dir.split("/") if part]
    return parts[0] if parts else "<root>"


def _task_id(task: dict[str, Any], index: int) -> str:
    value = task.get("id")
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"tasks[{index}].id must be a non-empty string")
    return value.strip()
