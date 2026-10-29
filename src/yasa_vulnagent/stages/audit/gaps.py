"""Canonical audit gap records shared by every checkpoint writer."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from typing import Any


def gap_id(source: str, reason: str, paths: Iterable[str] = ()) -> str:
    """Return a stable id for one gap record."""
    payload = "\0".join([source, reason, *paths])
    return f"gap-{source}-{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:12]}"


def make_gap(source: str, reason: str, paths: Iterable[str] = ()) -> dict[str, Any] | None:
    """Build one canonical gap, or None when the reason is empty."""
    source = str(source).strip() or "audit"
    reason = str(reason).strip()
    if not reason:
        return None
    normalized_paths = [str(path) for path in paths if str(path)]
    return {
        "id": gap_id(source, reason, normalized_paths),
        "source": source,
        "reason": reason,
        "paths": normalized_paths,
    }


def normalize_gap(value: Any, source: str = "audit") -> dict[str, Any] | None:
    """Normalize a string, a legacy ``{source,message}`` record, or a canonical gap."""
    if isinstance(value, str):
        return make_gap(source, value)
    if not isinstance(value, Mapping):
        return None
    record_source = str(value.get("source") or source)
    reason = str(value.get("reason") or value.get("message") or "").strip()
    paths = value.get("paths") if isinstance(value.get("paths"), list) else []
    gap = make_gap(record_source, reason, paths)
    if gap is None:
        return None
    existing_id = str(value.get("id") or "").strip()
    if existing_id:
        gap["id"] = existing_id
    return gap


def normalize_gaps(values: Any, source: str = "audit") -> list[dict[str, Any]]:
    """Normalize and deduplicate a gap list."""
    if not isinstance(values, list):
        return []
    result: dict[str, dict[str, Any]] = {}
    for value in values:
        gap = normalize_gap(value, source=source)
        if gap is not None:
            result[gap["id"]] = gap
    return list(result.values())


def replace_source_gaps(
    existing: Any,
    source: str,
    records: Iterable[Any],
) -> list[dict[str, Any]]:
    """Replace one stage's gaps while preserving all other sources."""
    normalized = [gap for gap in normalize_gaps(existing) if gap["source"] != source]
    incoming: list[dict[str, Any]] = []
    for record in records:
        gap = normalize_gap(record, source=source)
        if gap is not None:
            incoming.append(gap)
    merged = {gap["id"]: gap for gap in [*normalized, *incoming]}
    return list(merged.values())


def merge_source_messages(
    existing: Any,
    source: str,
    messages: Any,
    paths: Iterable[str] = (),
) -> list[dict[str, Any]]:
    """Replace one stage's string messages with canonical gap records."""
    values = messages if isinstance(messages, list) else []
    records = [make_gap(source, str(message), paths) for message in values]
    return replace_source_gaps(
        existing,
        source,
        [record for record in records if record is not None],
    )
