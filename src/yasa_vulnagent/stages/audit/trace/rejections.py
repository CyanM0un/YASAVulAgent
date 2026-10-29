"""Compact negative memory of independently reviewed rejected findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass
class RejectionIndex:
    entries: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_audit(
        cls,
        findings: list[Mapping[str, Any]],
        reviews: list[Mapping[str, Any]],
        *,
        revision: str = "",
    ) -> "RejectionIndex":
        complete: dict[str, Mapping[str, Any]] = {}
        for review in reviews:
            if (
                str(review.get("type", "finding")) == "finding"
                and str(review.get("status", "")) == "complete"
                and str(review.get("verdict", "")) == "rejected"
            ):
                complete.setdefault(str(review.get("target_id", "")), review)
        entries: list[dict[str, Any]] = []
        for finding in findings:
            if str(finding.get("verdict", "")) != "rejected":
                continue
            finding_id = str(finding.get("id", ""))
            review = complete.get(finding_id)
            if review is None:
                continue
            source_revision = str(
                finding.get("source_revision") or review.get("source_revision") or ""
            )
            if revision and source_revision and source_revision != revision:
                continue
            reason = str(finding.get("reason") or review.get("reason") or "").strip()
            if not reason:
                continue
            paths = _paths(finding, review)
            entries.append(
                {
                    "id": finding_id,
                    "title": str(finding.get("title", ""))[:200],
                    "category": str(finding.get("category", ""))[:120],
                    "task_id": str(finding.get("task_id", "")),
                    "task_ids": [
                        str(item) for item in (finding.get("task_ids") or []) if item
                    ][:4],
                    "reason": reason[:300],
                    "paths": paths[:4],
                    "source_to_sink": _source_to_sink(finding)[:300],
                }
            )
        return cls(entries=entries)

    def for_task(
        self,
        task: Mapping[str, Any],
        *,
        categories: set[str] | None = None,
        limit: int = 8,
    ) -> list[dict[str, Any]]:
        task_id = str(task.get("id", ""))
        task_paths = {str(path) for path in (task.get("paths") or []) if path}
        categories = categories or set()
        scored: list[tuple[int, str, dict[str, Any]]] = []
        for entry in self.entries:
            score = 0
            if task_id and task_id in {entry.get("task_id"), *entry.get("task_ids", [])}:
                score += 3
            if task_paths and task_paths.intersection(entry.get("paths") or []):
                score += 2
            if categories and entry.get("category") in categories:
                score += 1
            if score:
                scored.append((score, str(entry.get("id", "")), entry))
        scored.sort(key=lambda item: (-item[0], item[1]))
        return [dict(entry) for _, _, entry in scored[: max(1, int(limit))]]


def _paths(finding: Mapping[str, Any], review: Mapping[str, Any]) -> list[str]:
    paths: list[str] = []
    for source in (finding.get("evidence"), review.get("evidence")):
        if not isinstance(source, list):
            continue
        for item in source:
            if isinstance(item, dict) and item.get("path"):
                path = str(item["path"])
                if path not in paths:
                    paths.append(path)
    return paths


def _source_to_sink(finding: Mapping[str, Any]) -> str:
    value = finding.get("source_to_sink")
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        source = value.get("source")
        sink = value.get("sink")
        if isinstance(source, dict):
            source = source.get("summary") or source.get("path")
        if isinstance(sink, dict):
            sink = sink.get("summary") or sink.get("operation") or sink.get("path")
        return f"{source or ''} -> {sink or ''}"
    return ""
