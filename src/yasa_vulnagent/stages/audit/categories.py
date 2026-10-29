"""Load the plan-facing audit category manifest.

Detailed CWE checklists live in ``category_details.json`` and are intentionally
not loaded here. The plan node only needs category identifiers and obligation
metadata.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib.resources import files
from typing import Any

_APPLIES_TO = {"entry", "patch"}
_SOURCES = {"baseline", "project"}


@dataclass(frozen=True)
class CategoryDefinition:
    id: str
    title: str
    applies_to: tuple[str, ...]
    source: str
    required: bool
    version: int


@dataclass(frozen=True)
class PatchCheckDefinition:
    kind: str
    title: str


@dataclass(frozen=True)
class CategoryManifest:
    profile_version: int
    categories: tuple[CategoryDefinition, ...]
    patch_checks: tuple[PatchCheckDefinition, ...]

    def for_kind(self, kind: str, *, required_only: bool = False) -> tuple[CategoryDefinition, ...]:
        return tuple(
            category
            for category in self.categories
            if kind in category.applies_to
            and (category.required or not required_only)
        )


def load_category_manifest() -> CategoryManifest:
    """Load and validate the packaged category manifest."""
    path = files("yasa_vulnagent.stages.audit").joinpath("categories.json")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"category manifest is unreadable: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("category manifest must be an object")

    profile_version = _positive_int(payload.get("profile_version"), "profile_version")
    raw_categories = payload.get("categories")
    if not isinstance(raw_categories, list) or not raw_categories:
        raise ValueError("category manifest.categories must be a non-empty array")

    categories: list[CategoryDefinition] = []
    seen: set[str] = set()
    for index, item in enumerate(raw_categories):
        if not isinstance(item, dict):
            raise ValueError(f"category manifest.categories[{index}] must be an object")
        category_id = _string(item.get("id"), f"categories[{index}].id")
        if category_id in seen:
            raise ValueError(f"duplicate category id: {category_id}")
        seen.add(category_id)
        applies_to = _string_list(item.get("applies_to"), f"categories[{index}].applies_to")
        invalid = set(applies_to) - _APPLIES_TO
        if invalid:
            raise ValueError(f"{category_id}: invalid applies_to values: {sorted(invalid)}")
        source = _string(item.get("source"), f"categories[{index}].source")
        if source not in _SOURCES:
            raise ValueError(f"{category_id}: invalid source: {source}")
        required = item.get("required")
        if not isinstance(required, bool):
            raise ValueError(f"{category_id}: required must be a boolean")
        categories.append(
            CategoryDefinition(
                id=category_id,
                title=_string(item.get("title"), f"categories[{index}].title"),
                applies_to=tuple(applies_to),
                source=source,
                required=required,
                version=_positive_int(item.get("version"), f"categories[{index}].version"),
            )
        )

    raw_patch_checks = payload.get("patch_checks")
    if not isinstance(raw_patch_checks, list) or not raw_patch_checks:
        raise ValueError("category manifest.patch_checks must be a non-empty array")
    patch_checks: list[PatchCheckDefinition] = []
    seen_kinds: set[str] = set()
    for index, item in enumerate(raw_patch_checks):
        if not isinstance(item, dict):
            raise ValueError(f"category manifest.patch_checks[{index}] must be an object")
        kind = _string(item.get("kind"), f"patch_checks[{index}].kind")
        if kind in seen_kinds:
            raise ValueError(f"duplicate patch check kind: {kind}")
        seen_kinds.add(kind)
        patch_checks.append(
            PatchCheckDefinition(
                kind=kind,
                title=_string(item.get("title"), f"patch_checks[{index}].title"),
            )
        )

    return CategoryManifest(
        profile_version=profile_version,
        categories=tuple(categories),
        patch_checks=tuple(patch_checks),
    )


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value.strip()


def _string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{label} must be a non-empty array")
    result = [_string(item, f"{label}[{index}]") for index, item in enumerate(value)]
    if len(set(result)) != len(result):
        raise ValueError(f"{label} must not contain duplicates")
    return result


def _positive_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value
