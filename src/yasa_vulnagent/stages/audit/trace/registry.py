"""Load and validate the data-driven trace specialist registry."""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib.resources import files
from typing import Any, Mapping

from ..categories import CategoryManifest

_TOOL_PROFILES = {"source", "source_yasa", "source_yasa_git"}
_APPLIES_TO = {"entry", "patch", "logic"}
_SCOPES = {"lens", "category"}


class RegistryError(ValueError):
    """Raised when the specialist registry is structurally invalid."""


@dataclass(frozen=True)
class SpecialistSpec:
    id: str
    title: str
    description: str
    prompt: str
    tools: str
    applies_to: tuple[str, ...]
    mandatory_for: tuple[str, ...]
    scope: str
    categories: tuple[str, ...]
    max_focus_units: int
    priority: int
    enabled: bool


@dataclass(frozen=True)
class SpecialistRegistry:
    profile_version: int
    specs: tuple[SpecialistSpec, ...]

    def get(self, specialist_id: str) -> SpecialistSpec | None:
        for spec in self.specs:
            if spec.id == specialist_id:
                return spec
        return None

    def enabled(self) -> tuple[SpecialistSpec, ...]:
        return tuple(spec for spec in self.specs if spec.enabled)

    def for_kind(self, kind: str) -> tuple[SpecialistSpec, ...]:
        return tuple(
            spec for spec in self.enabled() if kind in spec.applies_to
        )

    def mandatory_for(self, kind: str) -> tuple[SpecialistSpec, ...]:
        return tuple(
            spec
            for spec in self.enabled()
            if kind in spec.mandatory_for and kind in spec.applies_to
        )

    def public(self, kind: str) -> list[dict[str, Any]]:
        return [
            {
                "id": spec.id,
                "title": spec.title,
                "description": spec.description,
                "applies_to": list(spec.applies_to),
                "scope": spec.scope,
                "categories": list(spec.categories),
                "max_focus_units": spec.max_focus_units,
            }
            for spec in self.for_kind(kind)
        ]


def load_specialist_registry(
    categories: CategoryManifest | None = None,
) -> SpecialistRegistry:
    """Load the packaged registry; invalid definitions fail the trace start."""
    from .model import load_prompt

    path = files("yasa_vulnagent.stages.audit.trace").joinpath(
        "specialists/registry.json"
    )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RegistryError(f"specialist registry is unreadable: {exc}") from exc
    if not isinstance(payload, dict):
        raise RegistryError("specialist registry must be an object")
    version = payload.get("profile_version")
    if not isinstance(version, int) or isinstance(version, bool) or version <= 0:
        raise RegistryError("specialist registry.profile_version must be positive")
    raw_specs = payload.get("specialists")
    if not isinstance(raw_specs, list) or not raw_specs:
        raise RegistryError("specialist registry.specialists must be non-empty")

    category_ids = (
        {category.id for category in categories.categories}
        if categories is not None
        else set()
    )
    specs: list[SpecialistSpec] = []
    seen: set[str] = set()
    for index, item in enumerate(raw_specs):
        label = f"specialists[{index}]"
        if not isinstance(item, dict):
            raise RegistryError(f"{label} must be an object")
        specialist_id = _text(item.get("id"), f"{label}.id")
        if specialist_id in seen:
            raise RegistryError(f"duplicate specialist id: {specialist_id}")
        seen.add(specialist_id)
        tools = _text(item.get("tools"), f"{label}.tools")
        if tools not in _TOOL_PROFILES:
            raise RegistryError(f"{specialist_id}: unknown tool profile {tools}")
        applies_to = _text_list(item.get("applies_to"), f"{label}.applies_to")
        invalid = set(applies_to) - _APPLIES_TO
        if invalid:
            raise RegistryError(f"{specialist_id}: invalid applies_to {sorted(invalid)}")
        mandatory_for = _text_list(
            item.get("mandatory_for", []), f"{label}.mandatory_for", allow_empty=True
        )
        if set(mandatory_for) - {"patch"}:
            raise RegistryError(f"{specialist_id}: mandatory_for only supports patch")
        scope = _text(item.get("scope", "lens"), f"{label}.scope")
        if scope not in _SCOPES:
            raise RegistryError(f"{specialist_id}: invalid scope {scope}")
        categories_list = _text_list(
            item.get("categories", []), f"{label}.categories", allow_empty=True
        )
        if scope == "lens" and categories_list:
            raise RegistryError(f"{specialist_id}: lens scope cannot declare categories")
        if scope == "category":
            if not categories_list:
                raise RegistryError(f"{specialist_id}: category scope needs categories")
            if categories is not None:
                unknown = set(categories_list) - category_ids
                if unknown:
                    raise RegistryError(
                        f"{specialist_id}: unknown categories {sorted(unknown)}"
                    )
        prompt = _text(item.get("prompt"), f"{label}.prompt")
        load_prompt(prompt)
        max_focus = item.get("max_focus_units")
        if not isinstance(max_focus, int) or isinstance(max_focus, bool) or max_focus <= 0:
            raise RegistryError(f"{specialist_id}: max_focus_units must be positive")
        priority = item.get("priority")
        if not isinstance(priority, int) or isinstance(priority, bool):
            raise RegistryError(f"{specialist_id}: priority must be an integer")
        enabled = item.get("enabled")
        if not isinstance(enabled, bool):
            raise RegistryError(f"{specialist_id}: enabled must be boolean")
        specs.append(
            SpecialistSpec(
                id=specialist_id,
                title=_text(item.get("title"), f"{label}.title"),
                description=_text(item.get("description"), f"{label}.description"),
                prompt=prompt,
                tools=tools,
                applies_to=tuple(applies_to),
                mandatory_for=tuple(mandatory_for),
                scope=scope,
                categories=tuple(categories_list),
                max_focus_units=max_focus,
                priority=priority,
                enabled=enabled,
            )
        )
    return SpecialistRegistry(profile_version=version, specs=tuple(specs))


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RegistryError(f"{label} must be a non-empty string")
    return value.strip()


def _text_list(value: Any, label: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list):
        raise RegistryError(f"{label} must be an array")
    result = [_text(item, f"{label}[{index}]") for index, item in enumerate(value)]
    if not allow_empty and not result:
        raise RegistryError(f"{label} must not be empty")
    if len(set(result)) != len(result):
        raise RegistryError(f"{label} must not contain duplicates")
    return result
