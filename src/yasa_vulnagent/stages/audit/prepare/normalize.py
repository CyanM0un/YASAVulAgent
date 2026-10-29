"""Normalize discover entries and init patch graphs into audit records."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping

from .inventory import safe_relative


_FIVE_FIELDS = (
    "input_origin",
    "registration",
    "activation",
    "input_binding",
    "trust_boundary",
)
_REF_RE = re.compile(
    r"^(?:(?P<prefix>source|review|read):)?"
    r"(?P<path>.+?):(?P<start>\d+)-(?P<end>\d+)$"
)
_PATCH_STATUSES = {"complete", "partial", "not_applicable"}
_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")


def normalize_entries(
    entries_file: Path,
    ledger_file: Path,
    repository: Path,
    scope_files: list[str],
    *,
    discover_revision: str,
    current_revision: str,
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    raw_entries = _load_array(entries_file, "confirmed-entries.json")
    evidence_map = _load_evidence(ledger_file)
    raw_by_id = {
        str(item.get("entry_id", "")): item
        for item in raw_entries
        if isinstance(item, dict) and item.get("entry_id")
    }
    scope = set(scope_files)
    source_changed = bool(
        discover_revision
        and current_revision
        and discover_revision != current_revision
    )
    entries: list[dict[str, Any]] = []
    gaps: list[str] = []
    warnings: list[str] = []
    seen: set[str] = set()

    for index, raw in enumerate(raw_entries):
        if not isinstance(raw, dict):
            gaps.append(f"confirmed entry {index} is not an object")
            continue
        entry_id = str(raw.get("entry_id", "")).strip()
        if not entry_id:
            gaps.append(f"confirmed entry {index} is missing entry_id")
            continue
        if entry_id in seen:
            gaps.append(f"duplicate confirmed entry: {entry_id}")
            continue
        if str(raw.get("status", "confirmed")) != "confirmed":
            gaps.append(f"{entry_id}: entry is not confirmed")
            continue
        summary = str(raw.get("summary", "")).strip()
        explanation = summary or f"Confirmed entry {entry_id}."
        location = raw.get("location")
        location = location if isinstance(location, dict) else {}
        entry_location, error = _read_evidence(
            repository,
            scope,
            path=str(location.get("path", "")),
            start=_int(location.get("line_start")),
            end=_int(location.get("line_end")),
            explanation=explanation,
            source_changed=source_changed,
        )
        evidence: list[dict[str, Any]] = []
        if entry_location is not None:
            evidence.append(entry_location)
        else:
            gaps.append(f"{entry_id}: entry location is invalid: {error}")

        discovery: dict[str, Any] = {
            "summary": summary,
            "role": str(raw.get("role", "")),
        }
        for field in _FIVE_FIELDS:
            value = raw.get(field)
            if not isinstance(value, dict):
                discovery[field] = {"summary": "", "evidence": []}
                warnings.append(f"{entry_id}: missing {field}")
                continue
            field_evidence: list[dict[str, Any]] = []
            for ref in _refs(value.get("evidence_refs")):
                resolved, error = _resolve_ref(
                    str(ref),
                    repository,
                    scope,
                    evidence_map,
                    raw_by_id,
                    source_changed,
                    field,
                )
                if resolved is None:
                    gaps.append(f"{entry_id}: {field} evidence invalid: {error}")
                    continue
                _append_unique(field_evidence, resolved)
            discovery[field] = {
                "summary": str(value.get("summary", "")),
                "evidence": field_evidence,
            }

        for ref in _refs(raw.get("evidence_refs")):
            resolved, error = _resolve_ref(
                str(ref),
                repository,
                scope,
                evidence_map,
                raw_by_id,
                source_changed,
                "entry",
            )
            if resolved is None:
                gaps.append(f"{entry_id}: evidence invalid: {error}")
                continue
            _append_unique(evidence, resolved)

        if entry_location is None:
            if not evidence:
                gaps.append(f"{entry_id}: no current-source evidence")
                continue
            entry_location = evidence[0]
        entries.append(
            {
                "id": entry_id,
                "name": _name(raw, summary, entry_id),
                "source": "discover",
                "entry_location": entry_location,
                "evidence": evidence,
                "discovery": discovery,
            }
        )
        seen.add(entry_id)

    return entries, gaps, list(dict.fromkeys(warnings))


def normalize_patches(
    patch_file: Path,
    run_root: Path,
    history_dir: Path,
    scope_files: list[str],
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    payload = _load_object(patch_file, "patch_graphs.json")
    graphs = payload.get("graphs", [])
    if not isinstance(graphs, list):
        raise ValueError("patch_graphs.json.graphs must be an array")
    scope = set(scope_files)
    patches: list[dict[str, Any]] = []
    gaps: list[str] = []
    warnings = _strings(payload.get("warnings"))
    seen: set[str] = set()

    for index, graph in enumerate(graphs):
        if not isinstance(graph, dict):
            gaps.append(f"patch graph {index} is not an object")
            continue
        commit = str(graph.get("commit", "")).strip().lower()
        if not _SHA_RE.match(commit):
            gaps.append(f"patch graph {index} has an invalid commit")
            continue
        if commit in seen:
            gaps.append(f"duplicate patch graph: {commit}")
            continue
        status = str(graph.get("status", "partial"))
        if status not in _PATCH_STATUSES:
            gaps.append(f"patch {commit}: invalid status {status}")
            continue
        units = graph.get("units", [])
        units = units if isinstance(units, list) else []
        unit_records: list[dict[str, Any]] = []
        unit_ids: list[str] = []
        changed_paths: list[str] = []
        for unit in units:
            if not isinstance(unit, dict):
                continue
            unit_id = str(unit.get("id", "")).strip()
            if not unit_id:
                gaps.append(f"patch {commit}: unit is missing id")
                continue
            paths = _safe_paths(unit.get("paths", []), scope)
            if unit_id in unit_ids:
                gaps.append(f"patch {commit}: duplicate unit id {unit_id}")
                continue
            unit_ids.append(unit_id)
            unit_records.append(
                {
                    "id": unit_id,
                    "kind": str(unit.get("kind", "")),
                    "summary": str(unit.get("summary", "")),
                    "paths": paths,
                }
            )
            for path in paths:
                if path not in changed_paths:
                    changed_paths.append(path)
            refs = unit.get("source_refs", [])
            for ref in refs if isinstance(refs, list) else []:
                if isinstance(ref, dict):
                    path = safe_relative(str(ref.get("path", "")))
                    if path is not None and path in scope and path not in changed_paths:
                        changed_paths.append(path)

        extra_paths = graph.get("changed_paths", [])
        for path in extra_paths if isinstance(extra_paths, list) else []:
            normalized = safe_relative(str(path))
            if normalized is not None and normalized in scope and normalized not in changed_paths:
                changed_paths.append(normalized)

        graph_file = history_dir / "patches" / commit / "graph.json"
        artifact_file = None
        if graph_file.is_file() and _inside(graph_file, run_root):
            artifact_file = _relative_run_path(graph_file, run_root)
        else:
            warnings.append(f"patch {commit}: graph.json is missing")

        raw_explanations = graph.get("explanations", [])
        explanations = [
            {
                "kind": str(item.get("kind", "")),
                "text": str(item.get("text", "")),
            }
            for item in (raw_explanations if isinstance(raw_explanations, list) else [])
            if isinstance(item, dict)
        ]
        record = {
            "id": f"patch-{commit}",
            "commit": commit,
            "parent": str(graph.get("parent", "")),
            "status": status,
            "changed_paths": changed_paths,
            "repair_unit_ids": unit_ids,
            "artifact_file": artifact_file,
            "units": unit_records,
            "explanations": explanations,
            "gaps": [],
            "warnings": [],
            "usable": bool(unit_ids or status == "not_applicable"),
        }
        patches.append(record)
        seen.add(commit)

    return patches, gaps, list(dict.fromkeys(warnings))


def _load_array(path: Path, label: str) -> list[Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is unreadable: {exc}") from exc
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array")
    return value


def _load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is unreadable: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _load_evidence(ledger_file: Path) -> dict[str, dict[str, Any]]:
    import sqlite3

    try:
        connection = sqlite3.connect(f"{Path(ledger_file).as_uri()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute(
                "SELECT evidence_id, payload FROM evidence"
            ).fetchall()
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise ValueError(f"discover evidence is unreadable: {exc}") from exc
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        try:
            payload = json.loads(str(row["payload"]))
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            result[str(row["evidence_id"])] = payload
    return result


def _resolve_ref(
    ref: str,
    repository: Path,
    scope: set[str],
    evidence_map: Mapping[str, dict[str, Any]],
    raw_by_id: Mapping[str, dict[str, Any]],
    source_changed: bool,
    label: str,
) -> tuple[dict[str, Any] | None, str | None]:
    if ref.startswith("evidence:"):
        evidence = evidence_map.get(ref.split(":", 1)[1])
        if evidence is None:
            return None, f"unknown evidence id: {ref}"
        return _read_evidence(
            repository,
            scope,
            path=str(evidence.get("source_file", "")),
            start=_int(evidence.get("line_start")),
            end=_int(evidence.get("line_end")),
            explanation=str(evidence.get("summary", "")) or f"Imported from {label}.",
            source_changed=source_changed,
            fingerprint=str(evidence.get("source_fingerprint", "")),
        )
    if ref.startswith("entry:"):
        target = raw_by_id.get(ref.split(":", 1)[1])
        if target is None:
            return None, f"unknown entry: {ref}"
        location = target.get("location")
        location = location if isinstance(location, dict) else {}
        return _read_evidence(
            repository,
            scope,
            path=str(location.get("path", "")),
            start=_int(location.get("line_start")),
            end=_int(location.get("line_end")),
            explanation=str(target.get("summary", "")) or f"Imported from {label}.",
            source_changed=source_changed,
        )
    match = _REF_RE.match(ref)
    if not match:
        return None, f"unverifiable reference: {ref}"
    return _read_evidence(
        repository,
        scope,
        path=match.group("path"),
        start=int(match.group("start")),
        end=int(match.group("end")),
        explanation=f"Imported from {label}.",
        source_changed=source_changed,
    )


def _read_evidence(
    repository: Path,
    scope: set[str],
    *,
    path: str,
    start: int,
    end: int,
    explanation: str,
    source_changed: bool,
    fingerprint: str = "",
) -> tuple[dict[str, Any] | None, str | None]:
    relative = safe_relative(path)
    if relative is None or relative not in scope:
        return None, f"path is outside the discover scope: {path}"
    target = repository / relative
    if target.is_symlink() or not target.is_file():
        return None, f"source file is unavailable: {relative}"
    try:
        target.resolve().relative_to(repository)
    except (OSError, RuntimeError, ValueError):
        return None, f"source path escapes the repository: {relative}"
    if start < 1 or end < start:
        return None, f"invalid line range: {relative}:{start}-{end}"
    if source_changed and not fingerprint:
        return None, "source revision changed and reference has no fingerprint"
    if fingerprint and _fingerprint(target) != fingerprint:
        return None, f"source fingerprint changed: {relative}"
    try:
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return None, f"source file is unreadable: {relative}: {exc}"
    if end > len(lines):
        return None, f"line range exceeds {relative}:{len(lines)}"
    code = "\n".join(lines[start - 1 : end])
    return (
        {
            "path": relative,
            "start_line": start,
            "end_line": end,
            "code": code,
            "explanation": explanation,
        },
        None,
    )


def _refs(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item.strip()]


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


def _append_unique(items: list[dict[str, Any]], value: dict[str, Any]) -> None:
    key = (value.get("path"), value.get("start_line"), value.get("end_line"))
    if not any(
        (item.get("path"), item.get("start_line"), item.get("end_line")) == key
        for item in items
    ):
        items.append(value)


def _safe_paths(values: Any, scope: set[str]) -> list[str]:
    if not isinstance(values, list):
        return []
    result: list[str] = []
    for value in values:
        path = safe_relative(str(value))
        if path is not None and path in scope:
            result.append(path)
    return result


def _inside(path: Path, root: Path) -> bool:
    try:
        return path.resolve().is_relative_to(root)
    except (OSError, RuntimeError):
        return False


def _fingerprint(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _relative_run_path(path: Path, run_root: Path) -> str:
    try:
        return path.resolve().relative_to(run_root).as_posix()
    except ValueError:
        return str(path.resolve())


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _name(raw: dict[str, Any], summary: str, entry_id: str) -> str:
    name = str(raw.get("name", "")).strip()
    if not name:
        name = " ".join(summary.split())[:120]
    return name or entry_id
