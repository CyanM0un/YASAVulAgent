from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ....storage import utc_now
from ..evidence import location_ref, make_evidence, validate_location, validate_refs
from ..ledger import DiscoverLedger
from .query import QUERY_KINDS, FeatureQueryError, execute_query, validate_query_pattern


ROLES = {"source", "registration", "activation", "binding", "boundary", "unknown"}
DEFAULT_MAX_RESULTS = 200
DEFAULT_MAX_TASKS = 32
DEFAULT_TIMEOUT = 30


def _hash(*parts: Any) -> str:
    return hashlib.sha256("|".join(str(part) for part in parts).encode()).hexdigest()[:16]


def _relative(path: str) -> str:
    return str(path).removeprefix("./")


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _entry_id(path: str, start: int, end: int, kind: str = "feature_hit") -> str:
    return "entry-" + _hash(path, start, end, kind)


def _range_covered(
    receipts: list[dict[str, Any]],
    path: str,
    start: int,
    end: int,
) -> bool:
    ranges: list[tuple[int, int]] = []
    for receipt in receipts or []:
        if receipt.get("tool") != "read_file":
            continue
        if receipt.get("status") != "ok" or receipt.get("truncated"):
            continue
        if _relative(str(receipt.get("path", ""))) != path:
            continue
        try:
            first = int(receipt.get("start_line", 0))
            last = int(receipt.get("end_line", 0))
        except (TypeError, ValueError):
            continue
        if first < 1 or last < first:
            continue
        ranges.append((first, last))
    cursor = max(1, int(start))
    target_end = int(end)
    for first, last in sorted(ranges):
        if first > cursor:
            break
        cursor = max(cursor, last + 1)
        if cursor > target_end:
            return True
    return cursor > target_end


def normalize_observation(observation: dict[str, Any]) -> dict[str, Any]:
    query = observation.get("query") if isinstance(observation.get("query"), dict) else {}
    kind = str(observation.get("kind", "text"))
    role = str(observation.get("role", "unknown"))
    definition = observation.get("definition") if isinstance(observation.get("definition"), dict) else {}
    evidence = observation.get("evidence_refs")
    evidence = evidence if isinstance(evidence, list) else []
    scope = query.get("scope")
    scope = scope if isinstance(scope, list) else []
    return {
        "kind": kind,
        "name": str(observation.get("name", "")).strip(),
        "role": role if role in ROLES else "unknown",
        "definition": {
            "path": _relative(str(definition.get("path", ""))),
            "line_start": _int(definition.get("line_start", 0)),
            "line_end": _int(definition.get("line_end", 0)),
        },
        "evidence_refs": [
            str(item) for item in evidence if str(item).strip()
        ],
        "query": {
            "kind": str(query.get("kind", kind)),
            "target": str(query.get("target", observation.get("name", ""))).strip(),
            "regex": bool(query.get("regex", False)),
            "scope": [
                _relative(str(item))
                for item in scope
                if str(item).strip()
            ],
            "max_results": _int(
                query.get("max_results", DEFAULT_MAX_RESULTS), DEFAULT_MAX_RESULTS
            ) or DEFAULT_MAX_RESULTS,
        },
        "limitations": [
            str(item) for item in observation.get("limitations", []) if str(item).strip()
        ],
    }


def validate_observation(
    repository: Path,
    ledger: DiscoverLedger,
    observation: dict[str, Any],
    *,
    read_ranges: list[dict[str, Any]] | None = None,
    max_regex_chars: int = 512,
) -> tuple[dict[str, Any] | None, list[str]]:
    normalized = normalize_observation(observation)
    errors: list[str] = []
    if normalized["kind"] not in QUERY_KINDS:
        errors.append(f"unsupported feature observation kind: {normalized['kind']}")
    if not normalized["name"]:
        errors.append("feature observation name is empty")
    if len(normalized["name"]) > 240:
        errors.append("feature observation name is too long")
    query = normalized["query"]
    if query["kind"] not in QUERY_KINDS:
        errors.append(f"unsupported query kind: {query['kind']}")
    if not query["target"]:
        errors.append("feature observation query target is empty")
    if len(query["target"]) > 512:
        errors.append("feature observation query target is too long")
    if query["kind"] in QUERY_KINDS:
        try:
            validate_query_pattern(
                query["kind"], query["target"], bool(query["regex"]), max_regex_chars
            )
        except FeatureQueryError as exc:
            errors.append(str(exc))
    definition = normalized["definition"]
    location = validate_location(
        repository,
        ledger,
        path=definition["path"],
        start=definition["line_start"],
        end=definition["line_end"],
    )
    if not location.get("ok"):
        errors.append(str(location.get("error", "invalid feature definition")))
    elif read_ranges is not None and not _range_covered(
        read_ranges,
        definition["path"],
        definition["line_start"],
        definition["line_end"],
    ):
        errors.append(
            "feature definition range was not read in this task: "
            f"{definition['path']}:{definition['line_start']}-{definition['line_end']}"
        )
    refs = normalized["evidence_refs"] or [
        location_ref(definition["path"], definition["line_start"], definition["line_end"])
    ]
    canonical, ref_errors = validate_refs(repository, ledger, refs, allow_entries=False)
    errors.extend(ref_errors)
    if errors:
        return None, errors
    normalized["evidence_refs"] = canonical
    normalized["definition"]["fingerprint"] = str(location.get("fingerprint", ""))
    if query["scope"]:
        allowed = {
            str(file.get("path", ""))
            for file in ledger.iter_files(limit=1000)
            if file.get("usage_hint") == "production-candidate"
            and file.get("content_type") == "text"
        }
        effective = [path for path in query["scope"] if path in allowed]
        if not effective:
            return None, ["feature query scope contains no production text files"]
        query["scope"] = effective
    return normalized, []


def _mechanism(observation: dict[str, Any]) -> dict[str, Any]:
    definition = observation["definition"]
    mechanism_id = "mechanism-" + _hash(
        observation["kind"],
        observation["name"],
        definition["path"],
        definition["line_start"],
        definition["line_end"],
    )
    return {
        "mechanism_id": mechanism_id,
        "kind": observation["kind"],
        "name": observation["name"],
        "role": observation["role"],
        "definition_path": definition["path"],
        "line_start": definition["line_start"],
        "line_end": definition["line_end"],
        "evidence_refs": observation["evidence_refs"],
        "status": "observed",
        "created_at": utc_now(),
    }


def _query_spec(observation: dict[str, Any], *, cursor: int = 0) -> dict[str, Any]:
    query = dict(observation["query"])
    query["cursor"] = max(0, int(cursor))
    query["max_results"] = max(1, min(int(query.get("max_results", DEFAULT_MAX_RESULTS)), 1000))
    return query


def _query_id(mechanism_id: str, spec: dict[str, Any]) -> str:
    return "query-" + _hash(
        mechanism_id,
        spec.get("kind"),
        spec.get("target"),
        int(bool(spec.get("regex", False))),
        json.dumps(sorted(spec.get("scope", [])), ensure_ascii=False),
    )


def _existing_hit(ledger: DiscoverLedger, hit_id: str) -> dict[str, Any] | None:
    for hit in ledger.hit_rows():
        if str(hit.get("hit_id", "")) == hit_id:
            return hit
    return None


def _materialize_results(
    ledger: DiscoverLedger,
    *,
    query_id: str,
    mechanism_id: str,
    results: list[dict[str, Any]],
    role: str,
    artifact_dir: Path,
    wave: int,
    max_tasks: int,
    current_tasks: int,
) -> dict[str, Any]:
    created_candidates = 0
    created_tasks = 0
    for result in results:
        path = _relative(str(result.get("path", "")))
        start = int(result.get("line_start", 0))
        end = int(result.get("line_end", start))
        file_row = ledger.get_file(path)
        fingerprint = str(file_row.get("fingerprint", "")) if file_row else ""
        entry_id = _entry_id(path, start, end)
        evidence = make_evidence(
            kind="feature-hit",
            path=path,
            start=start,
            end=end,
            fingerprint=fingerprint,
            excerpt=str(result.get("text", "")),
            summary=f"feature query hit: {result.get('text', '')}",
        )
        evidence_id = str(evidence["evidence_id"])
        hit_id = "hit-" + _hash(query_id, path, start, end)
        existing_hit = _existing_hit(ledger, hit_id)
        if existing_hit is not None and existing_hit.get("confirm_task_id"):
            continue
        entry = ledger.get_entry(entry_id)
        if entry is not None and str(entry.get("status", "candidate")) != "candidate":
            continue
        if entry is None:
            entry = {
                "entry_id": entry_id,
                "status": "candidate",
                "kind": "feature_hit",
                "role": role,
                "location": {"path": path, "line_start": start, "line_end": end},
                "summary": str(result.get("text", ""))[:4000],
                "assumptions": ["feature query hit requires confirm verification"],
                "evidence_refs": [evidence_id],
                "stale_reason": "",
            }
            ledger.put_evidence(evidence)
            ledger.put_entry(entry)
            ledger.set_file_status(path, "candidate")
            created_candidates += 1
        if current_tasks + created_tasks >= max_tasks:
            confirm_task_id = ""
        else:
            confirm_task_id = ledger.ensure_confirm_task(
                path=path,
                candidate_ids=[entry_id],
                origin="mechanism_hit",
                question=f"Verify feature-hit candidate {entry_id} in {path}.",
                artifact_dir=str(artifact_dir),
                wave=wave,
            )
            if confirm_task_id:
                created_tasks += 1
        ledger.put_hit(
            {
                "hit_id": hit_id,
                "query_id": query_id,
                "mechanism_id": mechanism_id,
                "path": path,
                "line_start": start,
                "line_end": end,
                "candidate_id": entry_id,
                "confirm_task_id": confirm_task_id,
                "created_at": utc_now(),
            }
        )
    return {
        "candidates": created_candidates,
        "tasks": created_tasks,
    }


def _execute_and_store(
    repository: Path,
    ledger: DiscoverLedger,
    *,
    mechanism: dict[str, Any],
    observation: dict[str, Any],
    query: dict[str, Any],
    artifact_dir: Path,
    wave: int,
    max_results: int,
    max_tasks: int,
    timeout: int,
    max_regex_chars: int = 512,
) -> dict[str, Any]:
    spec = _query_spec(observation, cursor=int(query.get("cursor", 0)))
    spec["max_results"] = max_results
    result = execute_query(
        repository,
        ledger,
        spec,
        default_max_results=max_results,
        timeout_seconds=timeout,
        max_regex_chars=max_regex_chars,
    )
    created_tasks_before = sum(
        1
        for hit in ledger.hit_rows()
        if str(hit.get("mechanism_id", "")) == str(mechanism.get("mechanism_id", ""))
        and hit.get("confirm_task_id")
    )
    materialized = _materialize_results(
        ledger,
        query_id=str(query["query_id"]),
        mechanism_id=str(mechanism["mechanism_id"]),
        results=list(result.get("results", [])),
        role=str(observation.get("role", "unknown")),
        artifact_dir=artifact_dir,
        wave=wave,
        max_tasks=max(0, max_tasks - created_tasks_before),
        current_tasks=0,
    )
    query.update(
        {
            "kind": spec["kind"],
            "target": spec["target"],
            "regex": bool(spec.get("regex", False)),
            "scope": spec.get("scope", []),
            "cursor": int(result.get("next_cursor", 0)),
            "returned": int(result.get("returned", 0)),
            "truncated": bool(result.get("truncated", False)),
            "complete": bool(result.get("complete", False)),
            "limitations": result.get("limitations", []),
            "errors": result.get("errors", []),
        }
    )
    ledger.put_query(query)
    mechanism["query_id"] = str(query["query_id"])
    mechanism["status"] = "queried" if query.get("complete") else "partial"
    ledger.put_mechanism(mechanism)
    return {
        "query": query,
        "result": result,
        **materialized,
    }


def process_observations(
    repository: Path,
    ledger: DiscoverLedger,
    observations: list[dict[str, Any]],
    *,
    task_id: str,
    artifact_dir: Path,
    wave: int = 0,
    read_ranges_by_task: dict[str, list[dict[str, Any]]] | None = None,
    max_results: int = DEFAULT_MAX_RESULTS,
    max_tasks: int = DEFAULT_MAX_TASKS,
    timeout: int = DEFAULT_TIMEOUT,
    max_regex_chars: int = 512,
) -> dict[str, Any]:
    summary = {
        "observations": 0,
        "mechanisms": 0,
        "queries": 0,
        "hits": 0,
        "candidates": 0,
        "tasks": 0,
        "warnings": [],
        "errors": [],
        "mechanism_ids": [],
    }
    for raw in observations:
        if not isinstance(raw, dict):
            continue
        summary["observations"] += 1
        source_task = str(raw.get("_source_task_id", "")) or task_id
        receipts = None
        if read_ranges_by_task is not None:
            receipts = read_ranges_by_task.get(source_task, [])
        observation, errors = validate_observation(
            repository,
            ledger,
            raw,
            read_ranges=receipts,
            max_regex_chars=max_regex_chars,
        )
        if observation is None:
            summary["warnings"].extend(
                f"{source_task}: invalid feature observation: {error}"
                for error in errors
            )
            continue
        mechanism = _mechanism(observation)
        old = ledger.get_mechanism(mechanism["mechanism_id"])
        if old is not None:
            mechanism["query_id"] = str(old.get("query_id", ""))
            mechanism["status"] = str(old.get("status", "observed"))
        ledger.put_mechanism(mechanism)
        summary["mechanisms"] += 1
        summary["mechanism_ids"].append(str(mechanism["mechanism_id"]))
        query_id = _query_id(mechanism["mechanism_id"], _query_spec(observation))
        query = next(
            (item for item in ledger.query_rows() if item.get("query_id") == query_id),
            None,
        )
        if query is None:
            query = {
                "query_id": query_id,
                "mechanism_id": mechanism["mechanism_id"],
                "kind": observation["query"]["kind"],
                "target": observation["query"]["target"],
                "regex": bool(observation["query"].get("regex", False)),
                "scope": observation["query"].get("scope", []),
                "cursor": 0,
                "returned": 0,
                "truncated": False,
                "complete": False,
                "limitations": [],
                "errors": [],
                "created_at": utc_now(),
            }
            ledger.put_query(query)
            summary["queries"] += 1
        if query.get("complete"):
            continue
        try:
            execution = _execute_and_store(
                repository,
                ledger,
                mechanism=mechanism,
                observation=observation,
                query=query,
                artifact_dir=artifact_dir,
                wave=wave,
                max_results=max_results,
                max_tasks=max_tasks,
                timeout=timeout,
                max_regex_chars=max_regex_chars,
            )
        except FeatureQueryError as exc:
            summary["warnings"].append(f"{source_task}: feature query rejected: {exc}")
            continue
        summary["hits"] += int(execution["result"].get("returned", 0))
        summary["candidates"] += int(execution.get("candidates", 0))
        summary["tasks"] += int(execution.get("tasks", 0))
        summary["warnings"].extend(
            f"{source_task}: feature query incomplete: {item}"
            for item in execution["query"].get("limitations", [])
        )
        summary["errors"].extend(
            f"{source_task}: feature query error: {item}"
            for item in execution["query"].get("errors", [])
        )
    if summary["warnings"]:
        ledger.add_messages(warnings=summary["warnings"])
    if summary["errors"]:
        ledger.add_messages(gaps=summary["errors"])
    return summary


def resume_incomplete_queries(
    repository: Path,
    ledger: DiscoverLedger,
    *,
    artifact_dir: Path,
    wave: int = 0,
    max_results: int = DEFAULT_MAX_RESULTS,
    max_tasks: int = DEFAULT_MAX_TASKS,
    timeout: int = DEFAULT_TIMEOUT,
    max_regex_chars: int = 512,
) -> dict[str, Any]:
    summary = {"queries": 0, "hits": 0, "candidates": 0, "tasks": 0}
    for query in ledger.incomplete_queries():
        if query.get("errors"):
            continue
        mechanism = ledger.get_mechanism(str(query.get("mechanism_id", "")))
        if mechanism is None:
            continue
        observation = {
            "kind": mechanism.get("kind", "text"),
            "name": mechanism.get("name", ""),
            "role": mechanism.get("role", "unknown"),
            "definition": {
                "path": mechanism.get("definition_path", ""),
                "line_start": mechanism.get("line_start", 0),
                "line_end": mechanism.get("line_end", 0),
            },
            "evidence_refs": mechanism.get("evidence_refs", []),
            "query": {
                "kind": query.get("kind", "text"),
                "target": query.get("target", ""),
                "regex": bool(query.get("regex", False)),
                "scope": query.get("scope", []),
                "max_results": max_results,
            },
        }
        execution = _execute_and_store(
            repository,
            ledger,
            mechanism=mechanism,
            observation=observation,
            query=query,
            artifact_dir=artifact_dir,
            wave=wave,
            max_results=max_results,
            max_tasks=max_tasks,
            timeout=timeout,
            max_regex_chars=max_regex_chars,
        )
        summary["queries"] += 1
        summary["hits"] += int(execution["result"].get("returned", 0))
        summary["candidates"] += int(execution.get("candidates", 0))
        summary["tasks"] += int(execution.get("tasks", 0))
    return summary


def ensure_confirm_tasks_for_candidates(
    ledger: DiscoverLedger,
    *,
    artifact_dir: Path,
    wave: int = 0,
    max_candidates: int = 8,
) -> int:
    covered: set[str] = set()
    for task in ledger.list_tasks(
        statuses={"pending", "partial", "running"}, kind_prefix="confirm"
    ):
        covered.update(str(item) for item in task.get("candidate_ids", []))
    by_path: dict[str, list[str]] = {}
    for entry in ledger.entries(status="candidate"):
        entry_id = str(entry.get("entry_id", ""))
        if not entry_id or entry_id in covered:
            continue
        location = entry.get("location") if isinstance(entry.get("location"), dict) else {}
        path = _relative(str(location.get("path", "")))
        if path:
            by_path.setdefault(path, []).append(entry_id)
    created = 0
    limit = max(1, int(max_candidates))
    for path, ids in sorted(by_path.items()):
        for index in range(0, len(ids), limit):
            task_id = ledger.ensure_confirm_task(
                path=path,
                candidate_ids=ids[index : index + limit],
                origin="candidate",
                artifact_dir=str(artifact_dir),
                wave=wave,
                max_candidates=limit,
            )
            if task_id:
                created += 1
    return created


def build_source_hints(ledger: DiscoverLedger) -> dict[str, Any]:
    sources: list[dict[str, Any]] = []
    for entry in ledger.entries():
        if str(entry.get("role", "")) != "source":
            continue
        location = entry.get("location") if isinstance(entry.get("location"), dict) else {}
        sources.append(
            {
                "entry_id": str(entry.get("entry_id", "")),
                "path": str(location.get("path", "")),
                "status": str(entry.get("status", "")),
                "line_start": location.get("line_start"),
                "line_end": location.get("line_end"),
            }
        )
    attempts: dict[str, int] = {}
    for task in ledger.list_tasks():
        for path in ledger.task_scope_paths(str(task.get("task_id", ""))):
            attempts[path] = attempts.get(path, 0) + int(task.get("attempts", 0))
    return {
        "source_entries": sources,
        "source_paths": sorted({item["path"] for item in sources if item["path"]}),
        "mechanism_hit_paths": sorted(
            {str(hit.get("path", "")) for hit in ledger.hit_rows() if hit.get("path")}
        ),
        "file_attempts": [
            {"path": path, "attempts": count}
            for path, count in sorted(attempts.items())
        ],
        "note": "Hints are ordering suggestions only; they are not coverage evidence.",
    }
