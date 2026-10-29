"""Canonical result construction and the validation contract."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from .schema import DISPOSITIONS, LEVELS, TERMINAL, empty_result
from .storage import ValidationPaths, write_json


def canonicalize(
    *,
    paths: ValidationPaths,
    run_id: str,
    repository: str,
    repo_commit: str,
    source_audit: str,
    selected: list[dict[str, Any]],
    raw_results: Mapping[str, dict[str, Any]],
    verifier_results: Mapping[str, dict[str, Any]],
    runtime: Mapping[str, Any],
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    gaps: list[dict[str, str]] = []
    for finding in selected:
        finding_id = str(finding.get("id", ""))
        raw = raw_results.get(finding_id)
        if not isinstance(raw, dict):
            result = empty_result(finding)
            result["execution_status"] = "not_started"
            result["counterevidence_or_proof_gap"] = [
                "primary validation agent produced no result"
            ]
            findings.append(result)
            gaps.append(
                {"finding_id": finding_id, "reason": result["counterevidence_or_proof_gap"][0]}
            )
            continue
        verifier = verifier_results.get(finding_id)
        result = _normalize(raw, finding, verifier, paths)
        findings.append(result)
        if result["disposition"] == "unresolved":
            gaps.append(
                {
                    "finding_id": finding_id,
                    "reason": "; ".join(result.get("counterevidence_or_proof_gap", [])) or "unresolved",
                }
            )
    counts = {
        "selected": len(selected),
        "confirmed": sum(1 for item in findings if item["disposition"] == "confirmed"),
        "rejected": sum(1 for item in findings if item["disposition"] == "rejected"),
        "unresolved": sum(1 for item in findings if item["disposition"] == "unresolved"),
    }
    status = "complete" if counts["unresolved"] == 0 else "partial"
    return {
        "run_id": run_id,
        "repo": repository,
        "repo_commit": repo_commit,
        "source_audit": source_audit,
        "status": status,
        "execution_status": "completed",
        "runtime": dict(runtime),
        "selected_finding_ids": [str(item.get("id", "")) for item in selected],
        "counts": counts,
        "findings": findings,
        "gaps": gaps,
    }


def write_validation(paths: ValidationPaths, artifact: dict[str, Any]) -> None:
    write_json(paths.validation_file, artifact)


def _normalize(
    raw: dict[str, Any],
    finding: Mapping[str, Any],
    verifier: dict[str, Any] | None,
    paths: ValidationPaths,
) -> dict[str, Any]:
    result = empty_result(finding)
    result.update({key: value for key, value in raw.items() if key in result})
    result["id"] = str(finding.get("id", ""))
    result["finding_id"] = str(finding.get("id", ""))
    result["title"] = str(finding.get("title", "")) or result["title"]
    disposition = str(result.get("disposition", "unresolved"))
    result["disposition"] = disposition if disposition in DISPOSITIONS else "unresolved"
    result["execution_status"] = str(result.get("execution_status", "not_started"))
    if result["execution_status"] == "not_run":
        result["execution_status"] = "not_started"
    result["reproduction_level"] = str(result.get("reproduction_level", "internal_auxiliary"))
    if result["reproduction_level"] not in LEVELS:
        result["reproduction_level"] = "internal_auxiliary"
    result["environment"] = _environment(result.get("environment"))
    result["reproduction"] = result.get("reproduction") if isinstance(result.get("reproduction"), dict) else {}
    behavior = result.get("intended_behavior")
    if not isinstance(behavior, dict):
        behavior = {}
    for key in ("legitimate_actor", "legitimate_resource", "expected_capability", "security_boundary"):
        if not behavior.get(key):
            behavior[key] = "not recorded"
    if behavior.get("security_boundary_crossed") not in {"yes", "no", "unknown"}:
        behavior["security_boundary_crossed"] = "unknown"
    result["intended_behavior"] = behavior
    if not result.get("validation_method"):
        result["validation_method"] = "runtime validation"
    if not result.get("observed_result"):
        result["observed_result"] = "not run"
    rubric = result.get("rubric")
    rubric = [str(item) for item in rubric if str(item)] if isinstance(rubric, list) else []
    result["rubric"] = rubric[:5] or ["runtime behavior compared with the finding's intended boundary"]
    evidence = result.get("evidence")
    result["evidence"] = [item for item in evidence if isinstance(item, dict)] if isinstance(evidence, list) else []
    for item in result["evidence"]:
        if not item.get("kind"):
            item["kind"] = "runtime"
        if not item.get("description"):
            item["description"] = str(item.get("observation", "") or "runtime observation")
        if item.get("artifact"):
            item["artifact"] = _run_relative(item["artifact"], paths)
    reproduction = result["reproduction"]
    if isinstance(reproduction, dict):
        reproduction["artifacts"] = [
            _run_relative(item, paths)
            for item in reproduction.get("artifacts", [])
            if str(item).strip()
        ] if isinstance(reproduction.get("artifacts"), list) else []
        if not reproduction["artifacts"]:
            reproduction["artifacts"] = [
                str(item.get("artifact"))
                for item in result["evidence"]
                if item.get("artifact")
            ]
    controls = result.get("negative_controls")
    result["negative_controls"] = [item for item in controls if isinstance(item, dict)] if isinstance(controls, list) else []
    artifacts = result.get("artifacts")
    result["artifacts"] = [
        _run_relative(item, paths) for item in artifacts if str(item).strip()
    ] if isinstance(artifacts, list) else []
    gap = result.get("counterevidence_or_proof_gap")
    result["counterevidence_or_proof_gap"] = [str(item) for item in gap if str(item)] if isinstance(gap, list) else []
    result["verifier"] = _verifier(verifier, paths)
    _apply_contract(result, paths, raw)
    return result


def _apply_contract(result: dict[str, Any], paths: ValidationPaths, raw: Mapping[str, Any]) -> None:
    disposition = str(result.get("disposition", "unresolved"))
    if disposition not in TERMINAL:
        result["disposition"] = "unresolved"
        gap = result.get("counterevidence_or_proof_gap")
        if not isinstance(gap, list) or not gap:
            result["counterevidence_or_proof_gap"] = ["runtime validation did not complete"]
        return
    failures: list[str] = []
    boundary = str(result["intended_behavior"].get("security_boundary_crossed", "unknown"))
    expected = "yes" if disposition == "confirmed" else "no"
    if result.get("execution_status") != "completed":
        failures.append("execution_status is not completed")
    if boundary != expected:
        failures.append(f"security_boundary_crossed must be {expected}")
    if result.get("reproduction_level") in {"internal_auxiliary", "not_attempted"}:
        failures.append("terminal result lacks a decisive reproduction level")
    if not _execution_record(raw.get("reproduction"), paths):
        failures.append("missing or incomplete reproduction record")
    if not _environment_ok(raw.get("environment")):
        failures.append("missing environment runtime, dependencies, or configuration")
    if not result.get("validation_method"):
        failures.append("missing validation_method")
    if not result.get("observed_result"):
        failures.append("missing observed_result")
    if not result.get("rubric"):
        failures.append("missing rubric")
    if not _behavior_ok(result.get("intended_behavior")):
        failures.append("incomplete intended_behavior")
    if not _behavior_ok(raw.get("intended_behavior")):
        failures.append("agent result is missing the full intended_behavior")
    if not _artifact_evidence(result, paths):
        failures.append("no saved runtime artifact backs the evidence")
    if not result["verifier"].get("independent") or not result["verifier"].get("rerun"):
        failures.append("fresh verifier did not independently rerun")
    if not _execution_record(result["verifier"].get("execution"), paths):
        failures.append("fresh verifier is missing its execution record")
    if not _artifact_evidence(result["verifier"], paths):
        failures.append("fresh verifier is missing its own saved evidence")
    verifier_disposition = str(result["verifier"].get("disposition", ""))
    if verifier_disposition and verifier_disposition != disposition:
        failures.append("fresh verifier disagreed with the primary disposition")
    if not _environment_ok(result["verifier"].get("environment")):
        failures.append("fresh verifier is missing environment")
    if failures:
        result["disposition"] = "unresolved"
        result["counterevidence_or_proof_gap"] = failures


def _environment(value: Any) -> dict[str, Any]:
    environment = dict(value) if isinstance(value, dict) else {}
    environment.setdefault("runtime", "docker")
    dependencies = environment.get("dependencies")
    if not isinstance(dependencies, list) or not dependencies:
        environment["dependencies"] = ["environment image"]
    configuration = environment.get("configuration")
    if not isinstance(configuration, list) or not configuration:
        environment["configuration"] = ["runtime validation"]
    return environment


def _verifier(value: dict[str, Any] | None, paths: ValidationPaths) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"independent": False, "rerun": False, "evidence": []}
    result = dict(value)
    nested = result.get("verifier")
    if isinstance(nested, dict):
        result.update(nested)
    result["independent"] = bool(result.get("independent", False))
    evidence = result.get("evidence") if isinstance(result.get("evidence"), list) else []
    result["rerun"] = bool(
        result.get("execution_status") == "completed"
        and result.get("reproduction")
        and _artifact_evidence({"evidence": evidence, "artifacts": result.get("artifacts", [])}, paths)
    )
    result.setdefault("environment", {})
    result.setdefault("evidence", [])
    result["evidence"] = [
        item for item in result["evidence"] if isinstance(item, dict)
    ]
    for item in result["evidence"]:
        if item.get("artifact"):
            item["artifact"] = _run_relative(item["artifact"], paths)
    result.setdefault(
        "execution",
        result.get("reproduction") if isinstance(result.get("reproduction"), dict) else {"commands": []},
    )
    if isinstance(result.get("execution"), dict):
        execution = result["execution"]
        execution["artifacts"] = [
            _run_relative(item, paths)
            for item in execution.get("artifacts", [])
            if str(item).strip()
        ] if isinstance(execution.get("artifacts"), list) else []
    return result


def _environment_ok(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    if not str(value.get("runtime", "")).strip():
        return False
    for key in ("dependencies", "configuration"):
        items = value.get(key)
        if not isinstance(items, list) or not items or not all(str(item).strip() for item in items):
            return False
    return True


def _behavior_ok(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    for key in ("legitimate_actor", "legitimate_resource", "expected_capability", "security_boundary"):
        if not str(value.get(key, "")).strip():
            return False
    return value.get("security_boundary_crossed") in {"yes", "no", "unknown"}


def _execution_record(value: Any, paths: ValidationPaths) -> bool:
    if not isinstance(value, dict):
        return False
    for key in ("setup", "inputs", "commands"):
        items = value.get(key)
        if not isinstance(items, list) or not items:
            return False
    if not isinstance(value.get("cleanup"), list):
        return False
    for key in ("expected", "observed"):
        if not str(value.get(key, "")).strip():
            return False
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        return False
    return any(_artifact_ok(item, paths) for item in artifacts)


def _artifact_evidence(result: Mapping[str, Any], paths: ValidationPaths) -> bool:
    evidence = result.get("evidence", [])
    if not isinstance(evidence, list):
        return False
    for item in evidence:
        if not isinstance(item, dict):
            continue
        if _artifact_ok(item.get("artifact"), paths):
            return True
    for item in result.get("artifacts", []):
        if _artifact_ok(item, paths):
            return True
    return False


def _run_relative(value: Any, paths: ValidationPaths) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    path = Path(text)
    if path.is_absolute():
        try:
            return path.resolve().relative_to(paths.root.resolve()).as_posix()
        except (OSError, ValueError):
            return text
    return text


def _artifact_ok(value: Any, paths: ValidationPaths) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    path = Path(text)
    if not path.is_absolute():
        path = paths.root / path
    try:
        resolved = path.resolve()
        resolved.relative_to(paths.root.resolve())
    except (OSError, ValueError):
        return False
    return resolved.is_file()
