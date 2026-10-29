"""Run the validate stage and persist its canonical result."""

from __future__ import annotations

import json
import logging
import shutil
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

from langgraph.runtime import Runtime

from ...agent.usage import UsageRecorder
from ...config import load_settings
from ...observability import start_run_logging, trace_node
from ...storage import load_state, mark_failed, save_state, utc_now
from ...workflow.state import RunContext, RunState
from ..common import record_stage
from .agent import check_plan, run_execute, run_plan, run_verify
from .commands import ShellRunner
from .contract import canonicalize, write_validation
from .intake import (
    audit_path,
    docker_runtime,
    ensure_environment,
    load_audit,
    reload_environment,
    select_findings,
)
from .environment.storage import git_revision
from .model import ValidationConfigurationError, ValidationModelError, ValidationPhaseError
from .schema import empty_state, empty_result
from .storage import (
    ValidationPaths,
    finding_dir,
    validation_paths,
    verifier_finding_dir,
    write_json,
)


logger = logging.getLogger(__name__)

_MIN_PHASE_SECONDS = 120.0


@trace_node("workflow.validate")
def run_stage(
    state: RunState,
    runtime: Runtime[RunContext] | None = None,
) -> dict[str, object]:
    context = runtime.context if runtime is not None else RunContext(settings=load_settings())
    settings = context.settings
    usage = context.usage or UsageRecorder(settings.usage_price_table)
    if settings.validate_max_total_tokens > 0 or settings.validate_max_total_cost > 0:
        usage.configure_limits(
            max_tokens=settings.validate_max_total_tokens or None,
            max_cost=settings.validate_max_total_cost or None,
        )
    context = replace(context, usage=usage)
    started_at = utc_now()
    paths = validation_paths(state["stages_dir"])
    paths.root.mkdir(parents=True, exist_ok=True)
    start_update = record_stage(
        "validate",
        state,
        status="running",
        message="validation is running.",
        started_at=started_at,
        details={"state_file": str(paths.state_file)},
    )
    running_state: RunState = {**state, **start_update}
    validation = empty_state(running_state, paths)
    repository = Path(str(running_state.get("repository", "")))
    validation["repo_commit"] = git_revision(repository) if repository.is_dir() else ""
    validation["run_file"] = str(running_state.get("run_file", ""))
    validation["environment_mode"] = str(
        running_state.get("validation_environment_mode") or "auto"
    )
    if running_state.get("validation_finding_ids"):
        validation["explicit_finding_ids"] = list(running_state["validation_finding_ids"])
    write_json(paths.state_file, validation)
    if running_state.get("validation_rerun"):
        _reset(paths)
    try:
        summary = _run_validation(
            state=running_state,
            validation=validation,
            paths=paths,
            context=context,
        )
    except ValidationConfigurationError as exc:
        summary = _intake_blocked(
            state=running_state,
            validation=validation,
            paths=paths,
            runtime={},
            reason="model_configuration",
            message=str(exc),
        )
        summary["status"] = "blocked"
        summary["execution_status"] = "blocked"
        summary["stop_reason"] = "model_configuration"
        summary["errors"] = [str(exc)]
        write_validation(paths, summary)
    except Exception as exc:
        summary = _intake_blocked(
            state=running_state,
            validation=validation,
            paths=paths,
            runtime={},
            reason="internal_error",
            message=str(exc),
        )
        summary["status"] = "failed"
        summary["execution_status"] = "failed"
        summary["stop_reason"] = "internal_error"
        summary["errors"] = [str(exc)]
        write_validation(paths, summary)
        _persist(paths, validation, summary)
        usage.write(paths.usage_file, stage_prefix="validate")
        record_stage(
            "validate",
            {**running_state, "validation": _summary(summary, paths)},
            status="failed",
            message="validation failed.",
            started_at=started_at,
            details=_summary(summary, paths),
        )
        raise
    usage.write(paths.usage_file, stage_prefix="validate")
    reload_environment(running_state)
    _persist(paths, validation, summary)
    status = str(summary.get("status", "failed"))
    final_update = record_stage(
        "validate",
        {**running_state, "validation": _summary(summary, paths)},
        status=status,
        message=f"Validation finished with status {status}.",
        started_at=started_at,
        details=_summary(summary, paths),
    )
    final_update["validation"] = _summary(summary, paths)
    return final_update


def run_validate(
    run_file: Path,
    *,
    finding_ids: list[str] | None = None,
    environment_mode: str = "auto",
    rerun: bool = False,
) -> RunState:
    """Run validation from an existing run whose audit stage is complete."""
    run_file = Path(run_file).expanduser().resolve()
    state = load_state(run_file)
    records = [item for item in state.get("stages", []) if item.get("name") == "audit"]
    if not records or records[-1].get("status") not in {"complete", "partial"}:
        raise ValueError("validate requires an existing run with a complete or partial audit stage")
    if environment_mode not in {"auto", "reuse", "build"}:
        raise ValueError("environment mode must be auto, reuse, or build")
    state = {
        **state,
        "validation_finding_ids": list(finding_ids or []),
        "validation_environment_mode": environment_mode,
        "validation_rerun": bool(rerun),
    }
    save_state(state)
    session = start_run_logging(run_file)
    session.progress.start("workflow.validate_resume", run_file=str(run_file))
    try:
        update = run_stage(
            state,
            runtime=Runtime(
                context=RunContext(settings=load_settings(), progress=session.progress)
            ),
        )
        session.progress.finish(
            "workflow.validate_resume",
            status=str(update.get("validation", {}).get("status", "failed")),
        )
        return {**state, **update}
    except Exception as exc:
        session.progress.finish(
            "workflow.validate_resume",
            status="failed",
            error_type=type(exc).__name__,
        )
        try:
            persisted = load_state(run_file)
            mark_failed(persisted, exc)
        except (OSError, TypeError, ValueError):
            pass
        raise
    finally:
        session.close()


def _run_validation(
    *,
    state: RunState,
    validation: dict[str, Any],
    paths: ValidationPaths,
    context: RunContext,
) -> dict[str, Any]:
    repository = Path(str(state.get("repository", "")))
    if not repository.is_dir():
        raise ValueError(f"repository is not a directory: {repository}")
    repo_commit = str(validation.get("repo_commit", ""))
    audit_file = audit_path(state)
    audit = load_audit(audit_file)
    explicit = list(validation.get("explicit_finding_ids") or [])
    selected = select_findings(audit, explicit or None)
    validation["source_audit"] = str(audit_file)
    validation["selected_finding_ids"] = [str(item.get("id", "")) for item in selected]
    validation["findings"] = selected
    write_json(paths.selection_file, _selection(validation, audit_file))
    if not selected:
        artifact = canonicalize(
            paths=paths,
            run_id=str(state.get("run_id", "")),
            repository=str(repository),
            source_audit=str(audit_file),
            selected=[],
            raw_results={},
            verifier_results={},
            runtime={
                "selected": "docker",
                "available": False,
                "checked": False,
                "reason": "no_findings",
            },
            repo_commit=repo_commit,
        )
        artifact["status"] = "complete"
        write_validation(paths, artifact)
        validation.update(artifact)
        return artifact

    runtime = docker_runtime(context.settings)
    if not runtime.get("available"):
        return _intake_blocked(
            state=state,
            validation=validation,
            paths=paths,
            runtime=runtime,
            reason=f"docker_unavailable:{runtime.get('reason', '')}",
        )
    environment = ensure_environment(
        validation,
        paths,
        context,
        str(validation.get("environment_mode", "auto")),
    )
    reload_environment(validation)
    if environment.get("status") != "ready":
        return _intake_blocked(
            state=state,
            validation=validation,
            paths=paths,
            runtime=runtime,
            reason=f"{environment.get('reason', 'environment_unavailable')}"
            + (f":{environment.get('error')}" if environment.get("error") else ""),
        )
    handle = environment["handle"]
    validation["environment"] = handle
    validation["runtime"] = runtime
    write_json(paths.selection_file, _selection(validation, audit_file))
    raw_results: dict[str, dict[str, Any]] = {}
    verifier_results: dict[str, dict[str, Any]] = {}
    deadline = time.monotonic() + max(1, context.settings.validate_total_timeout)
    for finding in selected:
        finding_id = str(finding.get("id", ""))
        directory = finding_dir(paths, finding_id)
        directory.mkdir(parents=True, exist_ok=True)
        if deadline - time.monotonic() <= _MIN_PHASE_SECONDS:
            raw_results[finding_id] = _failed_result(
                finding,
                "validation skipped: time budget exhausted before the finding started",
                stop_reason="time_budget",
            )
            continue
        plan = _resume_plan(directory, finding_id)
        if plan is None:
            try:
                plan = run_plan(
                    context=context,
                    repository=repository,
                    paths=paths,
                    finding=finding,
                    environment=handle,
                    artifact_dir=directory,
                    deadline=deadline,
                )
            except ValidationConfigurationError:
                raise
            except ValidationModelError as exc:
                raw_results[finding_id] = _failed_result(
                    finding, f"validation plan failed: {exc}", stop_reason="model_request"
                )
                continue
            except ValidationPhaseError as exc:
                raw_results[finding_id] = _failed_result(
                    finding, f"validation plan failed: {exc}", stop_reason=exc.stop_reason
                )
                continue
            except Exception as exc:
                raw_results[finding_id] = _failed_result(
                    finding, f"validation plan failed: {exc}"
                )
                continue
        else:
            logger.info("validate resume: reusing plan finding=%s", finding_id)
        primary = _resume_result(directory / "result.json", finding_id)
        if primary is None:
            shell = ShellRunner(
                root=paths.root,
                repository=repository,
                settings=context.settings,
                log_dir=directory / "attempts" / "0001",
            )
            try:
                primary = run_execute(
                    context=context,
                    repository=repository,
                    paths=paths,
                    finding=finding,
                    plan=plan,
                    environment=handle,
                    shell=shell,
                    artifact_dir=directory,
                    deadline=deadline,
                )
            except ValidationConfigurationError:
                raise
            except ValidationModelError as exc:
                primary = _failed_result(
                    finding,
                    f"validation execution failed: {exc}",
                    stop_reason="model_request",
                )
            except ValidationPhaseError as exc:
                primary = _failed_result(
                    finding, f"validation execution failed: {exc}", stop_reason=exc.stop_reason
                )
            except Exception as exc:
                primary = _failed_result(finding, f"validation execution failed: {exc}")
        else:
            logger.info("validate resume: reusing primary result finding=%s", finding_id)
        raw_results[finding_id] = primary
        if primary.get("disposition") not in {"confirmed", "rejected"}:
            continue
        verifier_directory = verifier_finding_dir(paths, finding_id)
        verifier_directory.mkdir(parents=True, exist_ok=True)
        verifier = _resume_result(verifier_directory / "result.json", finding_id)
        if verifier is None:
            verifier_shell = ShellRunner(
                root=paths.root,
                repository=repository,
                settings=context.settings,
                log_dir=verifier_directory / "attempts" / "0001",
            )
            try:
                verifier = run_verify(
                    context=context,
                    repository=repository,
                    paths=paths,
                    finding=finding,
                    plan=plan,
                    primary=primary,
                    environment=handle,
                    shell=verifier_shell,
                    artifact_dir=verifier_directory,
                    deadline=deadline,
                )
            except ValidationConfigurationError:
                raise
            except ValidationModelError as exc:
                verifier = {
                    "finding_id": finding_id,
                    "id": finding_id,
                    "disposition": "unresolved",
                    "execution_status": "failed",
                    "agent_stop_reason": "model_request",
                    "counterevidence_or_proof_gap": [f"verifier failed: {exc}"],
                    "verifier": {"independent": True, "rerun": False},
                }
            except ValidationPhaseError as exc:
                verifier = {
                    "finding_id": finding_id,
                    "id": finding_id,
                    "disposition": "unresolved",
                    "execution_status": "failed",
                    "agent_stop_reason": exc.stop_reason,
                    "counterevidence_or_proof_gap": [f"verifier failed: {exc}"],
                    "verifier": {"independent": True, "rerun": False},
                }
            except Exception as exc:
                verifier = {
                    "finding_id": finding_id,
                    "id": finding_id,
                    "disposition": "unresolved",
                    "execution_status": "failed",
                    "counterevidence_or_proof_gap": [f"verifier failed: {exc}"],
                    "verifier": {"independent": True, "rerun": False},
                }
        else:
            logger.info("validate resume: reusing verifier result finding=%s", finding_id)
        verifier_results[finding_id] = verifier

    artifact = canonicalize(
        paths=paths,
        run_id=str(state.get("run_id", "")),
        repository=str(repository),
        source_audit=str(audit_file),
        selected=selected,
        raw_results=raw_results,
        verifier_results=verifier_results,
        runtime=runtime,
        repo_commit=repo_commit,
    )
    write_validation(paths, artifact)
    validation.update(artifact)
    validation["status"] = artifact["status"]
    validation["execution_status"] = "completed"
    validation["stop_reason"] = ""
    return artifact


def _failed_result(
    finding: dict[str, Any], reason: str, *, stop_reason: str = ""
) -> dict[str, Any]:
    result = empty_result(finding)
    result["execution_status"] = "failed"
    result["agent_stop_reason"] = stop_reason
    result["counterevidence_or_proof_gap"] = [reason]
    return result


def _load_json_object(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _resume_plan(directory: Path, finding_id: str) -> dict[str, Any] | None:
    value = _load_json_object(directory / "plan.json")
    if value is None:
        return None
    try:
        check_plan(value, finding_id)
    except ValueError:
        return None
    return value


def _resume_result(path: Path, finding_id: str) -> dict[str, Any] | None:
    value = _load_json_object(path)
    if value is None:
        return None
    if str(value.get("finding_id", "")) != finding_id:
        return None
    if value.get("execution_status") != "completed":
        return None
    if not str(value.get("disposition", "")):
        return None
    return value


def _intake_blocked(
    *,
    state: RunState,
    validation: dict[str, Any],
    paths: ValidationPaths,
    runtime: dict[str, Any],
    reason: str,
    message: str = "",
) -> dict[str, Any]:
    selected = list(validation.get("findings", []))
    artifact = canonicalize(
        paths=paths,
        run_id=str(state.get("run_id", "")),
        repository=str(state.get("repository", "")),
        source_audit=str(validation.get("source_audit", "")),
        selected=selected,
        raw_results={},
        verifier_results={},
        runtime=runtime,
        repo_commit=str(validation.get("repo_commit", "")),
    )
    artifact["status"] = "blocked"
    artifact["execution_status"] = "blocked"
    artifact["stop_reason"] = reason
    artifact["errors"] = [message] if message else []
    for item in artifact["findings"]:
        item["counterevidence_or_proof_gap"] = [reason + (f": {message}" if message else "")]
    artifact["gaps"] = [
        {"finding_id": str(item.get("id", "")), "reason": reason}
        for item in artifact["findings"]
    ]
    write_validation(paths, artifact)
    validation.update(artifact)
    return artifact


def _persist(
    paths: ValidationPaths,
    validation: dict[str, Any],
    summary: dict[str, Any],
) -> None:
    validation.update(
        {
            "status": summary.get("status", "failed"),
            "execution_status": summary.get("execution_status", "failed"),
            "stop_reason": summary.get("stop_reason", ""),
            "errors": list(summary.get("errors", [])),
            "gaps": list(summary.get("gaps", [])),
            "runtime": summary.get("runtime", {}),
        }
    )
    write_json(paths.state_file, validation)
    write_json(
        paths.index_file,
        {
            "selected_finding_ids": summary.get("selected_finding_ids", []),
            "findings": [
                {
                    "finding_id": item.get("finding_id", ""),
                    "disposition": item.get("disposition", ""),
                }
                for item in summary.get("findings", [])
            ],
        },
    )


def _selection(validation: dict[str, Any], audit_file: Path) -> dict[str, Any]:
    return {
        "source_audit": str(audit_file),
        "selected_finding_ids": validation.get("selected_finding_ids", []),
        "repo_commit": validation.get("repo_commit", ""),
        "environment": validation.get("environment", {}),
        "runtime": validation.get("runtime", {}),
    }


def _summary(artifact: dict[str, Any], paths: ValidationPaths) -> dict[str, Any]:
    return {
        "status": str(artifact.get("status", "failed")),
        "execution_status": str(artifact.get("execution_status", "failed")),
        "artifact_dir": str(paths.root),
        "state_file": str(paths.state_file),
        "validation_file": str(paths.validation_file),
        "selection_file": str(paths.selection_file),
        "selected_finding_ids": list(artifact.get("selected_finding_ids", [])),
        "counts": artifact.get("counts", {}),
        "runtime": artifact.get("runtime", {}),
        "repo_commit": artifact.get("repo_commit", ""),
        "stop_reason": str(artifact.get("stop_reason", "")),
        "errors": list(artifact.get("errors", [])),
        "gaps": list(artifact.get("gaps", [])),
    }


def _reset(paths: ValidationPaths) -> None:
    for directory in (paths.findings_dir, paths.verifier_dir):
        if directory.exists():
            shutil.rmtree(directory)
    for path in (paths.state_file, paths.validation_file, paths.selection_file, paths.index_file):
        if path.is_file():
            path.unlink()
