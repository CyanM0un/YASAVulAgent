"""Run the report stage and persist local submission materials."""

from __future__ import annotations

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
from ..validate.environment.storage import git_revision
from .agent import draft_advisory, investigate_route, review_advisory
from .contract import (
    body_errors,
    body_sha256,
    body_score_errors,
    cwe_errors,
    cvss_value,
    derive_fields,
    redact,
    review_errors,
    section,
)
from .intake import (
    ReportInputError,
    load_audit,
    load_validation,
    material,
    select_findings,
)
from .model import (
    ReportConfigurationError,
    ReportModelError,
    ReportPhaseError,
    build_model,
)
from .routes import scan, selection
from .schema import empty_item, empty_state, finding_key
from .storage import (
    ReportPaths,
    ensure_dirs,
    finding_dir,
    read_json,
    report_paths,
    write_json,
    write_text,
)


logger = logging.getLogger(__name__)


@trace_node("workflow.report")
def run_stage(
    state: RunState,
    runtime: Runtime[RunContext] | None = None,
) -> dict[str, object]:
    context = runtime.context if runtime is not None else RunContext(settings=load_settings())
    settings = context.settings
    usage = context.usage or UsageRecorder(settings.usage_price_table)
    if settings.report_max_total_tokens > 0 or settings.report_max_total_cost > 0:
        usage.configure_limits(
            max_tokens=settings.report_max_total_tokens or None,
            max_cost=settings.report_max_total_cost or None,
        )
    context = replace(context, usage=usage)
    started_at = utc_now()
    paths = report_paths(state["stages_dir"])
    ensure_dirs(paths)
    start_update = record_stage(
        "report",
        state,
        status="running",
        message="report generation is running.",
        started_at=started_at,
        details={"state_file": str(paths.state_file)},
    )
    running_state: RunState = {**state, **start_update}
    report = empty_state(running_state, paths)
    report["language"] = settings.report_language
    write_json(paths.state_file, report)
    explicit = [
        str(item) for item in (running_state.get("report_finding_ids") or [])
    ]
    rerun = bool(running_state.get("report_rerun"))

    try:
        report = _run_report(
            context,
            running_state,
            paths,
            explicit=explicit,
            rerun=rerun,
        )
    except ReportInputError as exc:
        report = _blocked_report(running_state, paths, str(exc), "report_input")
    except ReportConfigurationError as exc:
        report = _blocked_report(running_state, paths, str(exc), "model_configuration")
    except ReportModelError as exc:
        report = _blocked_report(running_state, paths, str(exc), exc.stop_reason)
    except ReportPhaseError as exc:
        report = _blocked_report(
            running_state, paths, str(exc), exc.stop_reason or "model_response"
        )
    except Exception as exc:  # pragma: no cover - defensive stage boundary
        logger.exception("report stage failed")
        report = _failed_report(running_state, paths, str(exc))
    finally:
        usage.write(paths.usage_file, stage_prefix="report")

    report["report_file"] = str(paths.report_file)
    report["routes_file"] = str(paths.routes_file)
    report["index_file"] = str(paths.index_file)
    report["usage_file"] = str(paths.usage_file)
    report["summary_file"] = str(paths.summary_file)
    write_json(paths.report_file, report)
    write_text(paths.summary_file, _summary_text(report))
    write_json(paths.index_file, _index(report, paths))
    write_json(paths.state_file, report)

    status = str(report.get("status", "failed"))
    summary = _stage_summary(report, paths)
    update = record_stage(
        "report",
        running_state,
        status=status,
        message=_status_message(report),
        started_at=started_at,
        details=summary,
    )
    update["status"] = status
    update["finished_at"] = utc_now()
    update["report"] = summary
    save_state({**running_state, **update})
    return update


def run_report(
    run_file: Path,
    *,
    finding_ids: list[str] | None = None,
    rerun: bool = False,
) -> RunState:
    """Run report generation from an existing run whose validate stage is usable."""
    run_file = Path(run_file).expanduser().resolve()
    state = load_state(run_file)
    records = [item for item in state.get("stages", []) if item.get("name") == "validate"]
    if not records or records[-1].get("status") not in {"complete", "partial"}:
        raise ValueError(
            "report requires an existing run with a complete or partial validate stage"
        )
    state = {
        **state,
        "report_finding_ids": list(finding_ids or []),
        "report_rerun": bool(rerun),
    }
    save_state(state)
    session = start_run_logging(run_file)
    session.progress.start("workflow.report_resume", run_file=str(run_file))
    try:
        update = run_stage(
            state,
            runtime=Runtime(
                context=RunContext(settings=load_settings(), progress=session.progress)
            ),
        )
        session.progress.finish(
            "workflow.report_resume",
            status=str(update.get("report", {}).get("status", "failed")),
        )
        return {**state, **update}
    except Exception as exc:
        session.progress.finish(
            "workflow.report_resume",
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


def _run_report(
    context: RunContext,
    state: RunState,
    paths: ReportPaths,
    *,
    explicit: list[str],
    rerun: bool,
) -> dict[str, Any]:
    settings = context.settings
    if rerun:
        _reset(paths)
    deadline = time.monotonic() + max(1, settings.report_total_timeout)
    validation, validation_path = load_validation(state)
    audit = load_audit(validation, validation_path.parents[2])
    selected, omitted = select_findings(
        validation, explicit, limit=settings.report_max_findings
    )

    repository = Path(str(state["repository"]))
    validation_commit = str(validation.get("repo_commit") or "")
    current_commit = git_revision(repository) if repository.is_dir() else "working-tree"
    language = settings.report_language
    report = empty_state(state, paths)
    report.update(
        {
            "repo": str(repository),
            "repo_commit": validation_commit,
            "current_commit": current_commit,
            "source_validation": str(validation_path),
            "source_audit": str(validation.get("source_audit") or ""),
            "validation_status": str(validation.get("status") or ""),
            "language": language,
            "selected_finding_ids": [
                str(item.get("finding_id") or item.get("id") or "") for item in selected
            ],
        }
    )
    gaps: list[dict[str, Any]] = []
    if omitted:
        gaps.append(
            {
                "id": "report-cap",
                "reason": f"{omitted} confirmed findings were omitted by REPORT_MAX_FINDINGS",
                "finding_ids": [],
            }
        )
    if current_commit != validation_commit:
        gaps.append(
            {
                "id": "source-drift",
                "reason": (
                    f"current checkout is {current_commit}, validation ran on "
                    f"{validation_commit}; the advisory must state the tested revision"
                ),
                "finding_ids": [],
            }
        )
    report["gaps"] = gaps

    if not selected:
        report["status"] = "complete"
        report["execution_status"] = "completed"
        report["direct_submit_ready"] = False
        return report

    model = build_model(context)
    route, route_gaps, scan_result = _route(
        context,
        model,
        state,
        paths,
        validation_commit,
        language,
        rerun,
        deadline,
    )
    report["routes"] = scan_result.get("candidates", []) + [route]
    report["language"] = str(route.get("language") or language)
    for gap in route_gaps:
        gaps.append({"id": "route", "reason": gap, "finding_ids": []})

    for finding in selected:
        item = _generate_item(
            context,
            model,
            state,
            paths,
            finding,
            audit,
            route,
            language,
            validation_commit,
            current_commit,
            deadline,
        )
        report["findings"].append(item)

    ready = sum(item["status"] == "ready" for item in report["findings"])
    body_ready = sum(item.get("body_status") == "ready" for item in report["findings"])
    if ready == len(report["findings"]):
        report["status"] = "complete"
    elif ready or body_ready:
        report["status"] = "partial"
    else:
        report["status"] = "blocked"
    report["execution_status"] = "completed"
    report["direct_submit_ready"] = bool(report["findings"]) and all(
        item["status"] == "ready" and item.get("route", {}).get("status") == "confirmed"
        for item in report["findings"]
    )
    report["gaps"] = gaps
    return report


def _route(
    context: RunContext,
    model: Any,
    state: RunState,
    paths: ReportPaths,
    repo_commit: str,
    language: str,
    rerun: bool,
    deadline: float,
) -> tuple[dict[str, Any], list[str], dict[str, Any]]:
    scan_result = scan(Path(str(state["repository"])))
    if not rerun:
        cached = read_json(paths.routes_file)
        if (
            isinstance(cached, dict)
            and cached.get("repo_commit") == repo_commit
            and cached.get("language") == language
            and isinstance(cached.get("selected"), dict)
        ):
            return cached["selected"], list(cached.get("gaps", [])), scan_result
    try:
        route, gaps, decision = investigate_route(
            context,
            model,
            scan_result,
            language=language,
            deadline=deadline,
            receipt_file=paths.root / "routes.agent.json",
        )
    except (ReportModelError, ReportPhaseError) as exc:
        if getattr(exc, "stop_reason", "") == "model_configuration":
            raise
        gaps = [f"route investigation failed: {exc}"]
        route = selection(scan_result["default_route"], scan_result, language=language)
        decision = {}
    write_json(
        paths.routes_file,
        {
            "repo_commit": repo_commit,
            "language": language,
            "scan": {
                "sources": [item["path"] for item in scan_result.get("sources", [])],
                "emails": scan_result.get("emails", []),
                "urls": scan_result.get("urls", []),
                "github": scan_result.get("github", {}),
            },
            "candidates": scan_result.get("candidates", []),
            "decision": decision,
            "selected": route,
            "gaps": gaps,
        },
    )
    return route, gaps, scan_result


def _generate_item(
    context: RunContext,
    model: Any,
    state: RunState,
    paths: ReportPaths,
    finding: dict[str, Any],
    audit: dict[str, Any],
    route: dict[str, Any],
    language: str,
    validation_commit: str,
    current_commit: str,
    deadline: float,
) -> dict[str, Any]:
    finding_id = str(finding.get("finding_id") or finding.get("id") or "")
    title = str(finding.get("title") or finding_id)
    language = str(route.get("language") or language)
    item = empty_item(finding_id, title, language=language)
    item["route"] = dict(route)
    item["route_status"] = str(route.get("status") or "unknown")
    item["format"] = _format(route)
    directory = finding_dir(paths, finding_id)
    directory.mkdir(parents=True, exist_ok=True)

    bundle, material_gaps = material(
        finding,
        audit,
        validation_root=Path(str(state["stages_dir"])) / "validate",
        repo_commit=validation_commit,
        current_commit=current_commit,
    )
    item["audit_severity"] = str(bundle["audit"].get("severity") or "unknown")
    write_json(directory / "material.json", bundle)
    if material_gaps:
        item["status"] = "blocked"
        item["gaps"] = material_gaps
        return item
    item["gaps"] = []

    rerun = bool(state.get("report_rerun"))
    draft = read_json(directory / "draft.json") if not rerun else None
    canonical, errors = _draft_contract(draft, bundle)
    if errors or draft is None:
        try:
            draft = draft_advisory(
                context,
                model,
                material=bundle,
                route=route,
                language=language,
                deadline=deadline,
                receipt_file=directory / "draft.agent.json",
            )
        except (ReportModelError, ReportPhaseError) as exc:
            item["status"] = _failure_status(exc)
            item["gaps"] = [f"draft request failed: {exc}"]
            return item
        canonical, errors = _draft_contract(draft, bundle)
        if errors:
            try:
                draft = draft_advisory(
                    context,
                    model,
                    material=bundle,
                    route=route,
                    language=language,
                    deadline=deadline,
                    receipt_file=directory / "draft-repair.agent.json",
                    violations=errors,
                    previous_draft=draft,
                )
            except (ReportModelError, ReportPhaseError) as exc:
                item["status"] = "blocked"
                item["gaps"] = [f"draft repair request failed: {exc}"]
                return item
            canonical, errors = _draft_contract(draft, bundle)
        if errors:
            item["status"] = "blocked"
            item["gaps"] = errors
            return item
    if canonical is None:
        item["status"] = "blocked"
        item["gaps"] = errors or ["draft is not usable"]
        return item
    write_json(directory / "draft.json", canonical)
    item.update(
        {
            "title": canonical["title"],
            "cwe": canonical["cwe"],
            "severity": canonical["cvss"]["severity"],
            "cvss": canonical["cvss"],
            "body": canonical["body"],
            "body_status": "ready",
        }
    )

    review = read_json(directory / "review.json") if not rerun else None
    if not _review_usable(review, canonical["body"]):
        try:
            review = review_advisory(
                context,
                model,
                material=bundle,
                draft=canonical,
                route=route,
                language=language,
                deadline=deadline,
                receipt_file=directory / "review.agent.json",
            )
        except (ReportModelError, ReportPhaseError) as exc:
            item["status"] = _failure_status(exc)
            item["gaps"] = [f"review request failed: {exc}"]
            _write_item_artifacts(paths, item)
            return item
        review["body_sha256"] = body_sha256(canonical["body"])
        write_json(directory / "review.json", review)
    review_errors_list = review_errors(review)
    item["review"] = _review_value(review)
    if review_errors_list:
        item["status"] = "blocked"
        item["gaps"] = review_errors_list
        _write_item_artifacts(paths, item)
        return item

    item["subject"] = _subject(route, canonical)
    if item["format"] != "email":
        item["form_fields"] = derive_fields(canonical["body"])
        required = [
            str(value).strip()
            for value in route.get("required_fields", [])
            if str(value).strip()
        ]
        missing = [field for field in required if field not in item["form_fields"]]
        if missing:
            item["gaps"] = [
                "route requires fields that are not in the standard advisory body: "
                + ", ".join(sorted(set(missing)))
            ]
            item["status"] = "pending"
    route_gaps = _route_requirement_gaps(route, canonical["body"])
    if route_gaps:
        item["gaps"] = route_gaps
        item["status"] = "pending"
    if item["route_status"] == "unknown":
        item["status"] = "pending"
        item["gaps"] = [
            "submission route is unresolved; the full local body is retained"
        ]
    if item["status"] != "pending":
        item["status"] = "ready"
    _write_item_artifacts(paths, item)
    return item


def _draft_contract(
    draft: Any, bundle: dict[str, Any]
) -> tuple[dict[str, Any] | None, list[str]]:
    if not isinstance(draft, dict):
        return None, ["draft is not an object"]
    errors: list[str] = []
    title = str(draft.get("title") or "").strip()
    if not title:
        errors.append("title is required")
    cwe = (
        [str(item).strip().upper() for item in draft.get("cwe", [])]
        if isinstance(draft.get("cwe"), list)
        else []
    )
    errors.extend(cwe_errors(bundle["audit"].get("cwe_ids", []), cwe))
    value, cvss_errors = cvss_value(draft.get("cvss"))
    errors.extend(cvss_errors)
    body = redact(str(draft.get("body") or ""))
    errors.extend(body_errors(body))
    if title and section(body, "Title").strip() != title:
        errors.append("body title does not match the draft title")
    if value is not None:
        errors.extend(body_score_errors(body, value))
        declared = str(draft.get("severity") or "").lower().strip()
        if declared and declared != value["severity"]:
            errors.append(
                f"declared severity {declared} does not match the recalculated "
                f"severity {value['severity']}"
            )
    if errors or value is None:
        return None, errors
    return {
        "title": title,
        "cwe": cwe,
        "severity": value["severity"],
        "cvss": value,
        "body": body,
        "subject": str(draft.get("subject") or "").strip(),
    }, []


def _failure_status(error: Exception) -> str:
    reason = getattr(error, "stop_reason", "")
    return "pending" if reason in {"time_budget", "token_budget", "cost_budget"} else "blocked"


def _review_usable(review: Any, body: str) -> bool:
    return (
        isinstance(review, dict)
        and review.get("status") == "approved"
        and review.get("body_sha256") == body_sha256(body)
        and not review_errors(review)
    )


def _review_value(review: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": str(review.get("status") or "blocked"),
        "independent": review.get("independent") is True,
        "conclusion": str(review.get("conclusion") or ""),
        "checks": review.get("checks") if isinstance(review.get("checks"), dict) else {},
        "issues": review.get("issues") if isinstance(review.get("issues"), list) else [],
        "model": str(review.get("model") or ""),
        "body_sha256": str(review.get("body_sha256") or ""),
    }


def _route_requirement_gaps(route: dict[str, Any], body: str) -> list[str]:
    gaps: list[str] = []
    limit = route.get("length_limit")
    if isinstance(limit, int) and limit > 0 and len(body) > limit:
        gaps.append(f"route length limit {limit} is exceeded by the body")
    encryption = str(route.get("encryption") or "").strip().lower()
    if encryption and encryption not in {"none", "no", "n/a", "not required", "optional"}:
        gaps.append(
            "route requires encryption or a PGP key; prepare the protected package manually"
        )
    if route.get("attachment_rules"):
        gaps.append(
            "route has attachment rules; prepare the attachment package manually"
        )
    return gaps


def _format(route: dict[str, Any]) -> str:
    kind = str(route.get("kind") or "")
    return (
        kind
        if kind in {"email", "github_advisory", "github_form", "web_form"}
        else "github_advisory"
    )


def _subject(route: dict[str, Any], draft: dict[str, Any]) -> str:
    if _format(route) != "email":
        return ""
    return (
        str(draft.get("subject") or "").strip()
        or str(route.get("subject_template") or "").strip()
        or f"Security report: {draft['title']}"
    )


def _write_item_artifacts(paths: ReportPaths, item: dict[str, Any]) -> None:
    find_id = str(item["finding_id"])
    item["artifacts"] = [
        str(paths.submissions_dir / f"{finding_key(find_id)}.md"),
        str(paths.submissions_dir / f"{finding_key(find_id)}.json"),
    ]
    if item.get("body_status") == "ready" and item.get("body"):
        _write_submission(paths, item)


def _write_submission(paths: ReportPaths, item: dict[str, Any]) -> None:
    find_id = str(item["finding_id"])
    name = finding_key(find_id)
    write_text(paths.submissions_dir / f"{name}.md", item["body"])
    write_json(
        paths.submissions_dir / f"{name}.json",
        {
            "finding_id": find_id,
            "format": item["format"],
            "route": item["route"],
            "recipient": item["route"].get("recipient", ""),
            "subject": item["subject"],
            "form_fields": item["form_fields"],
            "body_sha256": body_sha256(item["body"]),
            "body_file": str(paths.submissions_dir / f"{name}.md"),
            "status": item["status"],
        },
    )


def _reset(paths: ReportPaths) -> None:
    for directory in (paths.findings_dir, paths.submissions_dir):
        shutil.rmtree(directory, ignore_errors=True)
    for path in (
        paths.report_file,
        paths.routes_file,
        paths.index_file,
        paths.summary_file,
        paths.state_file,
    ):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    ensure_dirs(paths)


def _blocked_report(
    state: RunState, paths: ReportPaths, reason: str, stop_reason: str
) -> dict[str, Any]:
    report = empty_state(state, paths)
    report["status"] = "blocked"
    report["execution_status"] = "blocked"
    report["stop_reason"] = stop_reason
    report["language"] = state.get("config", {}).get("report_language", "en")
    report["gaps"] = [{"id": "report-input", "reason": reason, "finding_ids": []}]
    return report


def _failed_report(state: RunState, paths: ReportPaths, reason: str) -> dict[str, Any]:
    report = empty_state(state, paths)
    report["status"] = "failed"
    report["execution_status"] = "failed"
    report["stop_reason"] = "internal_error"
    report["language"] = state.get("config", {}).get("report_language", "en")
    report["gaps"] = [{"id": "report-internal", "reason": reason, "finding_ids": []}]
    return report


def _status_message(report: dict[str, Any]) -> str:
    status = report.get("status")
    if status == "complete":
        return "report materials are complete."
    if status == "partial":
        return "report materials are partial; inspect per-finding gaps."
    if status == "blocked":
        return "report generation is blocked; inspect the report gaps."
    return "report generation failed."


def _stage_summary(report: dict[str, Any], paths: ReportPaths) -> dict[str, Any]:
    findings = report.get("findings", [])
    return {
        "status": report.get("status"),
        "execution_status": report.get("execution_status"),
        "stop_reason": report.get("stop_reason", ""),
        "report_file": str(paths.report_file),
        "summary_file": str(paths.summary_file),
        "selected_finding_ids": report.get("selected_finding_ids", []),
        "ready": sum(item.get("status") == "ready" for item in findings),
        "blocked": sum(item.get("status") == "blocked" for item in findings),
        "pending": sum(item.get("status") == "pending" for item in findings),
        "direct_submit_ready": bool(report.get("direct_submit_ready")),
    }


def _index(report: dict[str, Any], paths: ReportPaths) -> dict[str, Any]:
    return {
        "run_id": report.get("run_id", ""),
        "status": report.get("status", ""),
        "report_file": str(paths.report_file),
        "summary_file": str(paths.summary_file),
        "selected_finding_ids": report.get("selected_finding_ids", []),
        "submissions": [
            str(paths.submissions_dir / f"{finding_key(str(item.get('finding_id', '')))}.md")
            for item in report.get("findings", [])
            if item.get("body_status") == "ready"
        ],
        "counts": {
            "selected": len(report.get("selected_finding_ids", [])),
            "ready": sum(
                item.get("status") == "ready" for item in report.get("findings", [])
            ),
            "blocked": sum(
                item.get("status") == "blocked" for item in report.get("findings", [])
            ),
            "pending": sum(
                item.get("status") == "pending" for item in report.get("findings", [])
            ),
        },
    }


def _summary_text(report: dict[str, Any]) -> str:
    lines = [
        "# Report summary",
        "",
        f"- Run: `{report.get('run_id', '')}`",
        f"- Repository: `{report.get('repo', '')}`",
        f"- Tested revision: `{report.get('repo_commit', '')}`",
        f"- Validation: `{report.get('validation_status', '')}`",
        f"- Status: `{report.get('status', '')}`",
        f"- Direct submit ready: `{str(bool(report.get('direct_submit_ready'))).lower()}`",
        "",
        "This stage only writes local draft materials. It never sends mail, opens an",
        "advisory, or calls a submission API.",
        "",
        "| Finding | Status | Route | CVSS | Gaps |",
        "| --- | --- | --- | --- | --- |",
    ]
    for item in report.get("findings", []):
        cvss = item.get("cvss") or {}
        score = cvss.get("base_score")
        gaps = "; ".join(str(gap) for gap in item.get("gaps", [])) or ""
        row = [
            str(item.get("finding_id", "")),
            str(item.get("status", "")),
            str(item.get("route_status", "")),
            f"{score} ({cvss.get('severity', '')})" if score is not None else "unknown",
            gaps,
        ]
        lines.append("| " + " | ".join(value.replace("|", "\\|") for value in row) + " |")
    if not report.get("findings"):
        lines.append(
            f"| none | {report.get('status', '')} | - | - | no confirmed finding selected |"
        )
    top_gaps = report.get("gaps", [])
    if top_gaps:
        lines.extend(["", "## Gaps", ""])
        for gap in top_gaps:
            lines.append(f"- {gap.get('reason', '')}")
    lines.extend(["", "## Submissions", ""])
    submissions = [
        item for item in report.get("findings", []) if item.get("body_status") == "ready"
    ]
    if submissions:
        for item in submissions:
            lines.append(
                f"- `submissions/{finding_key(str(item.get('finding_id', '')))}.md`"
            )
    else:
        lines.append("- none")
    return "\n".join(lines) + "\n"
