"""Model-backed route, draft, and review calls for the report stage."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ...workflow.state import RunContext
from .contract import body_sha256
from .model import load_prompt, run_json_call
from .routes import normalize_route, selection


def _payload(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, default=str)


def _source_excerpts(scan_result: dict[str, Any]) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    total = 0
    for source in scan_result.get("sources", []):
        if total >= 50_000 or len(result) >= 10:
            break
        text = str(source.get("text", ""))[:5000]
        total += len(text)
        result.append({"path": source["path"], "text": text})
    return result


def investigate_route(
    context: RunContext,
    model: Any,
    scan_result: dict[str, Any],
    *,
    language: str,
    deadline: float,
    receipt_file: Path,
) -> tuple[dict[str, Any], list[str], dict[str, Any]]:
    user_prompt = _payload(
        {
            "language": language,
            "repository": scan_result.get("repository", ""),
            "github": scan_result.get("github", {}),
            "sources": _source_excerpts(scan_result),
            "candidates": scan_result.get("candidates", []),
            "default_route": scan_result.get("default_route", {}),
        }
    )
    decision = run_json_call(
        context,
        model=model,
        system_prompt=load_prompt("route.md"),
        user_prompt=user_prompt,
        deadline=deadline,
        stage="report.route",
        task_id="route",
        receipt_file=receipt_file,
    )
    route, gaps = normalize_route(decision, scan_result, language=language)
    selected = selection(route, scan_result, language=language)
    return selected, gaps, decision


def draft_advisory(
    context: RunContext,
    model: Any,
    *,
    material: dict[str, Any],
    route: dict[str, Any],
    language: str,
    deadline: float,
    receipt_file: Path,
    violations: list[str] | None = None,
    previous_draft: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "language": language,
        "route": route,
        "audit_cwe": material.get("audit", {}).get("cwe_ids", []),
        "material": material,
    }
    if violations:
        payload["violations"] = list(violations)
        payload["previous_draft"] = previous_draft or {}
        payload["instruction"] = (
            "Repair the previous draft. Fix every listed violation while keeping "
            "all supported facts. Return the complete JSON object again."
        )
    user_prompt = _payload(payload)
    return run_json_call(
        context,
        model=model,
        system_prompt=load_prompt("draft.md"),
        user_prompt=user_prompt,
        deadline=deadline,
        stage="report.draft",
        task_id=str(material.get("finding_id", "finding")),
        receipt_file=receipt_file,
    )


def review_advisory(
    context: RunContext,
    model: Any,
    *,
    material: dict[str, Any],
    draft: dict[str, Any],
    route: dict[str, Any],
    language: str,
    deadline: float,
    receipt_file: Path,
) -> dict[str, Any]:
    user_prompt = _payload(
        {
            "language": language,
            "route": route,
            "material": material,
            "draft": {
                "title": draft.get("title", ""),
                "cwe": draft.get("cwe", []),
                "severity": draft.get("severity", ""),
                "cvss": draft.get("cvss", {}),
                "body": draft.get("body", ""),
            },
        }
    )
    review = run_json_call(
        context,
        model=model,
        system_prompt=load_prompt("review.md"),
        user_prompt=user_prompt,
        deadline=deadline,
        stage="report.review",
        task_id=f"{material.get('finding_id', 'finding')}-review",
        receipt_file=receipt_file,
    )
    review["independent"] = True
    review["model"] = str(getattr(model, "model_name", "") or "")
    if str(draft.get("body") or ""):
        review["body_sha256"] = body_sha256(str(draft.get("body")))
    return review

