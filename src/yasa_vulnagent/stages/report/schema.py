"""State and result schemas for the report stage."""

from __future__ import annotations

import re
from typing import Any, Mapping

ROUTE_KINDS = (
    "email",
    "github_advisory",
    "github_form",
    "web_form",
    "security_policy",
    "unknown",
)
SEVERITIES = ("none", "low", "medium", "high", "critical", "unknown")

REVIEW_CHECKS = (
    "evidence_supports_claim",
    "source_identity_matches",
    "no_fabricated_range_or_fix",
    "cvss_justified",
    "body_self_contained",
    "route_requirements_satisfied",
    "no_sensitive_data",
    "cwe_and_severity_consistent",
)


def finding_key(finding_id: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", str(finding_id)).strip("-")
    return value or "finding"


def empty_state(run_state: Mapping[str, Any], paths: Any) -> dict[str, Any]:
    return {
        "run_id": str(run_state.get("run_id", "")),
        "repo": str(run_state.get("repository", "")),
        "repo_commit": "",
        "current_commit": "",
        "source_validation": "",
        "source_audit": "",
        "validation_status": "",
        "status": "running",
        "execution_status": "running",
        "stop_reason": "",
        "language": "",
        "selected_finding_ids": [],
        "routes": [],
        "findings": [],
        "gaps": [],
        "direct_submit_ready": False,
        "artifact_dir": str(paths.root),
        "state_file": str(paths.state_file),
        "report_file": str(paths.report_file),
        "routes_file": str(paths.routes_file),
        "index_file": str(paths.index_file),
        "usage_file": str(paths.usage_file),
        "summary_file": str(paths.summary_file),
    }


def empty_item(finding_id: str, title: str, *, language: str) -> dict[str, Any]:
    return {
        "id": f"report-{finding_id}",
        "finding_id": finding_id,
        "title": title or finding_id,
        "status": "blocked",
        "body_status": "blocked",
        "route_status": "unknown",
        "format": "github_advisory",
        "language": language,
        "cwe": [],
        "severity": "unknown",
        "audit_severity": "unknown",
        "cvss": {
            "version": "unknown",
            "vector": "",
            "base_score": None,
            "severity": "unknown",
            "justification": "",
        },
        "route": {},
        "subject": "",
        "form_fields": {},
        "body": "",
        "review": {
            "status": "blocked",
            "independent": False,
            "conclusion": "Report material is pending.",
            "checks": {},
            "issues": [],
            "model": "",
            "body_sha256": "",
        },
        "gaps": ["report has not been generated"],
    }
