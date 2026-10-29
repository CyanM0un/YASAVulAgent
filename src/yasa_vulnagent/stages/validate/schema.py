"""State and result schemas for the validate stage."""

from __future__ import annotations

import re
from typing import Any, Mapping

DISPOSITIONS = ("confirmed", "rejected", "unresolved")
MODES = ("http", "cli", "test_case", "library_api", "service")
LEVELS = ("public_interface", "integration_test", "subsystem", "internal_auxiliary", "not_attempted")
TERMINAL = ("confirmed", "rejected")


def empty_state(run_state: Mapping[str, Any], paths: Any) -> dict[str, Any]:
    return {
        "run_id": str(run_state.get("run_id", "")),
        "repository": str(run_state.get("repository", "")),
        "run_file": str(run_state.get("run_file", "")),
        "source_audit": "",
        "selected_finding_ids": [],
        "findings": [],
        "repo_commit": "",
        "runtime": {},
        "status": "running",
        "execution_status": "running",
        "stop_reason": "",
        "errors": [],
        "warnings": [],
        "gaps": [],
        "artifact_dir": str(paths.root),
        "state_file": str(paths.state_file),
        "validation_file": str(paths.validation_file),
        "selection_file": str(paths.selection_file),
        "index_file": str(paths.index_file),
        "usage_file": str(paths.usage_file),
    }


def finding_key(finding_id: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", str(finding_id)).strip("-")
    return value or "finding"


def empty_result(finding: Mapping[str, Any]) -> dict[str, Any]:
    finding_id = str(finding.get("id", ""))
    return {
        "id": finding_id,
        "finding_id": finding_id,
        "title": str(finding.get("title", "")) or str(finding.get("id", "")) or "finding",
        "disposition": "unresolved",
        "execution_status": "not_started",
        "agent_stop_reason": "",
        "validation_method": "runtime validation",
        "reproduction_level": "not_attempted",
        "rubric": ["runtime behavior compared with the finding's intended boundary"],
        "intended_behavior": {
            "summary": str(finding.get("violated_invariant", "")),
            "legitimate_actor": "not recorded",
            "legitimate_resource": "not recorded",
            "expected_capability": "not recorded",
            "security_boundary": "not recorded",
            "security_boundary_crossed": "unknown",
        },
        "observed_result": "not run",
        "environment": {},
        "reproduction": {},
        "evidence": [],
        "negative_controls": [],
        "counterevidence_or_proof_gap": [],
        "verifier": {"independent": False, "rerun": False, "evidence": []},
        "artifacts": [],
    }
