from __future__ import annotations

import json
from pathlib import Path

from langchain_core.messages import AIMessage

VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def valid_body(*, revision: str = "working-tree", cwe: str = "CWE-78") -> str:
    filler = (
        "The request value crosses the intended security boundary and reaches "
        "the command execution path without an effective guard. "
    ) * 8
    return f"""# Title
Remote command execution in the widget request handler

# Summary

Affected component: `widget/handler.py`. Tested revision: `{revision}`.
The request parameter crosses the command-execution boundary.
Base score: 9.8 (critical). Vector: {VECTOR}.

# Details

## Root cause

The request value is passed to a shell command without quoting. {filler}

## Attack preconditions

The attacker can send an authenticated request to the widget endpoint.

## Expected versus observed behavior

Expected: the value is data, not shell syntax. Observed: the value is executed
as a shell command.

# Proof of concept

## Setup

Start the widget service with the documented test configuration.

## Steps

Send the following request:

```http
POST /widget HTTP/1.1
Host: localhost
Content-Type: application/json

{{"name": "a; id"}}
```

Expected: the name is stored literally. Observed: the response contains the
output of `id`.

## Cleanup

Stop the service and remove the temporary data directory.

# Impact

An authenticated user can run commands as the service account. {cwe} describes
the weakness. {filler}

## Remediation

Pass the value as an argument list instead of a shell string, and add a
regression test that rejects shell metacharacters.

## Regression test

Add a test that sends the same request and asserts that no command output is
returned.
"""


def route_payload() -> dict:
    return {
        "kind": "email",
        "status": "confirmed",
        "source": "SECURITY.md",
        "recipient": "security@example.com",
        "evidence": [
            {
                "source": "SECURITY.md",
                "quote": "Please report vulnerabilities to security@example.com.",
            }
        ],
    }


def draft_payload() -> dict:
    return {
        "title": "Remote command execution in the widget request handler",
        "cwe": ["CWE-78"],
        "severity": "critical",
        "cvss": {
            "version": "3.1",
            "vector": VECTOR,
            "justification": "Network reachable, no privileges, no user interaction, high confidentiality, integrity, and availability impact.",
        },
        "body": valid_body(),
        "subject": "Remote command execution in widget",
    }


def review_payload(*, status: str = "approved") -> dict:
    checks = {
        "evidence_supports_claim": True,
        "source_identity_matches": True,
        "no_fabricated_range_or_fix": True,
        "cvss_justified": True,
        "body_self_contained": True,
        "route_requirements_satisfied": True,
        "no_sensitive_data": True,
        "cwe_and_severity_consistent": True,
    }
    if status != "approved":
        checks["cvss_justified"] = False
    return {
        "status": status,
        "conclusion": "The draft is supported by the supplied validation evidence.",
        "checks": checks,
        "issues": [] if status == "approved" else ["CVSS impact is overstated"],
    }


class ScriptedModel:
    def __init__(self, responses: list) -> None:
        self.responses = list(responses)
        self.seen: list[list] = []

    def bind_tools(self, tools):
        return self

    async def ainvoke(self, messages):
        self.seen.append(list(messages))
        if not self.responses:
            raise AssertionError("unexpected model call")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return AIMessage(
            content=json.dumps(item) if isinstance(item, dict) else str(item),
            usage_metadata={"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
        )


class FatalError(RuntimeError):
    status_code = 401


def make_state(
    root: Path,
    *,
    confirmed: bool = True,
    policy: str | None = (
        "# Security\n\nPlease report vulnerabilities to security@example.com.\n"
    ),
) -> dict:
    repository = root / "repo"
    repository.mkdir()
    if policy is not None:
        (repository / "SECURITY.md").write_text(policy, encoding="utf-8")
    stages = root / "stages"
    (stages / "validate" / "findings" / "finding-1").mkdir(parents=True)
    (stages / "audit").mkdir(parents=True)
    evidence = stages / "validate" / "findings" / "finding-1" / "evidence.txt"
    evidence.write_text("uid=1000(widget) gid=1000(widget)\n", encoding="utf-8")
    audit = {
        "run_id": "run",
        "status": "complete",
        "findings": [
            {
                "id": "finding-1",
                "title": "Remote command execution in the widget request handler",
                "verdict": "confirmed",
                "severity": "critical",
                "confidence": "high",
                "cwe_ids": [78],
                "entry_point": "POST /widget",
                "impact": "arbitrary command execution",
                "prerequisites": ["authenticated request"],
                "violated_invariant": "request data must not become shell syntax",
                "source_to_sink": ["request name", "shell command"],
                "evidence": [
                    {
                        "path": "widget/handler.py",
                        "start_line": 10,
                        "end_line": 14,
                        "code": "run('echo ' + name)",
                        "explanation": "request value reaches the shell",
                    }
                ],
                "reason": "the request value reaches the shell",
                "protected_asset": "host command execution",
                "limitations": [],
            }
        ],
    }
    audit_path = stages / "audit" / "audit.json"
    audit_path.write_text(json.dumps(audit), encoding="utf-8")
    findings = []
    if confirmed:
        findings.append(
            {
                "finding_id": "finding-1",
                "title": "Remote command execution in the widget request handler",
                "disposition": "confirmed",
                "execution_status": "completed",
                "reproduction_level": "integration_test",
                "intended_behavior": {
                    "security_boundary_crossed": "yes",
                    "expected": "store the name literally",
                },
                "observed_result": "the command output is returned",
                "environment": {"runtime": "python", "dependencies": ["flask"]},
                "reproduction": {
                    "setup": ["start the service"],
                    "inputs": ["name=a; id"],
                    "commands": ["send the request"],
                    "expected": "literal name",
                    "observed": "uid=1000",
                    "cleanup": ["stop the service"],
                    "artifacts": ["findings/finding-1/evidence.txt"],
                },
                "evidence": [
                    {
                        "kind": "stdout",
                        "description": "command output",
                        "artifact": "findings/finding-1/evidence.txt",
                    }
                ],
                "verifier": {
                    "independent": True,
                    "rerun": True,
                    "evidence": [],
                    "execution": {"commands": ["rerun"]},
                },
                "agent_stop_reason": "complete",
                "limitations": [],
            }
        )
    validation = {
        "run_id": "run",
        "repo": str(repository),
        "repo_commit": "working-tree",
        "source_audit": str(audit_path),
        "status": "complete",
        "findings": findings,
    }
    validation_path = stages / "validate" / "validation.json"
    validation_path.write_text(json.dumps(validation), encoding="utf-8")
    state = {
        "run_id": "run",
        "repository": str(repository),
        "stages_dir": str(stages),
        "run_file": str(root / "run.json"),
        "stages": [
            {
                "name": "validate",
                "status": "complete",
                "artifact_dir": str(stages / "validate"),
                "artifact_file": str(stages / "validate" / "stage.json"),
            }
        ],
        "config": {},
    }
    (root / "run.json").write_text(json.dumps(state), encoding="utf-8")
    return state
