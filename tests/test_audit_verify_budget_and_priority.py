from __future__ import annotations

import asyncio
import json
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from yasa_vulnagent.config import (
    DEFAULT_AUDIT_VERIFY_RESERVE,
    DEFAULT_VALIDATE_CANDIDATE_FALLBACK_LIMIT,
    Settings,
    load_settings,
)
from yasa_vulnagent.stages.audit.budget import AuditBudget
from yasa_vulnagent.stages.audit.gate.node import gate
from yasa_vulnagent.stages.audit.verify.execution import VerifyExecution, run_verify_stage
from yasa_vulnagent.stages.audit.verify.priority import (
    candidate_score,
    fallback_eligible_candidates,
    is_negative_observation,
    prioritize_candidates,
)
from yasa_vulnagent.stages.validate.intake import select_findings
from yasa_vulnagent.workflow.state import RunContext


def _cand(
    finding_id: str,
    *,
    category: str = "identity_authentication_authorization",
    completeness: str = "complete",
    reachability: str = "reachable",
    triggerability: str = "triggerable",
    title: str = "Auth bypass allows arbitrary access",
    prerequisites: list[str] | None = None,
    missing_facts: list[str] | None = None,
    cwe_ids: list[int] | None = None,
    evidence: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "id": finding_id,
        "verdict": "candidate",
        "category": category,
        "completeness": completeness,
        "reachability": reachability,
        "triggerability": triggerability,
        "title": title,
        "prerequisites": list(prerequisites or []),
        "missing_facts": list(missing_facts or []),
        "cwe_ids": [89] if cwe_ids is None else list(cwe_ids),
        "evidence": [{"path": "a.py", "start_line": 1, "end_line": 2}, {"path": "a.py", "start_line": 5, "end_line": 6}]
        if evidence is None
        else list(evidence),
    }


class AuditVerifyBudgetAndPriorityTest(unittest.TestCase):
    def test_defaults_and_budget_verify_reserve(self) -> None:
        self.assertEqual(DEFAULT_AUDIT_VERIFY_RESERVE, 900)
        self.assertEqual(DEFAULT_VALIDATE_CANDIDATE_FALLBACK_LIMIT, 0)

        now = time.monotonic()
        budget_large = AuditBudget(deadline=now + 3600, started_at=now)
        self.assertAlmostEqual(budget_large.effective_verify_reserve(900), 900.0, delta=0.1)
        self.assertAlmostEqual(budget_large.trace_deadline(900), now + 2700.0, delta=0.1)
        self.assertFalse(budget_large.trace_expired(900))

        # Small timeout clamps reserve to 40% so trace is never starved.
        budget_small = AuditBudget(deadline=now + 300, started_at=now)
        self.assertAlmostEqual(budget_small.effective_verify_reserve(900), 120.0, delta=0.1)
        self.assertAlmostEqual(budget_small.trace_deadline(900), now + 180.0, delta=0.1)

        # Zero reserve disables reservation.
        self.assertEqual(budget_large.effective_verify_reserve(0), 0.0)
        self.assertEqual(budget_large.trace_deadline(0), budget_large.deadline)

        # Already inside reserve window -> trace_expired True, budget.expired False.
        budget_in_reserve = AuditBudget(deadline=now + 500, started_at=now - 3100)
        self.assertTrue(budget_in_reserve.trace_expired(900))
        self.assertFalse(budget_in_reserve.expired())

    def test_prioritize_candidates_interleaves_categories_and_demotes_negative_observations(self) -> None:
        neg = _cand(
            "f-neg",
            category="injection_interpretation",
            title="All /v1/users routes are behind auth middlewares; no route-level or branch-level path was found, precondition is not satisfied.",
        )
        auth1 = _cand("f-auth-1", category="identity_authentication_authorization")
        auth2 = _cand("f-auth-2", category="identity_authentication_authorization")
        auth3 = _cand("f-auth-3", category="identity_authentication_authorization")
        inj1 = _cand("f-inj-1", category="injection_interpretation")
        ssrf1 = _cand("f-ssrf-1", category="network_protocol_boundaries")
        weak = _cand(
            "f-weak",
            category="injection_interpretation",
            completeness="source_only",
            reachability="unknown",
            triggerability="unknown",
        )

        self.assertTrue(is_negative_observation(neg))
        self.assertGreater(candidate_score(inj1), candidate_score(weak))
        self.assertGreater(candidate_score(auth1), candidate_score(neg))

        ordered = prioritize_candidates([auth1, auth2, auth3, neg, weak, ssrf1, inj1])
        ids = [item["id"] for item in ordered]
        # Tier-1 categories (injection & ssrf) and top authz must appear in the first 3 slots.
        self.assertIn("f-inj-1", ids[:3])
        self.assertIn("f-ssrf-1", ids[:3])
        self.assertIn("f-auth-1", ids[:3])
        # Negative observation must be pushed to the very end.
        self.assertEqual(ids[-1], "f-neg")

    def test_verify_budget_exhausted_reports_distinct_stop_reason(self) -> None:
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def no_yasa(*_args, **_kwargs):
            yield None

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            (repo / "app.py").write_text("x = input()\neval(x)\n", encoding="utf-8")
            audit_dir = root / "stages" / "audit"
            audit_dir.mkdir(parents=True)
            trace_file = audit_dir / "traces" / "trace-1.json"
            trace_file.parent.mkdir(parents=True)
            trace_file.write_text(
                json.dumps(
                    {
                        "id": "trace-1",
                        "task_id": "task-1",
                        "status": "complete",
                        "flows": [
                            {
                                "id": "flow-1",
                                "category": "injection_interpretation",
                                "kind": "dataflow",
                                "summary": "Command execution via eval",
                                "completeness": "complete",
                                "reachability": "reachable",
                                "triggerability": "triggerable",
                                "source": {"summary": "input", "evidence": [{"path": "app.py", "start_line": 1, "end_line": 1}]},
                                "sink": {"summary": "eval", "evidence": [{"path": "app.py", "start_line": 2, "end_line": 2}]},
                                "evidence": [
                                    {"path": "app.py", "start_line": 1, "end_line": 1, "explanation": "src"},
                                    {"path": "app.py", "start_line": 2, "end_line": 2, "explanation": "sink"},
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            audit_payload = {
                "run_id": "run-1",
                "repository": str(repo),
                "mode": "entries",
                "scope": {"files": ["app.py"]},
                "tasks": [{"id": "task-1", "kind": "entry", "status": "complete", "paths": ["app.py"]}],
                "traces": [{"id": "trace-1", "task_id": "task-1", "status": "complete", "artifact_file": "traces/trace-1.json"}],
                "findings": [],
                "reviews": [],
            }
            (audit_dir / "audit.json").write_text(json.dumps(audit_payload), encoding="utf-8")
            state = {
                "run_id": "run-1",
                "repository": str(repo),
                "artifact_dir": str(audit_dir),
                "mode": "entries",
            }
            context = RunContext(
                settings=Settings(api_key=None, base_url="http://localhost", model="fake"),
                model=object(),
                audit_budget=AuditBudget(deadline=0, started_at=0),
            )
            with patch.object(VerifyExecution, "run_agent") as run_agent, patch(
                "yasa_vulnagent.stages.audit.verify.execution.open_yasa_mcp",
                no_yasa,
            ):
                result = asyncio.run(run_verify_stage(state, context))
            run_agent.assert_not_called()
            self.assertEqual(result["stop_reason"], "verify_budget_exhausted")
            self.assertEqual(result["verify"]["stop_reason"], "verify_budget_exhausted")
            self.assertEqual(result["verify"]["model"]["status"], "not_run")
            self.assertEqual(result["verify"]["deferred_count"], 1)

    def test_gate_redirects_trace_to_verify_inside_verify_reserve(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
            audit_dir = root / "stages" / "audit"
            audit_dir.mkdir(parents=True)
            audit_payload = {
                "run_id": "run-1",
                "repository": str(repo),
                "mode": "entries",
                "scope": {"files": ["app.py"]},
                "tasks": [
                    {"id": "t1", "kind": "entry", "status": "deferred", "paths": ["app.py"]},
                ],
                "findings": [_cand("f-1")],
                "reviews": [],
                "traces": [],
            }
            (audit_dir / "audit.json").write_text(json.dumps(audit_payload), encoding="utf-8")
            now = time.monotonic()
            budget = AuditBudget(deadline=now + 400, started_at=now - 3200)
            settings = replace(load_settings(), audit_timeout=3600, audit_verify_reserve=900)
            context = RunContext(settings=settings, audit_budget=budget)
            state = {
                "run_id": "run-1",
                "repository": str(repo),
                "artifact_dir": str(audit_dir),
                "mode": "entries",
                "framework": {"visits": {}},
            }
            out = gate(state, SimpleNamespace(context=context))  # type: ignore[arg-type]
            self.assertEqual(out["next_action"], "verify")

    def test_validate_select_findings_opt_in_candidate_fallback(self) -> None:
        audit = {
            "findings": [
                _cand("f-weak", completeness="source_only", reachability="unknown", triggerability="unknown"),
                _cand("f-neg", title="No bypass was found; properly enforced by middleware."),
                _cand("f-good-1", category="injection_interpretation"),
                _cand("f-good-2", category="network_protocol_boundaries"),
            ]
        }
        # Default limit=0 returns empty.
        self.assertEqual(select_findings(audit), [])
        # Opt-in limit=1 picks only the top qualified candidate and excludes weak/negative items.
        picked = select_findings(audit, candidate_fallback_limit=1)
        self.assertEqual(len(picked), 1)
        self.assertEqual(picked[0]["id"], "f-good-1")

        # When verified findings exist, fallback is NOT triggered.
        audit_with_confirmed = {
            "findings": [
                {"id": "f-conf", "verdict": "confirmed"},
                _cand("f-good-1", category="injection_interpretation"),
            ]
        }
        self.assertEqual(
            [item["id"] for item in select_findings(audit_with_confirmed, candidate_fallback_limit=3)],
            ["f-conf"],
        )
        self.assertEqual(len(fallback_eligible_candidates(audit["findings"], limit=5)), 2)
