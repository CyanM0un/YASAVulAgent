from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import patch

from yasa_vulnagent.agent.usage import UsageRecorder
from yasa_vulnagent.config import (
    DEFAULT_AGENT_CONTEXT_TOKENS,
    DEFAULT_AUDIT_TRACE_WAVE_SIZE,
    DEFAULT_AUDIT_VERIFY_WAVE_LIMIT,
    Settings,
    load_settings,
)
from yasa_vulnagent.stages.audit.budget import AuditBudget
from yasa_vulnagent.stages.audit.categories import load_category_manifest
from yasa_vulnagent.stages.audit.graph import build_audit_graph
from yasa_vulnagent.stages.audit.schema import empty_state
from yasa_vulnagent.stages.audit.storage import audit_paths, write_json
from yasa_vulnagent.stages.audit.trace.constants import (
    LEAD_MAX_ROUNDS,
    MAX_SPECIALISTS,
    SPECIALIST_MAX_ROUNDS,
)
from yasa_vulnagent.stages.audit.trace.execution import (
    TraceExecution,
    TraceTaskBudget,
    _load_category_details,
    _prioritize_pending_tasks,
    run_trace_stage,
)
from yasa_vulnagent.stages.audit.trace.lead import _prompt
from yasa_vulnagent.stages.audit.trace.registry import load_specialist_registry
from yasa_vulnagent.stages.audit.trace.result import EvidenceIndex, validate_category_checks
from yasa_vulnagent.stages.audit.trace.summaries import SummaryIndex
from yasa_vulnagent.stages.audit.trace.tools import TraceYasaToolbox
from yasa_vulnagent.stages.audit.verify.execution import VerifyExecution, run_verify_stage
from yasa_vulnagent.stages.audit.verify.inputs import VerifyInputs
from yasa_vulnagent.stages.audit.verify.result import freshly_read
from yasa_vulnagent.workflow.state import RunContext

from audit_fixtures import make_run_state, references_for

SOURCE = "src/app.py"
TEXT = (
    "def handle(request):\n"
    "    cmd = request.args['cmd']\n"
    "    return run(cmd)\n"
)


class _FakeSession:
    def __init__(self, payload: dict) -> None:
        self.payload = payload

    async def call_tool(self, name: str, arguments: dict):
        del name, arguments
        return type("Result", (), {"structuredContent": self.payload, "content": []})()


@asynccontextmanager
async def _no_yasa(*_args, **_kwargs):
    yield None


class AuditP0OptimizationsTest(unittest.TestCase):
    def test_p0_config_and_round_defaults(self) -> None:
        self.assertEqual(DEFAULT_AGENT_CONTEXT_TOKENS, 96000)
        self.assertEqual(DEFAULT_AUDIT_TRACE_WAVE_SIZE, 16)
        self.assertEqual(DEFAULT_AUDIT_VERIFY_WAVE_LIMIT, 16)
        self.assertEqual(MAX_SPECIALISTS, 2)
        self.assertEqual(SPECIALIST_MAX_ROUNDS, 8)
        self.assertEqual(LEAD_MAX_ROUNDS, 16)

        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing.env"
            with patch.dict(
                os.environ,
                {
                    "AUDIT_TRACE_WAVE_SIZE": "12",
                    "AUDIT_VERIFY_WAVE_LIMIT": "8",
                },
                clear=True,
            ):
                settings = load_settings(env_file=missing)
            self.assertEqual(settings.agent_context_tokens, 96000)
            self.assertEqual(settings.audit_trace_wave_size, 12)
            self.assertEqual(settings.audit_verify_wave_limit, 8)

    def test_lead_prompt_slims_category_details_strips_receipts_and_exposes_tool(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            (repo / "src").mkdir(parents=True)
            (repo / SOURCE).write_text(TEXT, encoding="utf-8")
            manifest = load_category_manifest()
            task = {
                "id": "task-1",
                "kind": "entry",
                "status": "planned",
                "entry_ids": ["entry-1"],
                "patch_ids": [],
                "paths": [SOURCE],
            }
            checks = [
                {
                    "id": f"cat-{cat.id}",
                    "task_id": "task-1",
                    "category": cat.id,
                    "status": "pending",
                }
                for cat in manifest.for_kind("entry")
            ]
            budget = AuditBudget.create(60)
            execution = TraceExecution(
                repository=repo,
                audit_dir=root / "audit",
                model=object(),
                settings=Settings(api_key=None, base_url="http://localhost", model="fake"),
                registry=load_specialist_registry(manifest),
                manifest=manifest,
                category_details=_load_category_details(),
                scope_files=[SOURCE],
                revision="working-tree",
                run_id="run-1",
                audit_state={"category_checks": checks, "mechanism_checks": []},
                entries_by_id={"entry-1": {"id": "entry-1", "name": "handle"}},
                patches_by_id={},
                evidence=EvidenceIndex(repo, [SOURCE]),
                summary_index=SummaryIndex([]),
                audit_budget=budget,
                task_budget=TraceTaskBudget(deadline=budget.deadline, max_model_calls=10),
                business={
                    "constraints": [
                        {
                            "id": "constraint-auth",
                            "description": "All console routes require authenticated admin session.",
                            "source_kind": "code",
                            "applicability": "applicable",
                            "reason": "global filter",
                            "supporting_evidence": [
                                {"path": SOURCE, "start_line": 1, "end_line": 1, "code": "x"}
                            ],
                        }
                    ],
                    "operations": [
                        {
                            "id": "op-handle",
                            "name": "Run command",
                            "entry_ids": ["entry-1"],
                            "actor": "admin",
                            "resource": "host",
                            "guards": ["require_admin"],
                            "locations": [{"path": SOURCE, "start_line": 1, "end_line": 3}],
                        }
                    ],
                    "investigations": [],
                },
            )
            prompt = _prompt(
                task,
                {"chains": [], "excerpts": [], "yasa": {}},
                {"likely_families": ["injection_interpretation"], "units": [], "delegations": [], "gaps": []},
                [{"role": "identity", "summary": "ok", "flows": [], "tool_receipts": [{"tool": "read_file"}] * 20}],
                execution,
            )

            self.assertEqual(len(prompt["category_catalog"]), len(checks))
            self.assertEqual(list(prompt["category_details"]), ["injection_interpretation"])
            self.assertNotIn("tool_receipts", prompt["specialists"][0])
            self.assertEqual(prompt["business"]["constraints"][0]["id"], "constraint-auth")
            self.assertEqual(prompt["business"]["operations"][0]["id"], "op-handle")

            tools, receipts = execution.tools_for_task(task)
            tool_by_name = {tool.name: tool for tool in tools}
            self.assertIn("get_category_details", tool_by_name)
            fetched = tool_by_name["get_category_details"].invoke(
                {"categories": ["network_protocol_boundaries", "bogus_cat"]}
            )
            self.assertIn("network_protocol_boundaries", fetched["categories"])
            self.assertIn("cwe_ids", fetched["categories"]["network_protocol_boundaries"])
            self.assertEqual(fetched["unknown_categories"], ["bogus_cat"])
            self.assertTrue(any(r.get("tool") == "get_category_details" for r in receipts))

    def test_non_highlighted_not_applicable_closes_without_separate_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / SOURCE).write_text(TEXT, encoding="utf-8")
            index = EvidenceIndex(root, [SOURCE])
            expected = [
                {"id": "c1", "task_id": "t1", "category": "injection_interpretation"},
                {"id": "c2", "task_id": "t1", "category": "native_binary_unsafe_memory"},
            ]
            raw = [
                {
                    "category": "injection_interpretation",
                    "status": "checked",
                    "applicability": "not_applicable",
                    "reason": "claims not applicable without code evidence",
                    "evidence": [],
                },
                {
                    "category": "native_binary_unsafe_memory",
                    "status": "checked",
                    "applicability": "not_applicable",
                    "reason": "Pure Python HTTP handler with no native FFI or unsafe memory operations.",
                    "evidence": [],
                },
            ]
            checks, gaps = validate_category_checks(
                raw,
                task={"id": "t1"},
                expected=expected,
                flows=[],
                evidence_index=index,
                likely_families=["injection_interpretation"],
            )
            by_cat = {item["category"]: item for item in checks}
            # Highlighted family still requires evidence for not_applicable.
            self.assertEqual(by_cat["injection_interpretation"]["applicability"], "unknown")
            # Non-highlighted family closes cleanly with concrete reason.
            self.assertEqual(by_cat["native_binary_unsafe_memory"]["applicability"], "not_applicable")
            self.assertEqual(by_cat["native_binary_unsafe_memory"]["status"], "checked")
            self.assertEqual(len(gaps), 1)
            self.assertIn("injection_interpretation", gaps[0])

    def test_prioritize_pending_tasks_runs_logic_and_patch_before_entry(self) -> None:
        tasks = [
            {"id": "e-normal", "kind": "entry", "priority": "normal"},
            {"id": "e-high", "kind": "entry", "priority": "high"},
            {"id": "p-high", "kind": "patch", "priority": "high"},
            {"id": "l-high", "kind": "logic", "priority": "high"},
            {"id": "l-normal", "kind": "logic", "priority": "normal"},
        ]
        ordered = [item["id"] for item in _prioritize_pending_tasks(tasks)]
        self.assertEqual(ordered, ["l-high", "p-high", "e-high", "l-normal", "e-normal"])

    def test_verify_business_for_fixes_ref_keys_and_matches_entry_tasks(self) -> None:
        business = {
            "constraints": [
                {
                    "id": "constraint-1",
                    "description": "Global auth required",
                    "source_kind": "code",
                    "applicability": "applicable",
                    "supporting_evidence": [{"path": SOURCE, "start_line": 1, "end_line": 1}],
                }
            ],
            "operations": [
                {
                    "id": "operation-1",
                    "name": "Handle",
                    "entry_ids": ["entry-1"],
                    "locations": [{"path": SOURCE, "start_line": 1, "end_line": 3}],
                }
            ],
            "investigations": [
                {"id": "investigation-1", "task_id": "task-entry-1", "question": "q", "outcome": "unknown"}
            ],
        }
        inputs = VerifyInputs(
            audit={}, scope={}, entries=[], patches=[], tasks=[], traces=[],
            findings=[], reviews=[], business=business, trace_artifacts={},
            mode="combined", source_revision="working-tree", run_id="run-1",
        )
        logic_task = {
            "id": "task-logic-1",
            "kind": "logic",
            "business_refs": {
                "constraint_ids": ["constraint-1"],
                "operation_ids": ["operation-1"],
                "investigation_ids": ["investigation-1"],
            },
        }
        logic_biz = inputs.business_for(logic_task)
        self.assertEqual([c["id"] for c in logic_biz["constraints"]], ["constraint-1"])
        self.assertEqual([o["id"] for o in logic_biz["operations"]], ["operation-1"])
        self.assertEqual([i["id"] for i in logic_biz["investigations"]], ["investigation-1"])

        entry_task = {
            "id": "task-entry-1",
            "kind": "entry",
            "entry_ids": ["entry-1"],
            "paths": [SOURCE],
            "business_refs": {},
        }
        entry_biz = inputs.business_for(entry_task)
        self.assertEqual([c["id"] for c in entry_biz["constraints"]], ["constraint-1"])
        self.assertEqual([o["id"] for o in entry_biz["operations"]], ["operation-1"])

    def test_freshly_read_accepts_yasa_get_function_with_code_and_rejects_summary_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            (repo / "src").mkdir()
            (repo / SOURCE).write_text(TEXT, encoding="utf-8")

            # Summary-only (no code body) -> should NOT produce spans
            summary_box = TraceYasaToolbox(
                _FakeSession(
                    {
                        "results": [
                            {"file_path": str(repo / SOURCE), "start_line": 1, "end_line": 3}
                        ]
                    }
                ),
                repo,
            )
            asyncio.run(summary_box.get_function(name="handle"))
            fresh, missing = freshly_read(
                [{"path": SOURCE, "start_line": 2, "end_line": 3}],
                summary_box.receipts,
            )
            self.assertFalse(fresh)
            self.assertEqual(missing, [SOURCE])

            # Full code body -> SHOULD satisfy freshly_read
            full_box = TraceYasaToolbox(
                _FakeSession(
                    {
                        "results": [
                            {
                                "file_path": str(repo / SOURCE),
                                "start_line": 1,
                                "end_line": 3,
                                "code": TEXT,
                            }
                        ]
                    }
                ),
                repo,
            )
            asyncio.run(full_box.get_function(name="handle", detail_level="full"))
            fresh, missing = freshly_read(
                [{"path": SOURCE, "start_line": 2, "end_line": 3}],
                full_box.receipts,
            )
            self.assertTrue(fresh)
            self.assertEqual(missing, [])

    def test_fast_reject_review_uses_tool_free_single_round_and_escalates_on_flag(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repository"
            (repo / "src").mkdir(parents=True)
            (repo / SOURCE).write_text(TEXT, encoding="utf-8")
            paths = audit_paths(root / "stages")
            paths.root.mkdir(parents=True)
            paths.trace_dir.mkdir(parents=True)
            flow = {
                "id": "flow-1",
                "task_id": "task-1",
                "category": "injection_interpretation",
                "kind": "dataflow",
                "completeness": "complete",
                "source": {"summary": "in", "evidence": [{"path": SOURCE, "start_line": 2, "end_line": 2, "explanation": "in"}]},
                "sink": {"summary": "out", "evidence": [{"path": SOURCE, "start_line": 3, "end_line": 3, "explanation": "out"}]},
                "reachability": "reachable",
                "triggerability": "triggerable",
                "summary": "candidate",
                "evidence": [
                    {"path": SOURCE, "start_line": 2, "end_line": 2, "explanation": "in"},
                    {"path": SOURCE, "start_line": 3, "end_line": 3, "explanation": "out"},
                ],
            }
            task = {"id": "task-1", "kind": "entry", "status": "complete", "paths": [SOURCE]}
            write_json(
                paths.audit_file,
                {
                    "entries": [], "patches": [], "tasks": [task],
                    "traces": [{"id": "trace-1", "task_id": "task-1", "kind": "entry", "status": "complete"}],
                    "findings": [], "reviews": [], "scope": {"files": [SOURCE]},
                },
            )
            write_json(paths.trace_dir / "trace-1.json", {"id": "trace-1", "task_id": "task-1", "flows": [flow]})
            state = {
                "run_id": "run-1",
                "repository": str(repo),
                "artifact_dir": str(paths.root),
                "state_file": str(paths.state_file),
                "audit_file": str(paths.audit_file),
                "scope": {"files": [SOURCE]},
                "prepare": {"source_revision": "working-tree"},
                "mode": "combined",
                "tasks": [task],
                "traces": [{"id": "trace-1", "task_id": "task-1", "kind": "entry", "status": "complete"}],
                "framework": {"visits": {"trace": 1}},
            }
            recorded_calls: list[dict] = []

            async def fake_agent(self, *, system_prompt, user_prompt, receipts, max_rounds, stage, task_id, tools_enabled=True):
                payload = json.loads(user_prompt)
                recorded_calls.append(
                    {
                        "stage": stage,
                        "mode": payload.get("mode", ""),
                        "tools_enabled": tools_enabled,
                        "max_rounds": max_rounds,
                        "has_code_in_evidence": bool(
                            isinstance(payload.get("finding"), dict)
                            and payload["finding"].get("evidence")
                            and payload["finding"]["evidence"][0].get("code")
                        ),
                    }
                )
                if tools_enabled:
                    receipts.append({"tool": "read_file", "path": SOURCE, "start_line": 1, "end_line": 4, "status": "ok"})
                evidence = [{"path": SOURCE, "start_line": 2, "end_line": 2, "explanation": "guarded"}]
                if stage == "audit.verify.review":
                    return {"verdict": "rejected", "reason": "quoted source confirms guard", "evidence": evidence}
                return {"verdict": "rejected", "reason": "guard blocks input", "evidence": evidence}

            context = RunContext(
                settings=Settings(api_key=None, base_url="http://localhost", model="fake"),
                model=object(),
                audit_budget=AuditBudget.create(60),
            )
            with patch.object(VerifyExecution, "run_agent", fake_agent), patch(
                "yasa_vulnagent.stages.audit.verify.execution.open_yasa_mcp", _no_yasa
            ):
                result = asyncio.run(run_verify_stage(state, context))

            self.assertEqual(result["findings"][0]["verdict"], "rejected")
            self.assertEqual(result["reviews"][0]["status"], "complete")
            self.assertEqual(result["reviews"][0]["mode"], "fast_reject_review")
            review_call = [c for c in recorded_calls if c["stage"] == "audit.verify.review"][0]
            self.assertEqual(review_call["mode"], "fast_reject_review")
            self.assertFalse(review_call["tools_enabled"])
            self.assertEqual(review_call["max_rounds"], 1)
            self.assertTrue(review_call["has_code_in_evidence"])

    def test_wave_interleaving_routes_verify_to_trace_and_feeds_rejections(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repository"
            (repo / "src").mkdir(parents=True)
            (repo / SOURCE).write_text(TEXT, encoding="utf-8")
            paths = audit_paths(root / "stages")
            paths.root.mkdir(parents=True)
            paths.trace_dir.mkdir(parents=True)
            tasks = [
                {
                    "id": f"task-{i}",
                    "kind": "entry",
                    "status": "planned",
                    "entry_ids": [f"entry-{i}"],
                    "patch_ids": [],
                    "paths": [SOURCE],
                    "priority": "high",
                }
                for i in range(1, 5)
            ]
            entries = [
                {
                    "id": f"entry-{i}",
                    "name": "handle",
                    "entry_location": {"path": SOURCE, "start_line": 1, "end_line": 3},
                }
                for i in range(1, 5)
            ]
            checks = [
                {
                    "id": f"cat-{i}",
                    "task_id": f"task-{i}",
                    "category": "injection_interpretation",
                    "status": "pending",
                }
                for i in range(1, 5)
            ]
            write_json(
                paths.audit_file,
                {
                    "run_id": "run-1",
                    "repo": str(repo),
                    "mode": "entries",
                    "scope": {"files": [SOURCE]},
                    "entries": entries,
                    "patches": [],
                    "tasks": tasks,
                    "traces": [],
                    "category_checks": checks,
                    "mechanism_checks": [],
                    "summaries": [],
                    "findings": [],
                    "reviews": [],
                    "gaps": [],
                },
            )
            state = {
                "run_id": "run-1",
                "repository": str(repo),
                "artifact_dir": str(paths.root),
                "state_file": str(paths.state_file),
                "audit_file": str(paths.audit_file),
                "scope": {"files": [SOURCE]},
                "prepare": {"source_revision": "working-tree"},
                "mode": "entries",
                "tasks": tasks,
                "entries": entries,
                "category_checks": checks,
                "framework": {"visits": {"trace": 0}},
            }
            settings = Settings(
                api_key=None,
                base_url="http://localhost",
                model="fake",
                audit_timeout=3600,
                audit_verify_reserve=900,
                audit_trace_wave_size=2,
                audit_verify_wave_limit=2,
            )
            context = RunContext(
                settings=settings,
                model=object(),
                usage=UsageRecorder(),
                audit_budget=AuditBudget.create(3600),
            )
            seen_rejections_by_wave: list[int] = []

            async def fake_run_one(task, values):
                seen_rejections_by_wave.append(len(values["rejections"].entries))
                task_id = task["id"]
                trace_id = f"trace-{task_id}"
                flow = {
                    "id": f"flow-{task_id}",
                    "task_id": task_id,
                    "category": "injection_interpretation",
                    "kind": "dataflow",
                    "completeness": "complete",
                    "source": {"summary": f"in-{task_id}", "evidence": [{"path": SOURCE, "start_line": 2, "end_line": 2, "explanation": "in"}]},
                    "sink": {"summary": f"out-{task_id}", "evidence": [{"path": SOURCE, "start_line": 3, "end_line": 3, "explanation": "out"}]},
                    "reachability": "reachable",
                    "triggerability": "triggerable",
                    "summary": f"candidate-{task_id}",
                    "evidence": [
                        {"path": SOURCE, "start_line": 2, "end_line": 2, "explanation": "in"},
                        {"path": SOURCE, "start_line": 3, "end_line": 3, "explanation": "out"},
                    ],
                }
                write_json(paths.trace_dir / f"{trace_id}.json", {"id": trace_id, "task_id": task_id, "flows": [flow]})
                return {
                    "status": "complete",
                    "trace": {
                        "id": trace_id,
                        "task_id": task_id,
                        "kind": "entry",
                        "status": "complete",
                        "coverage_complete": True,
                        "flow_count": 1,
                        "complete_flow_count": 1,
                        "partial_flow_count": 0,
                        "reachable_flow_count": 1,
                        "summary_count": 0,
                    },
                    "category_checks": [
                        {
                            "id": f"cat-{task_id.split('-')[1]}",
                            "task_id": task_id,
                            "category": "injection_interpretation",
                            "status": "checked",
                            "applicability": "applicable",
                            "reason": "checked",
                        }
                    ],
                    "mechanism_checks": [],
                    "summaries": [],
                    "gaps": [],
                }

            async def fake_verify_agent(self, *, system_prompt, user_prompt, receipts, tools_enabled=True, **_kwargs):
                if tools_enabled:
                    receipts.append({"tool": "read_file", "path": SOURCE, "start_line": 1, "end_line": 4, "status": "ok"})
                return {
                    "verdict": "rejected",
                    "reason": "framework middleware blocks this path",
                    "evidence": [{"path": SOURCE, "start_line": 2, "end_line": 2, "explanation": "guard"}],
                }

            with patch("yasa_vulnagent.stages.audit.trace.execution.open_yasa_mcp", _no_yasa), patch(
                "yasa_vulnagent.stages.audit.trace.execution._run_one", fake_run_one
            ), patch(
                "yasa_vulnagent.stages.audit.verify.execution.open_yasa_mcp", _no_yasa
            ), patch.object(VerifyExecution, "run_agent", fake_verify_agent):
                # Wave 1 trace: processes 2 of 4 tasks, leaves 2 planned.
                w1_trace = asyncio.run(run_trace_stage(state, context))
                self.assertEqual(w1_trace["stop_reason"], "trace_wave_complete")
                self.assertEqual(
                    sum(1 for t in w1_trace["tasks"] if t["status"] == "complete"), 2
                )
                self.assertEqual(
                    sum(1 for t in w1_trace["tasks"] if t["status"] == "planned"), 2
                )

                # Wave 1 verify: settles wave 1 candidates as rejected, routes back to trace!
                w1_state = {**state, **w1_trace, "framework": {"visits": {"trace": 1}}}
                w1_verify = asyncio.run(run_verify_stage(w1_state, context))
                self.assertEqual(w1_verify["next_action"], "trace")
                self.assertEqual(w1_verify["stop_reason"], "verify_wave_complete")
                self.assertEqual(w1_verify["verify"]["rejected_count"], 1)

                # Wave 2 trace: runs remaining 2 tasks and now sees Wave 1's RejectionIndex!
                w2_state = {**w1_state, **w1_verify, "framework": {"visits": {"trace": 1}}}
                w2_trace = asyncio.run(run_trace_stage(w2_state, context))
                self.assertEqual(w2_trace["status"], "complete")
                self.assertEqual(seen_rejections_by_wave[:2], [0, 0])
                self.assertTrue(all(count >= 1 for count in seen_rejections_by_wave[2:]))

                # Final verify: no remaining pending trace tasks -> routes to gate!
                w2_verify_state = {**w2_state, **w2_trace, "framework": {"visits": {"trace": 2}}}
                w2_verify = asyncio.run(run_verify_stage(w2_verify_state, context))
                self.assertEqual(w2_verify["next_action"], "gate")

    def test_graph_runs_plan_recon_trace_without_noop_trace_visit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_state = make_run_state(
                Path(temporary),
                entries=[],
                patches=[],
                init_status="complete",
                discover_status="complete",
                overview=True,
            )
            paths = audit_paths(run_state["stages_dir"])
            state = empty_state(run_state, paths)
            state["references"] = references_for(run_state)
            result = build_audit_graph().invoke(
                state,
                context=RunContext(
                    settings=Settings(api_key=None, base_url="http://localhost", model="fake")
                ),
            )
            self.assertEqual(
                result["framework"]["executed"],
                ["prepare", "plan", "recon", "trace", "verify", "gate", "finalize"],
            )
            self.assertEqual(result["framework"]["visits"]["trace"], 1)


if __name__ == "__main__":
    unittest.main()
