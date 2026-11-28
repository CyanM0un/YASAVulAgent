from __future__ import annotations

import asyncio
import json
import os
import tempfile
import threading
import time
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from yasa_vulnagent.agent.usage import UsageRecorder
from yasa_vulnagent.config import (
    DEFAULT_AUDIT_TRACE_TASK_TIMEOUT,
    DEFAULT_AUDIT_VERIFY_TASK_TIMEOUT,
    Settings,
    load_settings,
)
from yasa_vulnagent.stages.audit.budget import AuditBudget
from yasa_vulnagent.stages.audit.categories import load_category_manifest
from yasa_vulnagent.stages.audit.plan.batches import build_seed_batches
from yasa_vulnagent.stages.audit.plan.node import plan
from yasa_vulnagent.stages.audit.plan.tasks import derive_final_tasks
from yasa_vulnagent.stages.audit.prepare.node import prepare
from yasa_vulnagent.stages.audit.schema import empty_state
from yasa_vulnagent.stages.audit.storage import audit_paths, write_json
from yasa_vulnagent.stages.audit.trace.execution import run_trace_stage
from yasa_vulnagent.stages.audit.trace.result import EvidenceIndex
from yasa_vulnagent.stages.audit.trace.summaries import SummaryIndex, validate_candidates
from yasa_vulnagent.stages.audit.verify.execution import VerifyExecution, run_verify_stage
from yasa_vulnagent.workflow.state import RunContext

from audit_fixtures import make_run_state, references_for

SOURCE = "src/app.py"
TEXT = (
    "def helper(x):\n"
    "    return x\n"
    "def handle(request):\n"
    "    return helper(request.args['cmd'])\n"
)


@asynccontextmanager
async def _no_yasa(*_args, **_kwargs):
    yield None


class AuditP1OptimizationsTest(unittest.TestCase):
    def test_p1_timeout_config_defaults_and_env(self) -> None:
        self.assertEqual(DEFAULT_AUDIT_TRACE_TASK_TIMEOUT, 300)
        self.assertEqual(DEFAULT_AUDIT_VERIFY_TASK_TIMEOUT, 180)
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing.env"
            with patch.dict(
                os.environ,
                {
                    "AUDIT_TRACE_TASK_TIMEOUT": "240",
                    "AUDIT_VERIFY_TASK_TIMEOUT": "0",
                },
                clear=True,
            ):
                settings = load_settings(env_file=missing)
            self.assertEqual(settings.audit_trace_task_timeout, 240)
            self.assertEqual(settings.audit_verify_task_timeout, 0)

    def test_trace_dynamic_worker_pool_avoids_hol_blocking_shares_summaries_and_caps_deadline(
        self,
    ) -> None:
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
            write_json(
                paths.audit_file,
                {
                    "run_id": "run-1",
                    "repo": str(repo),
                    "mode": "entries",
                    "scope": {"files": [SOURCE]},
                    "entries": [
                        {"id": f"entry-{i}", "name": "handle", "entry_location": {"path": SOURCE, "start_line": 1, "end_line": 4}}
                        for i in range(1, 5)
                    ],
                    "patches": [],
                    "tasks": tasks,
                    "traces": [],
                    "category_checks": [],
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
                "framework": {"visits": {"trace": 0}},
            }
            settings = Settings(
                api_key=None,
                base_url="http://localhost",
                model="fake",
                audit_timeout=3600,
                audit_verify_reserve=900,
                audit_max_agents=2,
                audit_trace_wave_size=0,
                audit_trace_task_timeout=45,
            )
            context = RunContext(
                settings=settings,
                model=object(),
                usage=UsageRecorder(),
                audit_budget=AuditBudget.create(3600),
            )
            completion_order: list[str] = []
            seen_summary_counts: dict[str, int] = {}
            observed_remaining: list[float] = []

            async def fake_run_one(task, values):
                task_id = task["id"]
                observed_remaining.append(values["task_budget"].remaining_seconds())
                seen_summary_counts[task_id] = len(values["summary_index"].for_task(task))
                if task_id == "task-1":
                    # Slow straggler task: worker 2 should finish task-2, task-3, task-4 before task-1 completes!
                    await asyncio.sleep(0.12)
                else:
                    await asyncio.sleep(0.01)
                completion_order.append(task_id)
                new_summaries = []
                if task_id == "task-2":
                    new_summaries.append(
                        {
                            "id": "summary-live-1",
                            "task_id": task_id,
                            "unit": {"kind": "helper", "path": SOURCE, "function_fqn": "app.helper", "start_line": 1, "end_line": 2},
                            "behavior": "passthrough helper",
                            "conditions": ["always"],
                            "guards": [],
                            "unknowns": [],
                            "evidence": [{"path": SOURCE, "start_line": 1, "end_line": 2, "quote": "def helper(x):"}],
                        }
                    )
                return {
                    "status": "complete",
                    "trace": {"id": f"trace-{task_id}", "task_id": task_id, "kind": "entry", "status": "complete", "coverage_complete": True},
                    "category_checks": [],
                    "mechanism_checks": [],
                    "summaries": new_summaries,
                    "gaps": [],
                }

            with patch("yasa_vulnagent.stages.audit.trace.execution.open_yasa_mcp", _no_yasa), patch(
                "yasa_vulnagent.stages.audit.trace.execution._run_one", fake_run_one
            ):
                result = asyncio.run(run_trace_stage(state, context))

            self.assertEqual(result["status"], "complete")
            # task-2, task-3, task-4 must all finish BEFORE slow straggler task-1!
            self.assertEqual(completion_order[-1], "task-1")
            # task-3 and task-4 must see summary-live-1 emitted by task-2 in the same wave!
            self.assertGreaterEqual(seen_summary_counts["task-3"], 1)
            self.assertGreaterEqual(seen_summary_counts["task-4"], 1)
            # Soft per-task timeout capped deadline to <= 45s (instead of 2700s trace_deadline).
            self.assertTrue(all(rem <= 46.0 for rem in observed_remaining))

    def test_verify_worker_pool_avoids_hol_blocking_and_caps_candidate_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repository"
            (repo / "src").mkdir(parents=True)
            (repo / SOURCE).write_text(TEXT, encoding="utf-8")
            paths = audit_paths(root / "stages")
            paths.root.mkdir(parents=True)
            paths.trace_dir.mkdir(parents=True)
            findings = [
                {
                    "id": f"finding-{i}",
                    "task_id": "task-1",
                    "verdict": "candidate",
                    "category": "injection_interpretation",
                    "completeness": "complete",
                    "reachability": "reachable",
                    "triggerability": "triggerable",
                    "title": f"candidate {i}",
                    "evidence": [{"path": SOURCE, "start_line": 3, "end_line": 4, "code": "def handle(request):"}],
                }
                for i in range(1, 5)
            ]
            write_json(
                paths.audit_file,
                {
                    "entries": [], "patches": [],
                    "tasks": [{"id": "task-1", "kind": "entry", "status": "complete", "paths": [SOURCE]}],
                    "traces": [], "findings": findings, "reviews": [],
                    "scope": {"files": [SOURCE]},
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
                "framework": {"visits": {"trace": 1}},
            }
            settings = Settings(
                api_key=None,
                base_url="http://localhost",
                model="fake",
                audit_timeout=3600,
                audit_max_agents=2,
                audit_verify_task_timeout=30,
            )
            context = RunContext(
                settings=settings,
                model=object(),
                audit_budget=AuditBudget.create(3600),
            )
            finished: list[str] = []
            observed_remaining: list[float] = []

            async def fake_agent(self, *, system_prompt, user_prompt, receipts, task_id, tools_enabled=True, **_kwargs):
                observed_remaining.append(self.task_budget.remaining_seconds())
                if tools_enabled:
                    receipts.append({"tool": "read_file", "path": SOURCE, "start_line": 1, "end_line": 4, "status": "ok"})
                    if task_id == "finding-1":
                        await asyncio.sleep(0.12)
                    else:
                        await asyncio.sleep(0.01)
                else:
                    finished.append(task_id)
                return {
                    "verdict": "rejected",
                    "reason": "guarded",
                    "evidence": [{"path": SOURCE, "start_line": 3, "end_line": 4, "explanation": "guard"}],
                }

            with patch.object(VerifyExecution, "run_agent", fake_agent), patch(
                "yasa_vulnagent.stages.audit.verify.execution.open_yasa_mcp", _no_yasa
            ):
                result = asyncio.run(run_verify_stage(state, context))

            self.assertEqual(result["verify"]["rejected_count"], 4)
            self.assertEqual(finished[-1], "finding-1")
            self.assertTrue(all(rem <= 31.0 for rem in observed_remaining))

    def test_plan_packs_modules_runs_batches_concurrently_and_interleaves_by_risk(self) -> None:
        manifest = load_category_manifest()
        entries = [
            {
                "id": "e-health",
                "name": "healthz",
                "entry_location": {"path": "api/a_health.py", "start_line": 1, "end_line": 1},
                "discovery": {"role": "endpoint", "summary": "GET /healthz ping status"},
            },
            {
                "id": "e-upload",
                "name": "upload_archive",
                "entry_location": {"path": "api/z_upload.py", "start_line": 1, "end_line": 1},
                "discovery": {
                    "role": "endpoint",
                    "summary": "POST unauthenticated public file archive upload",
                    "trust_boundary": {"summary": "anonymous external client"},
                },
            },
            {
                "id": "e-upload-2",
                "name": "download_file",
                "entry_location": {"path": "api/z_upload.py", "start_line": 10, "end_line": 10},
                "discovery": {"role": "endpoint", "summary": "GET download attachment path"},
            },
            {
                "id": "e-ssrf",
                "name": "fetch_webhook",
                "entry_location": {"path": "api/m_webhook.py", "start_line": 1, "end_line": 1},
                "discovery": {
                    "role": "endpoint",
                    "summary": "POST public webhook URL fetch SSRF proxy",
                    "trust_boundary": {"summary": "unauthenticated callback"},
                },
            },
        ]
        seed_tasks = [
            {"id": f"task-{e['id']}", "kind": "entry", "status": "planned", "entry_ids": [e["id"]], "patch_ids": [], "paths": [e["entry_location"]["path"]]}
            for e in entries
        ]
        batches = build_seed_batches(seed_tasks, 100)
        # All 4 files in api/ pack into 1 batch!
        self.assertEqual(len(batches), 1)
        output = {
            "groups": [
                {"seed_task_ids": [task["id"]], "priority": "high", "reason": "high"}
                for task in batches[0]["tasks"]
            ],
            "order": list(range(len(batches[0]["tasks"]))),
        }
        tasks, _, _ = derive_final_tasks(
            seed_tasks, batches, [output], manifest, entries=entries
        )
        ids = [task["id"] for task in tasks]
        # High-risk upload & webhook come first across distinct files before second task in z_upload and healthz!
        self.assertEqual(set(ids[:2]), {"task-e-upload", "task-e-ssrf"})
        self.assertEqual(ids[-1], "task-e-health")

        # Verify concurrent multi-batch execution in plan() preserves deterministic order.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_state = make_run_state(
                root,
                mode="entries",
                entries=[
                    {
                        "entry_id": f"entry-{i}",
                        "status": "confirmed",
                        "role": "request-handler",
                        "summary": f"Entry {i}",
                        "location": {"path": "src/app.py", "line_start": 1, "line_end": 1},
                        "evidence_refs": ["source:src/app.py:1-1"],
                    }
                    for i in range(1, 5)
                ],
                evidence=[
                    {"evidence_id": "e1", "source_file": "src/app.py", "line_start": 1, "line_end": 1, "summary": "ev"}
                ],
                init_status="complete",
                discover_status="complete",
                overview=True,
            )
            paths = audit_paths(run_state["stages_dir"])
            state = empty_state(run_state, paths)
            state["references"] = references_for(run_state)
            state = {**state, **prepare(state)}

            active = 0
            peak = 0
            lock = threading.Lock()

            class ConcurrentFakeModel:
                model_name = "fake"

                def invoke(self, messages):
                    nonlocal active, peak
                    with lock:
                        active += 1
                        peak = max(peak, active)
                    time.sleep(0.03)
                    with lock:
                        active -= 1
                    payload = json.loads(messages[-1].content.split("\n", 1)[1])
                    groups = [
                        {"seed_task_ids": [t["id"]], "priority": "normal", "reason": "ok"}
                        for t in payload["seed_tasks"]
                    ]
                    return SimpleNamespace(
                        content=json.dumps({"groups": groups, "order": list(range(len(groups)))}),
                        usage_metadata={"input_tokens": 5, "output_tokens": 5, "total_tokens": 10},
                    )

            ctx = SimpleNamespace(
                context=RunContext(
                    settings=Settings(
                        api_key=None,
                        base_url="http://localhost",
                        model="fake",
                        audit_plan_batch_size=1,
                        audit_model_concurrency=4,
                    ),
                    model=ConcurrentFakeModel(),
                    usage=UsageRecorder(),
                )
            )
            result = plan(state, ctx)
            self.assertEqual(len(result["tasks"]), 4)
            self.assertGreaterEqual(peak, 2)

    def test_summary_truncation_off_by_one_and_targeted_compact_retrieval(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            (repo / "src").mkdir()
            (repo / SOURCE).write_text(TEXT, encoding="utf-8")
            index = EvidenceIndex(repo, [SOURCE])
            task = {"id": "task-1", "kind": "entry", "paths": [SOURCE]}

            def _cand(name: str) -> dict:
                return {
                    "unit": {"kind": "helper", "path": SOURCE, "function_fqn": f"app.{name}"},
                    "behavior": f"does {name}",
                    "conditions": ["authenticated"],
                    "evidence": [{"path": SOURCE, "start_line": 1, "end_line": 2, "explanation": "helper"}],
                }

            # Exactly 3 valid candidates -> ZERO truncation gap!
            exact_three, gaps_three = validate_candidates(
                [_cand("a"), _cand("b"), _cand("c")],
                task=task,
                evidence_index=index,
                repository=repo,
                revision="rev-1",
                run_id="run-1",
            )
            self.assertEqual(len(exact_three), 3)
            self.assertEqual(gaps_three, [])

            # 4 valid candidates -> truncates to 3 with exactly 1 truncation gap.
            four, gaps_four = validate_candidates(
                [_cand("a"), _cand("b"), _cand("c"), _cand("d")],
                task=task,
                evidence_index=index,
                repository=repo,
                revision="rev-1",
                run_id="run-1",
            )
            self.assertEqual(len(four), 3)
            self.assertTrue(any("truncated at 3" in gap for gap in gaps_four))

            # Targeted compact retrieval excludes unrelated summaries and raw quote blobs.
            unrelated = {
                "id": "summary-unrelated",
                "task_id": "task-other",
                "unit": {"kind": "helper", "path": "other/mod.py", "function_fqn": "other.fn", "start_line": 1, "end_line": 2},
                "behavior": "unrelated",
                "conditions": ["always"],
                "evidence": [{"path": "other/mod.py", "start_line": 1, "end_line": 2, "quote": "SECRET_RAW_QUOTE"}],
            }
            sidx = SummaryIndex([*exact_three, unrelated])
            scout = {
                "chains": [
                    {"nodes": [{"path": SOURCE, "function_fqn": "app.b"}]}
                ]
            }
            matched = sidx.for_task(task, scout, limit=8)
            self.assertEqual(len(matched), 3)
            self.assertNotIn("summary-unrelated", {item["id"] for item in matched})
            # Highest-scored match (exact chain FQN app.b) must be ranked first!
            self.assertEqual(matched[0]["unit"]["function_fqn"], "app.b")
            # Compact view must strip raw quote blobs and keep evidence_anchors.
            self.assertNotIn("evidence", matched[0])
            self.assertIn("evidence_anchors", matched[0])


if __name__ == "__main__":
    unittest.main()
