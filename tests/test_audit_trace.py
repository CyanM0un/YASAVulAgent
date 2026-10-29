from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import patch

from yasa_vulnagent.config import Settings
from yasa_vulnagent.stages.audit.budget import AuditBudget
from yasa_vulnagent.stages.audit.categories import load_category_manifest
from yasa_vulnagent.stages.audit.storage import audit_paths, write_json
from yasa_vulnagent.stages.audit.trace.execution import (
    TraceExecution,
    TraceTaskBudget,
    _load_category_details,
    _repair_contexts,
    run_trace_stage,
)
from yasa_vulnagent.stages.audit.trace.lead import _prompt, validate_lead
from yasa_vulnagent.stages.audit.trace.rejections import RejectionIndex
from yasa_vulnagent.stages.audit.trace.graph import run_trace_task
from yasa_vulnagent.stages.audit.trace.registry import load_specialist_registry
from yasa_vulnagent.stages.audit.trace.result import (
    EvidenceIndex,
    validate_category_checks,
    validate_flows,
    validate_mechanism_checks,
)
from yasa_vulnagent.agent.usage import UsageRecorder
from yasa_vulnagent.workflow.state import RunContext
from yasa_vulnagent.stages.audit.trace.summaries import (
    SummaryIndex,
    validate_candidates,
    validate_reuse,
)

SOURCE = "src/app.py"
TEXT = (
    "def handle(request):\n"
    "    cmd = request.args['cmd']\n"
    "    return run(cmd)\n"
)


class _Response:
    def __init__(self, content: str) -> None:
        self.content = content
        self.tool_calls = []


class _Model:
    def __init__(self, *, patch: bool = False) -> None:
        self.patch = patch
        self.calls: list[str] = []
        self.prompts: list[dict] = []

    def bind_tools(self, tools):
        return self

    async def ainvoke(self, messages):
        system = str(messages[0].content)
        prompt = json.loads(str(messages[-1].content))
        self.prompts.append(prompt)
        self.calls.append(system[:22])
        if "You triage" in system:
            unit = prompt["path_scout"]["chains"][0]["nodes"][0]
            return _Response(
                json.dumps(
                    {
                        "likely_families": ["injection_interpretation"],
                        "units": [
                            {
                                "unit_id": unit["unit_id"],
                                "relevance": "high",
                                "reason": "entry",
                                "expand": False,
                                "skip": False,
                                "grounding": ["chain:chain-1:node:0"],
                            }
                        ],
                        "delegations": [
                            {
                                "role": "patch" if self.patch else "identity",
                                "unit_id": unit["unit_id"],
                                "focus_question": "check this unit",
                                "priority": 1,
                                "grounding": ["chain:chain-1:node:0"],
                            }
                        ],
                        "notes": "ok",
                    }
                )
            )
        if "You are the trace lead" in system:
            return _Response(json.dumps(self._lead(prompt)))
        return _Response(json.dumps(self._specialist(prompt)))

    def _lead(self, prompt):
        if self.patch:
            flow = prompt["specialists"][0]["flows"][0]
            evidence = [{"path": SOURCE, "start_line": 2, "end_line": 2, "explanation": "guard"}]
            return {
                "status": "complete",
                "summary": "patch checked",
                "flows": [],
                "categories": [],
                "mechanisms": [
                    {
                        "kind": "original_path",
                        "status": "checked",
                        "outcome": "found",
                        "reason": "original path remains",
                        "flow_ids": [flow["id"]],
                        "evidence": evidence,
                    },
                    {
                        "kind": "bypass",
                        "status": "checked",
                        "outcome": "not_found",
                        "reason": "no bypass",
                        "flow_ids": [],
                        "evidence": evidence,
                    },
                    {
                        "kind": "same_mechanism",
                        "status": "checked",
                        "outcome": "not_applicable",
                        "reason": "single path",
                        "flow_ids": [],
                        "evidence": evidence,
                    },
                ],
                "summaries": [],
                "summary_reuse": [],
                "triage_override": [],
                "gaps": [],
            }
        categories = [
            {
                "category": check["category"],
                "status": "checked",
                "applicability": "applicable",
                "reason": "reviewed",
                "flow_ids": [],
                "evidence": [],
            }
            for check in prompt["required_categories"]
        ]
        flow = {
            "category": "injection_interpretation",
            "cwe_hints": [78],
            "kind": "dataflow",
            "completeness": "complete",
            "source": {
                "summary": "request parameter",
                "evidence": [
                    {"path": SOURCE, "start_line": 2, "end_line": 2, "explanation": "input"}
                ],
            },
            "sink": {
                "summary": "run",
                "operation": "command execution",
                "evidence": [
                    {"path": SOURCE, "start_line": 3, "end_line": 3, "explanation": "sink"}
                ],
            },
            "steps": [],
            "guards": [],
            "reachability": "reachable",
            "triggerability": "triggerable",
            "confidence": "high",
            "summary": "candidate",
            "impact": "command execution",
            "preconditions": ["request reaches handle"],
            "unknowns": [],
            "evidence": [],
        }
        return {
            "status": "complete",
            "summary": "entry checked",
            "entry_results": [],
            "unit_results": [],
            "flows": [flow],
            "categories": categories,
            "mechanisms": [],
            "summaries": [],
            "summary_reuse": [],
            "triage_override": [],
            "gaps": [],
        }

    def _specialist(self, prompt):
        if not self.patch:
            return {
                "status": "complete",
                "summary": "no issue",
                "flows": [],
                "observations": [],
                "unit_results": [],
                "summary_candidates": [],
                "gaps": [],
            }
        flow = {
            "category": "injection_interpretation",
            "kind": "dataflow",
            "completeness": "complete",
            "source": {
                "summary": "request parameter",
                "evidence": [
                    {"path": SOURCE, "start_line": 2, "end_line": 2, "explanation": "input"}
                ],
            },
            "sink": {
                "summary": "run",
                "evidence": [
                    {"path": SOURCE, "start_line": 3, "end_line": 3, "explanation": "sink"}
                ],
            },
            "reachability": "reachable",
            "triggerability": "triggerable",
            "confidence": "high",
            "summary": "original path",
            "evidence": [],
        }
        return {
            "status": "complete",
            "summary": "patch checked",
            "flows": [flow],
            "observations": [],
            "unit_results": [
                {
                    "patch_id": "patch-abc",
                    "unit_id": "unit-1",
                    "effectiveness": "bypassed",
                    "reason": "guard can be bypassed",
                    "flow_ids": [],
                    "evidence": [
                        {"path": SOURCE, "start_line": 2, "end_line": 2, "explanation": "guard"}
                    ],
                }
            ],
            "summary_candidates": [],
            "gaps": [],
        }


def _execution(root: Path, *, patch: bool = False):
    repository = root / "repository"
    (repository / "src").mkdir(parents=True)
    (repository / SOURCE).write_text(TEXT, encoding="utf-8")
    stages = root / "stages"
    audit_dir = stages / "audit"
    audit_dir.mkdir(parents=True)
    task = {
        "id": "task-1",
        "kind": "patch" if patch else "entry",
        "status": "planned",
        "entry_ids": [] if patch else ["entry-1"],
        "patch_ids": ["patch-abc"] if patch else [],
        "repair_unit_refs": (
            [{"patch_id": "patch-abc", "unit_id": "unit-1"}] if patch else []
        ),
        "paths": [SOURCE],
    }
    category_checks = (
        []
        if patch
        else [
            {
                "id": "cat-1",
                "task_id": "task-1",
                "category": "injection_interpretation",
                "status": "pending",
                "applicability": "unknown",
                "reason": "",
                "evidence": [],
            }
        ]
    )
    mechanism_checks = (
        [
            {"id": f"mechanism-{kind}", "task_id": "task-1", "kind": kind}
            for kind in ("original_path", "bypass", "same_mechanism")
        ]
        if patch
        else []
    )
    entry = {
        "id": "entry-1",
        "name": "handle",
        "entry_location": {"path": SOURCE, "start_line": 1, "end_line": 1},
    }
    patch_record = {
        "id": "patch-abc",
        "commit": "a" * 40,
        "units": [{"id": "unit-1", "paths": [SOURCE]}],
    }
    audit = {
        "run_id": "run-1",
        "repo": str(repository),
        "mode": "combined",
        "scope": {"files": [SOURCE]},
        "entries": [] if patch else [entry],
        "patches": [patch_record] if patch else [],
        "tasks": [task],
        "traces": [],
        "category_checks": category_checks,
        "mechanism_checks": mechanism_checks,
        "summaries": [],
        "findings": [],
        "reviews": [],
        "gaps": [],
    }
    write_json(audit_paths(stages).audit_file, audit)
    settings = Settings(
        api_key="test",
        base_url="http://localhost",
        model="fake",
        audit_timeout=3600,
        agent_hard_task_cap=20,
    )
    manifest = load_category_manifest()
    budget = AuditBudget.create(3600)
    execution = TraceExecution(
        repository=repository,
        audit_dir=audit_dir,
        model=_Model(patch=patch),
        settings=settings,
        registry=load_specialist_registry(manifest),
        manifest=manifest,
        category_details=_load_category_details(),
        scope_files=[SOURCE],
        revision="working-tree",
        run_id="run-1",
        audit_state=audit,
        entries_by_id={} if patch else {"entry-1": entry},
        patches_by_id={"patch-abc": patch_record} if patch else {},
        evidence=EvidenceIndex(repository, [SOURCE]),
        summary_index=SummaryIndex([]),
        audit_budget=budget,
        task_budget=TraceTaskBudget(deadline=budget.deadline, max_model_calls=20),
    )
    return task, execution, audit_paths(stages)


class TraceResultTest(unittest.TestCase):
    def test_flow_is_hydrated_and_unreachable_is_dropped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repo"
            (repository / "src").mkdir(parents=True)
            (repository / SOURCE).write_text(TEXT, encoding="utf-8")
            index = EvidenceIndex(repository, [SOURCE])
            task = {"id": "task-1", "entry_ids": ["entry-1"], "patch_ids": []}
            raw = {
                "category": "injection_interpretation",
                "completeness": "complete",
                "source": {
                    "summary": "input",
                    "evidence": [
                        {"path": SOURCE, "start_line": 2, "end_line": 2, "explanation": "input"}
                    ],
                },
                "sink": {
                    "summary": "run",
                    "evidence": [
                        {"path": SOURCE, "start_line": 3, "end_line": 3, "explanation": "sink"}
                    ],
                },
                "reachability": "reachable",
            }
            flows, gaps = validate_flows(
                [raw],
                task=task,
                categories={"injection_interpretation"},
                evidence_index=index,
            )
            self.assertEqual(len(flows), 1)
            self.assertEqual(flows[0]["source"]["evidence"][0]["quote"], "    cmd = request.args['cmd']")
            self.assertEqual(gaps, [])

            unreachable = {**raw, "reachability": "unreachable"}
            flows, gaps = validate_flows(
                [unreachable],
                task=task,
                categories={"injection_interpretation"},
                evidence_index=index,
            )
            self.assertEqual(flows, [])
            self.assertTrue(any("unreachable" in gap for gap in gaps))

            outside = {**raw, "source": {"summary": "x", "evidence": [
                {"path": "../secret", "start_line": 1, "end_line": 1, "explanation": "x"}
            ]}}
            flows, gaps = validate_flows(
                [outside],
                task=task,
                categories={"injection_interpretation"},
                evidence_index=index,
            )
            self.assertEqual(flows, [])
            self.assertTrue(any("outside" in gap for gap in gaps))

            source_only = {**raw, "completeness": "source_only", "sink": {}}
            flows, _ = validate_flows(
                [source_only],
                task=task,
                categories={"injection_interpretation"},
                evidence_index=index,
            )
            self.assertEqual(len(flows), 1)
            self.assertEqual(flows[0]["reachability"], "unknown")
            self.assertEqual(flows[0]["triggerability"], "unknown")

    def test_missing_checks_stay_pending_and_found_needs_complete_flow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repo"
            (repository / "src").mkdir(parents=True)
            (repository / SOURCE).write_text(TEXT, encoding="utf-8")
            index = EvidenceIndex(repository, [SOURCE])
            task = {"id": "task-1"}
            checks, gaps = validate_category_checks(
                [],
                task=task,
                expected=[
                    {"id": "cat-1", "task_id": "task-1", "category": "injection_interpretation"}
                ],
                flows=[],
                evidence_index=index,
            )
            self.assertEqual(checks[0]["status"], "pending")
            self.assertIn("not covered", checks[0]["reason"])
            self.assertTrue(gaps)

            mechanisms, gaps = validate_mechanism_checks(
                [{"kind": "original_path", "status": "checked", "outcome": "found",
                  "reason": "claimed", "flow_ids": []}],
                expected=[{"id": "mechanism-1", "task_id": "task-1", "kind": "original_path"}],
                flows=[],
                evidence_index=index,
                unit_results=[],
            )
            self.assertEqual(mechanisms[0]["outcome"], "unknown")
            self.assertEqual(mechanisms[0]["status"], "pending")
            self.assertTrue(gaps)

    def test_summary_reuse_requires_exact_conditions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repo"
            (repository / "src").mkdir(parents=True)
            (repository / SOURCE).write_text(TEXT, encoding="utf-8")
            index = EvidenceIndex(repository, [SOURCE])
            task = {"id": "task-1", "kind": "entry"}
            summaries, gaps = validate_candidates(
                [
                    {
                        "unit": {"kind": "helper", "path": SOURCE, "function_fqn": "handle"},
                        "behavior": "reads input",
                        "conditions": ["request is authenticated"],
                        "evidence": [
                            {"path": SOURCE, "start_line": 1, "end_line": 1, "explanation": "helper"}
                        ],
                    }
                ],
                task=task,
                evidence_index=index,
                repository=repository,
                revision="working-tree",
                run_id="run-1",
            )
            self.assertEqual(len(summaries), 1)
            self.assertEqual(gaps, [])
            summary_index = SummaryIndex(summaries)
            records, gaps = validate_reuse(
                [
                    {
                        "summary_id": summaries[0]["id"],
                        "match": "exact",
                        "used_for": "check",
                        "conditions_checked": True,
                    }
                ],
                task=task,
                index=summary_index,
                flow_ids=set(),
            )
            self.assertEqual(len(records), 1)
            self.assertEqual(gaps, [])

            records, gaps = validate_reuse(
                [
                    {
                        "summary_id": summaries[0]["id"],
                        "match": "partial",
                        "used_for": "check",
                        "conditions_checked": True,
                    }
                ],
                task=task,
                index=summary_index,
                flow_ids=set(),
            )
            self.assertEqual(records, [])
            self.assertTrue(gaps)

            records, gaps = validate_reuse(
                [
                    {
                        "summary_id": summaries[0]["id"],
                        "match": "exact",
                        "used_for": "check",
                        "conditions_checked": True,
                    }
                ],
                task={"id": "task-patch", "kind": "patch"},
                index=summary_index,
                flow_ids=set(),
            )
            self.assertEqual(records, [])
            self.assertTrue(any("patch" in gap for gap in gaps))


class TraceStageTest(unittest.TestCase):
    def test_gate_debt_reaches_trace_prompt_and_compact_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            task, execution, paths = _execution(root)
            audit = json.loads(paths.audit_file.read_text(encoding="utf-8"))
            audit["tasks"][0]["status"] = "partial"
            audit["gate"] = {
                "debts": [
                    {
                        "id": "debt-1",
                        "blocking": True,
                        "action": "trace",
                        "target_id": "task-1",
                        "kind": "check",
                        "reason": "missing category check",
                        "paths": [SOURCE],
                    }
                ]
            }
            write_json(paths.audit_file, audit)

            @asynccontextmanager
            async def no_yasa(settings, repository):
                yield None

            context = RunContext(
                settings=execution.settings,
                model=execution.model,
                usage=UsageRecorder(),
                audit_budget=AuditBudget.create(3600),
            )
            state = {
                "run_id": "run-1",
                "repository": str(execution.repository),
                "artifact_dir": str(paths.root),
                "scope": {"files": [SOURCE]},
                "tasks": audit["tasks"],
                "framework": {},
            }
            with patch(
                "yasa_vulnagent.stages.audit.trace.execution.open_yasa_mcp",
                no_yasa,
            ):
                asyncio.run(run_trace_stage(state, context))

            self.assertTrue(
                any(
                    prompt.get("repair", {}).get("debt_ids") == ["debt-1"]
                    for prompt in execution.model.prompts
                )
            )
            saved = json.loads(paths.audit_file.read_text(encoding="utf-8"))
            self.assertEqual(saved["traces"][0]["repair_debt_count"], 1)
            self.assertEqual(saved["traces"][0]["repair_resolved_count"], 0)

    def test_checkpoint_preserves_verify_owned_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            task, execution, paths = _execution(root)
            audit = json.loads(paths.audit_file.read_text(encoding="utf-8"))
            audit["findings"] = [{"id": "existing-finding"}]
            audit["reviews"] = [{"id": "existing-review"}]
            write_json(paths.audit_file, audit)

            @asynccontextmanager
            async def no_yasa(settings, repository):
                yield None

            context = RunContext(
                settings=execution.settings,
                model=execution.model,
                usage=UsageRecorder(),
                audit_budget=AuditBudget.create(3600),
            )
            state = {
                "run_id": "run-1",
                "repository": str(execution.repository),
                "artifact_dir": str(paths.root),
                "scope": {"files": [SOURCE]},
                "tasks": [task],
                "framework": {},
            }
            with patch(
                "yasa_vulnagent.stages.audit.trace.execution.open_yasa_mcp",
                no_yasa,
            ):
                result = asyncio.run(run_trace_stage(state, context))

            self.assertEqual(result["status"], "complete")
            saved = json.loads(paths.audit_file.read_text(encoding="utf-8"))
            self.assertEqual(saved["findings"], [{"id": "existing-finding"}])
            self.assertEqual(saved["reviews"], [{"id": "existing-review"}])
            self.assertEqual(saved["tasks"][0]["status"], "complete")
            self.assertEqual(saved["trace"]["status"], "complete")
            self.assertEqual(saved["trace"]["flow_count"], 1)
            self.assertTrue((paths.trace_dir / f"{saved['traces'][0]['id']}.json").is_file())


class TraceRepairTest(unittest.TestCase):
    def test_repair_contexts_keep_only_blocking_trace_debts(self) -> None:
        contexts = _repair_contexts(
            {
                "debts": [
                    {
                        "id": "debt-1",
                        "blocking": True,
                        "action": "trace",
                        "target_id": "task-1",
                        "kind": "check",
                        "reason": "missing check",
                        "paths": ["src/app.py"],
                    },
                    {
                        "id": "debt-2",
                        "blocking": True,
                        "action": "verify",
                        "target_id": "task-1",
                        "kind": "review",
                        "reason": "review",
                    },
                    {
                        "id": "debt-3",
                        "blocking": False,
                        "action": "trace",
                        "target_id": "task-1",
                        "kind": "task",
                        "reason": "non-blocking",
                    },
                ]
            },
            [{"id": "trace-prev", "task_id": "task-1", "gaps": ["previous gap"]}],
        )

        self.assertEqual(list(contexts), ["task-1"])
        self.assertEqual(contexts["task-1"]["debt_ids"], ["debt-1"])
        self.assertEqual(contexts["task-1"]["prior_trace_id"], "trace-prev")
        self.assertEqual(contexts["task-1"]["prior_gaps"], ["previous gap"])

    def test_repair_responses_are_validated_and_counted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            task, execution, _ = _execution(Path(temporary))
            payload = {
                "status": "complete",
                "summary": "repaired",
                "categories": [
                    {
                        "category": "injection_interpretation",
                        "status": "checked",
                        "applicability": "applicable",
                        "reason": "reviewed",
                        "flow_ids": [],
                        "evidence": [],
                    }
                ],
                "repair_responses": [
                    {
                        "debt_id": "debt-1",
                        "status": "resolved",
                        "reason": "added the missing category check",
                    },
                    {
                        "debt_id": "debt-2",
                        "status": "unresolved",
                        "reason": "source does not support closure",
                    },
                ],
            }

            result = validate_lead(
                payload,
                task=task,
                specialist_results=[],
                expected_categories=execution.category_checks_for(task),
                expected_mechanisms=[],
                evidence_index=execution.evidence,
                summary_index=execution.summary_index,
                repository=execution.repository,
                revision=execution.revision,
                run_id=execution.run_id,
                repair_debts=[{"id": "debt-1"}, {"id": "debt-2"}, {"id": "debt-3"}],
            )

            self.assertEqual(result["repair_debt_count"], 3)
            self.assertEqual(result["repair_resolved_count"], 1)
            self.assertEqual(result["repair_unresolved_count"], 1)
            self.assertFalse(result["repair_complete"])
            self.assertTrue(any("missing debts" in gap for gap in result["gaps"]))

    def test_lead_prompt_contains_repair_and_known_rejections(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            task, execution, _ = _execution(Path(temporary))
            execution.repair_by_task = {
                "task-1": {
                    "debt_ids": ["debt-1"],
                    "debts": [{"id": "debt-1", "reason": "missing check"}],
                }
            }
            execution.rejections = RejectionIndex.from_audit(
                [
                    {
                        "id": "finding-1",
                        "task_id": "task-1",
                        "verdict": "rejected",
                        "title": "guarded flow",
                        "category": "injection_interpretation",
                        "reason": "guard is effective",
                        "evidence": [{"path": SOURCE, "start_line": 2, "end_line": 3}],
                    }
                ],
                [
                    {
                        "id": "review-1",
                        "type": "finding",
                        "target_id": "finding-1",
                        "status": "complete",
                        "verdict": "rejected",
                    }
                ],
            )
            prompt = _prompt(
                task,
                {"chains": [], "excerpts": [], "yasa": {}},
                {"units": [], "delegations": [], "gaps": []},
                [],
                execution,
            )

            self.assertEqual(prompt["repair"]["debt_ids"], ["debt-1"])
            self.assertEqual(prompt["known_rejections"][0]["id"], "finding-1")

class TraceGraphTest(unittest.TestCase):
    def test_entry_task_produces_candidate_flow_not_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            task, execution, _ = _execution(Path(temporary))
            outcome = asyncio.run(run_trace_task(task, execution, audit_paths(Path(temporary) / "stages")))
            self.assertEqual(outcome["status"], "complete")
            self.assertEqual(outcome["trace"]["flow_count"], 1)
            self.assertEqual(outcome["trace"]["complete_flow_count"], 1)
            self.assertTrue(outcome["trace"]["coverage_complete"])
            self.assertEqual(outcome["category_checks"][0]["status"], "checked")
            artifact = execution.audit_dir / "traces" / f"{outcome['trace']['id']}.json"
            payload = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertNotIn("findings", payload)
            self.assertEqual(payload["flows"][0]["completeness"], "complete")

    def test_patch_task_runs_mandatory_patch_specialist(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            task, execution, _ = _execution(root, patch=True)
            outcome = asyncio.run(run_trace_task(task, execution, audit_paths(root / "stages")))
            self.assertEqual(outcome["status"], "complete")
            self.assertIn("patch", outcome["specialist_roles"])
            self.assertEqual(len(outcome["mechanism_checks"]), 3)
            self.assertTrue(all(check["status"] == "checked" for check in outcome["mechanism_checks"]))
            self.assertEqual(outcome["unit_results"][0]["effectiveness"], "bypassed")
            self.assertTrue(outcome["trace"]["coverage_complete"])


if __name__ == "__main__":
    unittest.main()
