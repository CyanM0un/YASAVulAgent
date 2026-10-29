from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import patch

from yasa_vulnagent.agent.runtime import run_coroutine
from yasa_vulnagent.agent.usage import UsageRecorder
from yasa_vulnagent.config import Settings
from yasa_vulnagent.stages.audit.budget import AuditBudget
from yasa_vulnagent.stages.audit.recon.execution import run_recon_stage
from yasa_vulnagent.stages.audit.trace.graph import _coverage
from yasa_vulnagent.stages.audit.recon.model import (
    ReconBudgetError,
    ReconConfigurationError,
    ReconModelError,
)
from yasa_vulnagent.stages.audit.schema import empty_state
from yasa_vulnagent.stages.audit.storage import audit_paths, write_json
from yasa_vulnagent.workflow.state import RunContext

SOURCE = "src/app.py"
TEXT = "def export(request):\n    tenant = request.args['tenant_id']\n    return repository.export(tenant)\n"


class _Response:
    def __init__(self, content: str) -> None:
        self.content = content
        self.tool_calls = []


class _Model:
    def __init__(self, payload: dict, *, fail: bool = False) -> None:
        self.payload = payload
        self.fail = fail
        self.calls = 0

    def bind_tools(self, tools):
        return self

    async def ainvoke(self, messages):
        self.calls += 1
        if self.fail:
            raise RuntimeError("model unavailable")
        return _Response(json.dumps(self.payload))


@asynccontextmanager
async def _no_mcp(settings, repository):
    yield None


def _state(
    root: Path,
    *,
    tasks: list[dict] | None = None,
    traces: list[dict] | None = None,
) -> tuple[dict, object, Path]:
    repository = root / "repository"
    (repository / "src").mkdir(parents=True)
    (repository / SOURCE).write_text(TEXT, encoding="utf-8")
    stages = root / "stages"
    stages.mkdir()
    paths = audit_paths(stages)
    overview = root / "overview.md"
    overview.write_text("Only tenant administrators may export their own tenant orders.\n", encoding="utf-8")
    state = empty_state(
        {"run_id": "run-1", "repository": str(repository), "audit_mode": "combined"},
        paths,
    )
    state["prepare"] = {
        "status": "complete",
        "source_revision": "working-tree",
        "inputs": {"overview_file": str(overview)},
    }
    state["scope"] = {
        "files": [SOURCE],
        "entry_ids": ["entry-1"],
        "patch_ids": [],
        "limitations": [],
    }
    state["entries"] = [
        {
            "id": "entry-1",
            "name": "export",
            "entry_location": {"path": SOURCE, "start_line": 1, "end_line": 3},
        }
    ]
    state["tasks"] = list(tasks or [])
    write_json(
        paths.audit_file,
        {
            "run_id": "run-1",
            "repo": str(repository),
            "mode": "combined",
            "status": "partial",
            "business_artifact": "business-logic.json",
            "scope": state["scope"],
            "entries": state["entries"],
            "patches": [],
            "tasks": state["tasks"],
            "traces": list(traces or []),
            "category_checks": [{"id": "category-keep"}],
            "mechanism_checks": [{"id": "mechanism-keep"}],
            "summaries": [],
            "findings": [{"id": "finding-keep"}],
            "reviews": [{"id": "review-keep"}],
            "gaps": [],
        },
    )
    return state, paths, repository


def _context(model=None, *, api_key: str | None = "test", budget: AuditBudget | None = None) -> RunContext:
    settings = Settings(
        api_key=api_key,
        base_url="http://localhost",
        model="fake",
        audit_timeout=3600,
        agent_hard_task_cap=5,
    )
    return RunContext(
        settings=settings,
        model=model,
        usage=UsageRecorder(settings.usage_price_table),
        audit_budget=budget or AuditBudget.create(3600),
    )


def _task() -> dict:
    return {
        "id": "task-entry-1",
        "kind": "entry",
        "status": "planned",
        "entry_ids": ["entry-1"],
        "patch_ids": [],
        "origin_task_ids": [],
        "business_refs": {},
        "repair_unit_refs": [],
        "paths": [SOURCE],
        "priority": "normal",
    }


def _payload(*, evidence_path: str = SOURCE, outcome: str = "unknown") -> dict:
    evidence = [
        {
            "path": evidence_path,
            "start_line": 1,
            "end_line": 3,
            "explanation": "tenant scope in the export entry",
        }
    ]
    return {
        "constraints": [
            {
                "id": "constraint-tenant-export",
                "description": "Tenant admins export only their own tenant.",
                "source_kind": "documentation",
                "applicability": "applicable",
                "supporting_evidence": evidence,
            }
        ],
        "operations": [
            {
                "id": "operation-export",
                "name": "Export orders",
                "entry_ids": ["entry-1"],
                "locations": evidence,
                "evidence": evidence,
            }
        ],
        "investigations": [
            {
                "id": "investigation-tenant-binding",
                "task_id": "task-entry-1",
                "question": "Is tenant_id bound from the authenticated principal?",
                "constraint_ids": ["constraint-tenant-export"],
                "operation_ids": ["operation-export"],
                "outcome": outcome,
                "evidence": evidence,
            }
        ],
        "logic_tasks": [
            {
                "origin_task_ids": ["task-entry-1"],
                "business_refs": {
                    "constraint_ids": ["constraint-tenant-export"],
                    "operation_ids": ["operation-export"],
                    "investigation_ids": ["investigation-tenant-binding"],
                },
                "paths": [SOURCE],
                "priority": "high",
                "question": "Does the batch export use the same tenant binding?",
                "evidence": evidence,
            }
        ],
        "gaps": [],
        "warnings": [],
        "limitations": [],
    }


class ReconTest(unittest.TestCase):
    def test_valid_output_writes_sidecar_and_logic_task(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, paths, _repository = _state(Path(temporary), tasks=[_task()])
            model = _Model(_payload())
            with patch("yasa_vulnagent.stages.audit.recon.execution.open_yasa_mcp", _no_mcp):
                result = run_coroutine(run_recon_stage(state, _context(model)))

            business = json.loads(paths.business_file.read_text(encoding="utf-8"))
            audit = json.loads(paths.audit_file.read_text(encoding="utf-8"))
            self.assertEqual(result["next_action"], "trace")
            self.assertTrue(result["framework"]["recon_done"])
            self.assertEqual(result["recon"]["constraint_count"], 1)
            self.assertEqual(result["recon"]["logic_task_count"], 1)
            self.assertEqual(business["status"], "partial")
            self.assertEqual(business["constraints"][0]["supporting_evidence"][0]["code"], TEXT.rstrip("\n"))
            self.assertEqual(audit["recon"]["status"], "partial")
            self.assertEqual(audit["findings"], [{"id": "finding-keep"}])
            self.assertEqual(audit["reviews"], [{"id": "review-keep"}])
            self.assertEqual(audit["tasks"][-1]["kind"], "logic")
            self.assertEqual(audit["category_checks"], [{"id": "category-keep"}])
            self.assertEqual(audit["mechanism_checks"], [{"id": "mechanism-keep"}])
            self.assertEqual(model.calls, 1)

    def test_missing_model_with_tasks_fails_without_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, paths, _repository = _state(Path(temporary), tasks=[_task()])
            with self.assertRaises(ReconConfigurationError):
                run_coroutine(run_recon_stage(state, _context(None, api_key=None)))
            self.assertFalse(paths.business_file.exists())

    def test_invalid_evidence_fails_without_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, paths, _repository = _state(Path(temporary), tasks=[_task()])
            model = _Model(_payload(evidence_path="src/other.py"))
            with patch("yasa_vulnagent.stages.audit.recon.execution.open_yasa_mcp", _no_mcp):
                with self.assertRaises(ReconModelError):
                    run_coroutine(run_recon_stage(state, _context(model)))
            self.assertFalse(paths.business_file.exists())

    def test_source_revision_mismatch_fails_without_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, paths, _repository = _state(Path(temporary), tasks=[_task()])
            state["prepare"]["source_revision"] = "a" * 40
            with self.assertRaises(ReconConfigurationError):
                run_coroutine(run_recon_stage(state, _context(None)))
            self.assertFalse(paths.business_file.exists())

    def test_model_failure_fails_without_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, paths, _repository = _state(Path(temporary), tasks=[_task()])
            model = _Model(_payload(), fail=True)
            with patch("yasa_vulnagent.stages.audit.recon.execution.open_yasa_mcp", _no_mcp):
                with self.assertRaises(ReconModelError):
                    run_coroutine(run_recon_stage(state, _context(model)))
            self.assertFalse(paths.business_file.exists())

    def test_budget_exhaustion_fails_without_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, paths, _repository = _state(Path(temporary), tasks=[_task()])
            budget = AuditBudget(deadline=0, started_at=0)
            with self.assertRaises(ReconBudgetError):
                run_coroutine(run_recon_stage(state, _context(None, budget=budget)))
            self.assertFalse(paths.business_file.exists())

    def test_no_business_tasks_writes_empty_sidecar_without_model(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, paths, _repository = _state(Path(temporary))
            result = run_coroutine(run_recon_stage(state, _context(None, api_key=None)))
            business = json.loads(paths.business_file.read_text(encoding="utf-8"))
            self.assertEqual(result["recon"]["status"], "complete")
            self.assertEqual(business["status"], "complete")
            self.assertEqual(business["constraints"], [])
            self.assertEqual(business["model"]["status"], "not_run")

    def test_logic_task_already_answered_by_trace_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            question = "Does the batch export use the same tenant binding?"
            state, paths, _repository = _state(
                Path(temporary),
                tasks=[_task()],
                traces=[
                    {
                        "id": "trace-1",
                        "task_id": "task-entry-1",
                        "kind": "entry",
                        "status": "complete",
                        "coverage_complete": True,
                        "summary": question,
                    }
                ],
            )
            payload = _payload()
            payload["logic_tasks"][0]["question"] = question
            with patch("yasa_vulnagent.stages.audit.recon.execution.open_yasa_mcp", _no_mcp):
                result = run_coroutine(run_recon_stage(state, _context(_Model(payload))))
            self.assertEqual(result["recon"]["logic_task_count"], 0)

    def test_logic_task_coverage_requires_a_flow_or_summary(self) -> None:
        self.assertTrue(_coverage({"flows": [{"id": "flow-1"}]}, {"kind": "logic"}))
        self.assertFalse(_coverage({}, {"kind": "logic"}))
        self.assertFalse(_coverage({"categories": []}, {"kind": "entry"}))

    def test_no_tasks_preserves_existing_complete_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, paths, _repository = _state(Path(temporary))
            write_json(
                paths.business_file,
                {
                    "run_id": "run-1",
                    "repo": state["repository"],
                    "mode": "combined",
                    "status": "complete",
                    "scope": {"files": [SOURCE]},
                    "constraints": [{"id": "constraint-existing"}],
                    "operations": [],
                    "investigations": [],
                },
            )
            result = run_coroutine(run_recon_stage(state, _context(None, api_key=None)))
            business = json.loads(paths.business_file.read_text(encoding="utf-8"))
            self.assertEqual(result["recon"]["constraint_count"], 1)
            self.assertEqual(business["constraints"], [{"id": "constraint-existing"}])

    def test_existing_complete_sidecar_is_reused_without_model(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, paths, _repository = _state(Path(temporary), tasks=[_task()])
            write_json(
                paths.business_file,
                {
                    "run_id": "run-1",
                    "repo": state["repository"],
                    "mode": "combined",
                    "status": "complete",
                    "scope": {"files": [SOURCE]},
                    "constraints": [],
                    "operations": [],
                    "investigations": [],
                },
            )
            model = _Model(_payload())
            result = run_coroutine(run_recon_stage(state, _context(model, api_key=None)))
            self.assertEqual(result["recon"]["model"]["status"], "existing")
            self.assertEqual(model.calls, 0)


if __name__ == "__main__":
    unittest.main()
