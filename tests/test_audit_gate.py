from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from yasa_vulnagent.config import Settings
from yasa_vulnagent.stages.audit.budget import AuditBudget
from yasa_vulnagent.stages.audit.categories import load_category_manifest
from yasa_vulnagent.stages.audit.gate.node import gate
from yasa_vulnagent.stages.audit.verify.result import candidate_key, finding_id
from yasa_vulnagent.workflow.state import RunContext


class AuditGateTest(unittest.TestCase):
    def _context(self, *, expired: bool = False) -> SimpleNamespace:
        settings = Settings(api_key=None, base_url="http://localhost", model="fake")
        budget = AuditBudget(deadline=0, started_at=0) if expired else None
        return SimpleNamespace(context=RunContext(settings=settings, audit_budget=budget))

    def _flow(self) -> dict:
        return {
            "category": "injection_interpretation",
            "kind": "entry",
            "source": {
                "evidence": [{"path": "src/app.py", "start_line": 3, "end_line": 3}]
            },
            "sink": {
                "evidence": [{"path": "src/app.py", "start_line": 8, "end_line": 8}]
            },
            "reachability": "reachable",
            "triggerability": "triggerable",
            "preconditions": [],
            "summary": "request reaches a query",
        }

    def _entry_task(self) -> dict:
        return {
            "id": "task-1",
            "kind": "entry",
            "status": "complete",
            "entry_ids": ["entry-1"],
            "patch_ids": [],
            "paths": ["src/app.py"],
        }

    def _checks(self, task: dict) -> list[dict]:
        return [
            {
                "id": f"check-{category.id}",
                "task_id": task["id"],
                "category": category.id,
                "status": "checked",
            }
            for category in load_category_manifest().for_kind("entry")
        ]

    def _setup(
        self,
        root: Path,
        *,
        tasks: list[dict],
        traces: list[dict] | None = None,
        entries: list[dict] | None = None,
        patches: list[dict] | None = None,
        findings: list[dict] | None = None,
        reviews: list[dict] | None = None,
        flows: list[dict] | None = None,
        gaps: list[dict] | None = None,
        mode: str = "entries",
    ) -> tuple[dict, Path]:
        audit_dir = root / "stages" / "audit"
        audit_dir.mkdir(parents=True)
        traces = traces or []
        for trace in traces:
            self._write(
                audit_dir / "traces" / f"{trace['id']}.json",
                {"flows": flows or []},
            )
        audit = {
            "run_id": "run-test",
            "mode": mode,
            "status": "partial",
            "scope": {"files": ["src/app.py"]},
            "entries": entries or [],
            "patches": patches or [],
            "tasks": tasks,
            "traces": traces,
            "category_checks": [
                check
                for task in tasks
                for check in self._checks(task)
                if task.get("kind") == "entry"
            ],
            "mechanism_checks": [],
            "findings": findings or [],
            "reviews": reviews or [],
            "gaps": gaps or [],
        }
        self._write(audit_dir / "audit.json", audit)
        self._write(
            audit_dir / "business-logic.json",
            {
                "status": "partial",
                "constraints": [],
                "operations": [],
                "investigations": [],
                "gaps": [],
            },
        )
        state = {
            "run_id": "run-test",
            "repository": str(root),
            "artifact_dir": str(audit_dir),
            "audit_file": str(audit_dir / "audit.json"),
            "business_file": str(audit_dir / "business-logic.json"),
            "report_file": str(audit_dir / "report.md"),
            "index_file": str(audit_dir / "index.json"),
            "validation_file": str(audit_dir / "validation.json"),
            "mode": mode,
            "scope": {"files": ["src/app.py"]},
            "framework": {"executed": [], "visits": {}, "recon_done": True},
            "gate": {},
        }
        return state, audit_dir

    def _write(self, path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")

    def _read(self, path: Path) -> dict:
        return json.loads(path.read_text(encoding="utf-8"))

    def test_candidate_flow_routes_to_verify(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            task = self._entry_task()
            state, audit_dir = self._setup(
                root,
                tasks=[task],
                entries=[{"id": "entry-1", "paths": ["src/app.py"]}],
                traces=[
                    {
                        "id": "trace-1",
                        "task_id": task["id"],
                        "status": "complete",
                        "coverage_complete": True,
                    }
                ],
                flows=[self._flow()],
            )

            update = gate(state, runtime=self._context())

            self.assertEqual(update["next_action"], "verify")
            self.assertEqual(update["status"], "partial")
            self.assertEqual(update["gate"]["action"], "verify")
            self.assertEqual(len(update["gate"]["fingerprint"]), 64)
            self.assertEqual(update["tasks"], [task])
            self.assertFalse((audit_dir / "gate.json").exists())
            audit = self._read(audit_dir / "audit.json")
            self.assertEqual(audit["gate"]["action"], "verify")

    def test_complete_entry_scope_closes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            task = self._entry_task()
            state, _ = self._setup(
                root,
                tasks=[task],
                entries=[{"id": "entry-1", "paths": ["src/app.py"]}],
                traces=[
                    {
                        "id": "trace-1",
                        "task_id": task["id"],
                        "status": "complete",
                        "coverage_complete": True,
                    }
                ],
            )

            update = gate(state, runtime=self._context())

            self.assertEqual(update["next_action"], "finalize")
            self.assertEqual(update["status"], "complete")
            self.assertEqual(update["gate"]["blocking_count"], 0)

    def test_verified_finding_with_complete_review_closes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            task = self._entry_task()
            flow = self._flow()
            key = candidate_key(flow)
            finding = {
                "id": finding_id("run-test", key),
                "candidate_key": key,
                "verdict": "confirmed",
                "title": "query injection",
                "evidence": [
                    {"path": "src/app.py", "start_line": 3, "end_line": 8}
                ],
            }
            review = {
                "id": "review-1",
                "type": "finding",
                "target_id": finding["id"],
                "status": "complete",
                "verdict": "confirmed",
            }
            state, _ = self._setup(
                root,
                tasks=[task],
                entries=[{"id": "entry-1", "paths": ["src/app.py"]}],
                traces=[
                    {
                        "id": "trace-1",
                        "task_id": task["id"],
                        "status": "complete",
                        "coverage_complete": True,
                    }
                ],
                flows=[flow],
                findings=[finding],
                reviews=[review],
            )

            update = gate(state, runtime=self._context())

            self.assertEqual(update["next_action"], "finalize")
            self.assertEqual(update["status"], "complete")
            self.assertEqual(update["gate"]["confirmed_count"], 1)

    def test_review_with_opposite_verdict_is_not_complete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            task = self._entry_task()
            flow = self._flow()
            key = candidate_key(flow)
            finding = {
                "id": finding_id("run-test", key),
                "candidate_key": key,
                "verdict": "confirmed",
                "title": "query injection",
                "evidence": [
                    {"path": "src/app.py", "start_line": 3, "end_line": 8}
                ],
            }
            state, _ = self._setup(
                root,
                tasks=[task],
                entries=[{"id": "entry-1", "paths": ["src/app.py"]}],
                traces=[
                    {
                        "id": "trace-1",
                        "task_id": task["id"],
                        "status": "complete",
                        "coverage_complete": True,
                    }
                ],
                flows=[flow],
                findings=[finding],
                reviews=[
                    {
                        "id": "review-1",
                        "type": "finding",
                        "target_id": finding["id"],
                        "status": "complete",
                        "verdict": "rejected",
                    }
                ],
            )

            update = gate(state, runtime=self._context())

            self.assertEqual(update["next_action"], "verify")
            self.assertEqual(update["gate"]["review_debt_count"], 1)

    def test_missing_coverage_reopens_task_and_routes_to_trace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            task = self._entry_task()
            state, _ = self._setup(
                root,
                tasks=[task],
                entries=[{"id": "entry-1", "paths": ["src/app.py"]}],
                traces=[
                    {
                        "id": "trace-1",
                        "task_id": task["id"],
                        "status": "complete",
                        "coverage_complete": False,
                    }
                ],
            )

            update = gate(state, runtime=self._context())

            self.assertEqual(update["next_action"], "trace")
            self.assertEqual(update["status"], "partial")
            self.assertEqual(update["tasks"][0]["status"], "partial")
            self.assertEqual(update["gate"]["trace_debt_count"], 1)

    def test_confirmed_without_complete_review_is_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            task = self._entry_task()
            flow = self._flow()
            finding = {
                "id": finding_id("run-test", candidate_key(flow)),
                "candidate_key": candidate_key(flow),
                "verdict": "confirmed",
                "title": "query injection",
                "evidence": [
                    {"path": "src/app.py", "start_line": 3, "end_line": 8}
                ],
            }
            state, audit_dir = self._setup(
                root,
                tasks=[task],
                entries=[{"id": "entry-1", "paths": ["src/app.py"]}],
                traces=[
                    {
                        "id": "trace-1",
                        "task_id": task["id"],
                        "status": "complete",
                        "coverage_complete": True,
                    }
                ],
                flows=[flow],
                findings=[finding],
            )

            update = gate(state, runtime=self._context())

            self.assertEqual(update["next_action"], "verify")
            self.assertEqual(update["status"], "partial")
            self.assertEqual(update["gate"]["review_debt_count"], 1)
            self.assertEqual(update["gate"]["blocking_count"], 1)
            audit = self._read(audit_dir / "audit.json")
            self.assertEqual(audit["gate"]["stop_reason"], "gate_pending")

    def test_rejected_without_complete_review_routes_to_verify(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            task = self._entry_task()
            finding = {
                "id": "finding-rejected",
                "candidate_key": "candidate-rejected",
                "verdict": "rejected",
                "title": "guarded query",
                "evidence": [
                    {"path": "src/app.py", "start_line": 3, "end_line": 8}
                ],
            }
            state, _ = self._setup(
                root,
                tasks=[task],
                entries=[{"id": "entry-1", "paths": ["src/app.py"]}],
                traces=[
                    {
                        "id": "trace-1",
                        "task_id": task["id"],
                        "status": "complete",
                        "coverage_complete": True,
                    }
                ],
                findings=[finding],
            )

            update = gate(state, runtime=self._context())

            self.assertEqual(update["next_action"], "verify")
            self.assertEqual(update["gate"]["action"], "verify")
            self.assertEqual(update["gate"]["review_debt_count"], 1)

    def test_rejected_with_complete_review_closes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            task = self._entry_task()
            finding = {
                "id": "finding-rejected",
                "candidate_key": "candidate-rejected",
                "verdict": "rejected",
                "title": "guarded query",
                "evidence": [
                    {"path": "src/app.py", "start_line": 3, "end_line": 8}
                ],
            }
            state, _ = self._setup(
                root,
                tasks=[task],
                entries=[{"id": "entry-1", "paths": ["src/app.py"]}],
                traces=[
                    {
                        "id": "trace-1",
                        "task_id": task["id"],
                        "status": "complete",
                        "coverage_complete": True,
                    }
                ],
                findings=[finding],
                reviews=[
                    {
                        "id": "review-finding-rejected",
                        "type": "finding",
                        "target_id": "finding-rejected",
                        "status": "complete",
                        "verdict": "rejected",
                    }
                ],
            )

            update = gate(state, runtime=self._context())

            self.assertEqual(update["next_action"], "finalize")
            self.assertEqual(update["status"], "complete")
            self.assertEqual(update["gate"]["review_debt_count"], 0)

    def test_needs_validation_is_terminal_for_verify(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            task = {
                "id": "logic-1",
                "kind": "logic",
                "status": "complete",
                "entry_ids": ["entry-1"],
                "paths": ["src/app.py"],
            }
            finding = {
                "id": "finding-needs-validation",
                "candidate_key": "key",
                "verdict": "needs_validation",
                "title": "needs runtime",
                "missing_facts": ["runtime configuration"],
            }
            state, _ = self._setup(
                root,
                tasks=[task],
                entries=[{"id": "entry-1", "paths": ["src/app.py"]}],
                traces=[
                    {
                        "id": "trace-1",
                        "task_id": task["id"],
                        "status": "complete",
                        "coverage_complete": True,
                    }
                ],
                findings=[finding],
            )

            update = gate(state, runtime=self._context())

            self.assertEqual(update["next_action"], "finalize")
            self.assertEqual(update["status"], "complete")
            self.assertEqual(update["gate"]["needs_validation_count"], 1)
            self.assertEqual(update["gate"]["validation_pending"][0]["finding_id"], "finding-needs-validation")

    def test_not_applicable_patch_can_close_with_blocked_task(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            task = {
                "id": "patch-1",
                "kind": "patch",
                "status": "blocked",
                "entry_ids": [],
                "patch_ids": ["patch-1"],
                "paths": [],
            }
            patch = {
                "id": "patch-1",
                "status": "not_applicable",
                "changed_paths": ["src/app.py"],
                "repair_unit_ids": [],
                "units": [],
            }
            state, _ = self._setup(
                root,
                tasks=[task],
                patches=[patch],
                mode="patches",
            )

            update = gate(state, runtime=self._context())

            self.assertEqual(update["next_action"], "finalize")
            self.assertEqual(update["status"], "complete")
            self.assertEqual(update["gate"]["accepted_blocked_count"], 1)
            self.assertEqual(update["gate"]["blocking_count"], 0)

    def test_budget_exhaustion_finalizes_partial(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            task = self._entry_task()
            task["status"] = "partial"
            state, _ = self._setup(
                root,
                tasks=[task],
                entries=[{"id": "entry-1", "paths": ["src/app.py"]}],
            )

            update = gate(state, runtime=self._context(expired=True))

            self.assertEqual(update["next_action"], "finalize")
            self.assertEqual(update["status"], "partial")
            self.assertEqual(update["stop_reason"], "gate_budget_exhausted")

    def test_same_fingerprint_stops_routing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            task = self._entry_task()
            task["status"] = "partial"
            state, _ = self._setup(
                root,
                tasks=[task],
                entries=[{"id": "entry-1", "paths": ["src/app.py"]}],
            )
            first = gate(state, runtime=self._context())
            state["gate"] = first["gate"]
            state["tasks"] = first["tasks"]
            state["framework"] = first["framework"]

            second = gate(state, runtime=self._context())

            self.assertEqual(second["next_action"], "finalize")
            self.assertEqual(second["status"], "partial")
            self.assertEqual(second["stop_reason"], "gate_no_progress")


if __name__ == "__main__":
    unittest.main()
