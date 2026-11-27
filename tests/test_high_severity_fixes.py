from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from yasa_vulnagent.agent.budget import BudgetStop, TaskBudget
from yasa_vulnagent.agent.retry import RetryPolicy
from yasa_vulnagent.config import load_settings
from yasa_vulnagent.stages.audit.verify.result import freshly_read
from yasa_vulnagent.stages.discover.confirm.node import _apply_task_result
from yasa_vulnagent.stages.discover.ledger import DiscoverLedger
from yasa_vulnagent.stages.init.documents.tools import DocumentToolbox
from yasa_vulnagent.stages.init.index import InitIndex
from yasa_vulnagent.stages.report.intake import select_findings as select_report_findings
from yasa_vulnagent.stages.validate.commands import CommandDenied, ShellRunner
from yasa_vulnagent.stages.validate.contract import _normalize as normalize_validation
from yasa_vulnagent.stages.validate.environment.gate import evaluate_plan
from yasa_vulnagent.stages.validate.storage import validation_paths


class HighSeverityFixesTest(unittest.TestCase):
    def test_budget_enforces_max_rounds_per_invocation(self) -> None:
        budget = TaskBudget(max_model_calls=20, max_rounds_per_invocation=2)
        budget.consume_tool_round()
        budget.consume_tool_round()
        self.assertEqual(budget.exhausted_reason(), "round_limit")
        with self.assertRaises(BudgetStop) as error:
            budget.consume_tool_round()
        self.assertEqual(error.exception.reason, "round_limit")

    def test_retry_tool_sleeps_when_deadline_is_none(self) -> None:
        calls = 0

        def flaky() -> str:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise TimeoutError("transient timeout")
            return "ok"

        with patch("yasa_vulnagent.agent.retry.time.sleep") as mocked_sleep:
            result = RetryPolicy(tool_attempts=2).tool(flaky, deadline=None)
        self.assertEqual(result, "ok")
        mocked_sleep.assert_called_once_with(0.2)

    def test_init_index_preserves_multichunk_notes_and_indexes_commit_rationale(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            notes_dir = root / "notes"
            notes_dir.mkdir()
            (notes_dir / "doc1-1.json").write_text(
                json.dumps({"document_id": "doc1", "source": "README.md", "summary": "alpha token"}),
                encoding="utf-8",
            )
            (notes_dir / "doc1-2.json").write_text(
                json.dumps({"document_id": "doc1", "source": "README.md", "summary": "beta token"}),
                encoding="utf-8",
            )
            index = InitIndex(root / "index.sqlite")
            try:
                index.rebuild_documents(notes_dir)
                self.assertEqual(len(index.search_notes("alpha")["results"]), 1)
                self.assertEqual(len(index.search_notes("beta")["results"]), 1)

                index.upsert_commit(
                    {
                        "commit": "abc123",
                        "rationale": "Fix SQL injection in login query",
                        "security_signals": ["sqli"],
                        "locations": [{"path": "src/auth.py"}],
                    }
                )
                matches = index.search_commits("injection")["results"]
                self.assertEqual(len(matches), 1)
                self.assertEqual(matches[0]["sha"], "abc123")
            finally:
                index.close()

    def test_read_docx_sets_next_block_when_truncated_by_chunk_chars(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            docx_path = root / "spec.docx"
            docx_path.write_bytes(b"placeholder")
            toolbox = DocumentToolbox(root, root / "artifacts", chunk_chars=45)
            blocks = ["First block content", "Second block content", "Third block content"]
            fake_docx = SimpleNamespace(Document=lambda _path: object())
            with (
                patch.dict(sys.modules, {"docx": fake_docx}),
                patch.object(toolbox, "_docx_blocks_cached", return_value=blocks),
            ):
                result = toolbox.read_docx("spec.docx")
            self.assertEqual(result["start_block"], 1)
            self.assertEqual(result["end_block"], 1)
            self.assertEqual(result["next_block"], 2)
            self.assertTrue(result["truncated"])

    def test_discover_confirm_retry_and_same_file_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            source = repo / "app.py"
            source.write_text("def handle_a():\n    pass\n\ndef handle_b():\n    pass\n", encoding="utf-8")
            ledger = DiscoverLedger.open(Path(tmp) / "ledger.sqlite")
            try:
                ledger.replace_inventory(
                    files=[
                        {
                            "path": "app.py",
                            "size": 40,
                            "fingerprint": "app-fp",
                            "content_type": "text",
                            "usage_hint": "production-candidate",
                            "status": "pending",
                        }
                    ],
                    excluded=[],
                )
                ledger.put_entry(
                    {
                        "entry_id": "e1",
                        "status": "confirmed",
                        "role": "source",
                        "location": {"path": "app.py", "line_start": 1, "line_end": 2},
                    }
                )
                ledger.put_entry(
                    {
                        "entry_id": "e2",
                        "status": "candidate",
                        "role": "source",
                        "location": {"path": "app.py", "line_start": 4, "line_end": 5},
                    }
                )
                ledger.put_evidence(
                    {
                        "evidence_id": "ev1",
                        "path": "app.py",
                        "line_start": 4,
                        "line_end": 5,
                        "summary": "handler b",
                    }
                )
                task = {"task_id": "confirm-1", "candidate_ids": ["e1", "e2"], "origin": "screen"}
                updated = _apply_task_result(
                    repo,
                    ledger,
                    task,
                    {
                        "same_file_reviewed": True,
                        "entry_results": [
                            {
                                "entry_id": "e2",
                                "status": "not_applicable",
                                "reason": "internal helper",
                                "evidence_refs": ["app.py:4-5"],
                                "location": {"path": "app.py", "line_start": 4, "line_end": 5},
                            }
                        ],
                    },
                )
                self.assertEqual(updated["status"], "complete")

                sf_task = {"task_id": "confirm-sf", "candidate_ids": [], "origin": "same_file"}
                sf_updated = _apply_task_result(
                    repo,
                    ledger,
                    sf_task,
                    {
                        "same_file_reviewed": True,
                        "entry_results": [
                            {
                                "entry_id": "e3",
                                "status": "not_applicable",
                                "reason": "helper",
                                "evidence_refs": ["app.py:4-5"],
                                "location": {"path": "app.py", "line_start": 4, "line_end": 5},
                            }
                        ],
                    },
                )
                self.assertEqual(sf_updated["status"], "complete")
                self.assertIsNotNone(ledger.get_entry("e3"))
            finally:
                ledger.close()

    def test_audit_freshly_read_requires_all_ranges_in_same_file(self) -> None:
        ok, missing = freshly_read(
            evidence=[
                {"path": "app.py", "start_line": 1, "end_line": 10},
                {"path": "app.py", "start_line": 50, "end_line": 60},
            ],
            receipts=[
                {"tool": "read_file", "status": "ok", "path": "app.py", "start_line": 1, "end_line": 20},
            ],
        )
        self.assertFalse(ok)
        self.assertEqual(missing, ["app.py"])

    def test_report_select_findings_unlimited_when_limit_nonpositive(self) -> None:
        validation = {
            "findings": [
                {"id": "f1", "disposition": "confirmed"},
                {"id": "f2", "disposition": "confirmed"},
            ]
        }
        selected, omitted = select_report_findings(validation, None, limit=0)
        self.assertEqual(len(selected), 2)
        self.assertEqual(omitted, 0)

    def test_validate_command_and_mount_gate_block_bypass_variants(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runner = ShellRunner(
                root=root,
                repository=root,
                settings=load_settings(),
                log_dir=root / "logs",
            )
            with self.assertRaises(CommandDenied):
                runner.check("echo $(sudo id)")
            with self.assertRaises(CommandDenied):
                runner.check("echo ok\nsudo id")

            gate = evaluate_plan(
                {
                    "base_image": "python:3.12",
                    "dockerfile": [
                        {"instruction": "FROM", "arguments": "python:3.12"},
                        {
                            "instruction": "RUN",
                            "arguments": "--mount=type=bind,src=/etc,target=/mnt/etc cat /mnt/etc/passwd",
                        },
                    ],
                    "smoke_commands": [["python", "--version"]],
                    "inspection": {"evidence": [{"path": "pyproject.toml", "start_line": 1, "end_line": 5}]},
                },
                receipts=[
                    {"tool": "read_file", "status": "ok", "path": "pyproject.toml", "start_line": 1, "end_line": 10}
                ],
                settings=load_settings(),
            )
            self.assertEqual(gate["status"], "revise")
            self.assertTrue(any(item["code"] == "buildkit_host_bind" for item in gate["hard_errors"]))

    def test_validate_contract_rejects_missing_verifier_disposition(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = validation_paths(Path(tmp))
            paths.root.mkdir(parents=True)
            artifact = paths.root / "poc.txt"
            artifact.write_text("pwned", encoding="utf-8")
            finding = {"id": "f1", "title": "bug", "category": "sqli", "severity": "high"}
            raw = {
                "disposition": "confirmed",
                "summary": "reproduced",
                "intended_behavior": {"summary": "safe", "source": "README.md", "basis": "doc"},
                "execution": {"commands": ["python poc.py"], "artifacts": [str(artifact)]},
                "evidence": [{"kind": "runtime", "artifact": str(artifact), "detail": "ok"}],
            }
            verifier = {
                "independent": True,
                "execution_status": "completed",
                "reproduction": {"commands": ["python poc.py"], "artifacts": [str(artifact)]},
                "environment": {"runtime": "docker", "dependencies": ["python"], "configuration": ["default"]},
                "evidence": [{"kind": "runtime", "artifact": str(artifact), "detail": "ok"}],
                "disposition": "",
            }
            canonical = normalize_validation(raw, finding, verifier, paths)
            self.assertEqual(canonical["disposition"], "unresolved")
