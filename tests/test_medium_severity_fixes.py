from __future__ import annotations

import asyncio
import logging
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from yasa_vulnagent.agent.artifacts import ToolResultStore, atomic_write_json
from yasa_vulnagent.agent.context import ContextManager
from yasa_vulnagent.agent.tokens import TokenCounter
from yasa_vulnagent.agent.usage import UsageRecorder
from yasa_vulnagent.observability import ProgressReporter
from yasa_vulnagent.stages.audit.trace.execution import TraceExecution
from yasa_vulnagent.stages.audit.trace.graph import _paths as trace_paths
from yasa_vulnagent.stages.audit.trace.graph import _validate_persist
from yasa_vulnagent.stages.discover.confirm.node import _task_context
from yasa_vulnagent.stages.discover.ledger import DiscoverLedger
from yasa_vulnagent.stages.discover.screen.tools import ReadCache, SourceToolbox


class MediumSeverityFixesTest(unittest.TestCase):
    def test_context_compaction_keeps_hint_and_shrinks_oversized_single_exchange(self) -> None:
        counter = TokenCounter()
        manager = ContextManager(counter, max_tokens=200, trigger=0.5, keep_recent_results=3)
        huge = "x" * 4000
        messages = [
            SystemMessage(content="sys"),
            HumanMessage(content="user"),
            AIMessage(content="", tool_calls=[{"id": "c1", "name": "read_file", "args": {"path": "a.py"}}]),
            ToolMessage(content=huge, tool_call_id="c1"),
        ]
        self.assertTrue(manager.should_compact(messages))
        compacted = manager.compact(messages, hint="keep tracking finding f1")
        self.assertLess(counter.count_messages(compacted), counter.count_messages(messages))
        self.assertTrue(
            any(
                isinstance(msg, SystemMessage) and "keep tracking finding f1" in str(msg.content)
                for msg in compacted
            )
        )
        # Hint survives a second compaction without duplication.
        compacted_again = manager.compact(compacted, hint="keep tracking finding f1")
        hint_msgs = [
            str(msg.content)
            for msg in compacted_again
            if isinstance(msg, SystemMessage) and "keep tracking finding f1" in str(msg.content)
        ]
        self.assertEqual(len(hint_msgs), 1)
        self.assertEqual(hint_msgs[0].count("keep tracking finding f1"), 1)

    def test_progress_reporter_cross_thread_finish_clears_stack(self) -> None:
        now = 100.0
        reporter = ProgressReporter(
            logging.getLogger("test.progress.cross_thread"),
            heartbeat_interval=10.0,
            clock=lambda: now,
        )
        reporter.start("step.cross")
        worker = threading.Thread(target=lambda: reporter.finish("step.cross", status="complete"))
        worker.start()
        worker.join()
        self.assertEqual(reporter._steps, {})

    def test_atomic_write_and_tool_store_and_usage_limits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "state.json"
            atomic_write_json(target, {"ok": True}, sort_keys=True)
            self.assertIn('"ok": true', target.read_text(encoding="utf-8"))

            store = ToolResultStore(root / "tool-results")
            ref = store.save("read_file", {"path": "a.py"}, {"text": "hello"})
            self.assertTrue(ref.startswith("tool-results/"))
            self.assertEqual(store.read(ref)["total_chars"] > 0, True)

            usage = UsageRecorder()
            usage.configure_limits(max_tokens=100, max_cost=1.0)
            usage.record(
                stage="audit.trace",
                task_id="t1",
                model="test-model",
                usage={"input_tokens": 60, "output_tokens": 50},
            )
            snap = usage.snapshot("audit.trace")
            self.assertEqual(snap["exceeded"], "token_budget")
            usage.write(root / "usage.json", "audit")
            self.assertTrue((root / "usage.json").is_file())

    def test_audit_trace_paths_and_deferred_outcome(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            custom_dir = Path(tmp) / "custom-audit-dir"
            execution = MagicMock(spec=TraceExecution)
            execution.audit_dir = custom_dir
            execution.run_id = "run-1"
            resolved_paths = trace_paths(execution)
            self.assertEqual(resolved_paths.root, custom_dir)

            runtime = SimpleNamespace(context=SimpleNamespace(trace_runtime=execution))
            result = asyncio.run(
                _validate_persist(
                    {
                        "task": {"id": "task-1", "kind": "entry"},
                        "status": "deferred",
                        "error": "audit budget exhausted",
                    },
                    runtime,
                )
            )
            self.assertEqual(result["outcome"]["status"], "deferred")
            self.assertEqual(result["outcome"]["trace"], {})
            self.assertFalse((custom_dir / "traces").exists())

    def test_discover_list_directory_mixed_case_cursor_and_read_file_line_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "a.py").write_text("line1\n", encoding="utf-8")
            (repo / "B.py").write_text("line1\n", encoding="utf-8")
            (repo / "c.py").write_text("12345\n67890\nabcde\n", encoding="utf-8")
            list_toolbox = SourceToolbox(repo, max_output_chars=4000, cache=ReadCache(), allow_all=True)

            seen: list[str] = []
            cursor = ""
            for _ in range(10):
                page = list_toolbox.list_directory(".", max_entries=1, cursor=cursor)
                seen.extend(item["name"] for item in page["entries"])
                cursor = page["next_cursor"] or ""
                if not cursor:
                    break
            self.assertEqual(sorted(seen), ["B.py", "a.py", "c.py"])
            self.assertEqual(len(seen), 3)

            toolbox = SourceToolbox(repo, max_output_chars=12, cache=ReadCache(), allow_all=True)
            first = toolbox.read_file("c.py", start_line=1, end_line=3)
            self.assertEqual(first["text"], "12345\n67890")
            self.assertEqual(first["start_line"], 1)
            self.assertEqual(first["end_line"], 2)
            self.assertEqual(first["next_line"], 3)
            self.assertTrue(first["truncated"])

            second = toolbox.read_file("c.py", start_line=first["next_line"], end_line=3)
            self.assertEqual(second["text"], "abcde")
            self.assertEqual(second["end_line"], 3)
            self.assertIsNone(second["next_line"])

    def test_discover_confirm_injects_last_error_on_first_retry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger = DiscoverLedger.open(Path(tmp) / "ledger.sqlite")
            try:
                task = {
                    "task_id": "confirm-1",
                    "origin": "screen",
                    "question": "Verify entry",
                    "candidate_ids": [],
                    "attempts": 1,
                    "error": "",
                    "unknowns": ["missing evidence_refs"],
                }
                rendered = _task_context(ledger, task, limit=10000)
                self.assertIn("last_error", rendered)
                self.assertIn("missing evidence_refs", rendered)
            finally:
                ledger.close()
