from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from yasa_vulnagent.agent.context import compact_json
from yasa_vulnagent.agent.model import build_chat_model, model_name, parse_json_object
from yasa_vulnagent.agent.tokens import TokenCounter
from yasa_vulnagent.config import Settings
from yasa_vulnagent.stages.audit.trace.execution import TraceExecution
from yasa_vulnagent.stages.discover.ledger import DiscoverLedger
from yasa_vulnagent.stages.init.index import InitIndex
from yasa_vulnagent.workflow.state import RunContext


class ArchitectureOptimizationsTest(unittest.TestCase):
    def test_shared_model_and_json_helpers(self) -> None:
        settings = Settings(api_key="secret", base_url="https://example.invalid", model="m1")
        sentinel = object()
        ctx = RunContext(settings=settings, model=sentinel)
        self.assertIs(
            build_chat_model(ctx, stage_label="test", timeout=30, error_cls=RuntimeError),
            sentinel,
        )
        self.assertEqual(
            parse_json_object('```json\n{"a": 1}\n```', "test"),
            {"a": 1},
        )
        self.assertEqual(model_name(type("M", (), {"model_name": "gpt-test"})()), "gpt-test")

    def test_config_safe_dict_redacts_api_key_and_serializes_paths(self) -> None:
        settings = Settings(
            api_key="super-secret",
            base_url="https://example.invalid",
            model="m1",
            usage_price_table=Path("/tmp/prices.json"),
        )
        safe = settings.safe_dict()
        self.assertNotIn("api_key", safe)
        self.assertTrue(safe["api_key_configured"])
        self.assertEqual(safe["usage_price_table"], "/tmp/prices.json")
        self.assertIsInstance(safe["validate_env_base_image_allowlist"], list)

    def test_token_counter_caches_repeated_text(self) -> None:
        counter = TokenCounter()
        with patch.object(counter, "_raw_count", wraps=counter._raw_count) as wrapped:
            first = counter.count_text("hello world repeated")
            second = counter.count_text("hello world repeated")
        self.assertEqual(first, second)
        self.assertEqual(wrapped.call_count, 1)

    def test_compact_json_shrinks_multiple_large_strings_quickly(self) -> None:
        payload = {f"k{i}": "x" * 2000 for i in range(10)}
        result = compact_json(payload, limit=2500)
        parsed = json.loads(result)
        self.assertTrue(parsed.get("_truncated"))
        self.assertLessEqual(len(result), 2600)

    def test_discover_ledger_point_lookups_for_query_and_hit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger = DiscoverLedger.open(Path(tmp) / "ledger.sqlite")
            try:
                ledger.put_query(
                    {
                        "query_id": "q1",
                        "mechanism_id": "m1",
                        "kind": "regex",
                        "target": "route",
                        "complete": False,
                    }
                )
                ledger.put_hit(
                    {
                        "hit_id": "h1",
                        "query_id": "q1",
                        "mechanism_id": "m1",
                        "path": "app.py",
                        "line_start": 1,
                        "line_end": 2,
                    }
                )
                self.assertEqual(ledger.get_query("q1")["target"], "route")
                self.assertIsNone(ledger.get_query("missing"))
                self.assertEqual(ledger.get_hit("h1")["path"], "app.py")
                self.assertIsNone(ledger.get_hit("missing"))
            finally:
                ledger.close()

    def test_init_index_has_notes_detects_populated_fts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            index = InitIndex(Path(tmp) / "index.sqlite")
            try:
                self.assertFalse(index.has_notes())
                index.upsert_note({"document_id": "d1", "summary": "hello"})
                self.assertTrue(index.has_notes())
            finally:
                index.close()

    def test_trace_execution_isolates_tool_receipts_per_call(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            execution = object.__new__(TraceExecution)
            execution.repository = root
            execution.scope_files = []
            execution.cache = None
            execution.mcp_session = None
            execution.revision = ""
            spec = SimpleNamespace(tools="source")
            _, receipts_a = execution.tools_for(spec)
            _, receipts_b = execution.tools_for(spec)
            receipts_a.append({"tool": "read_file", "path": "a.py"})
            self.assertEqual(len(receipts_a), 1)
            self.assertEqual(len(receipts_b), 0)
