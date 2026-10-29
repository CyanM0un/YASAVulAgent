from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from yasa_vulnagent.agent.artifacts import ToolResultStore
from yasa_vulnagent.agent.budget import BudgetStop, TaskBudget
from yasa_vulnagent.agent.context import ContextManager
from yasa_vulnagent.agent.retry import RetryPolicy, classify_model_error
from yasa_vulnagent.agent.tokens import TokenCounter
from yasa_vulnagent.agent.usage import UsageRecorder
from yasa_vulnagent.agent.runtime import run_tool_loop


class RuntimeTest(unittest.TestCase):
    def test_budget_stops_after_model_calls(self) -> None:
        budget = TaskBudget(max_model_calls=2, hard_task_cap=10)
        budget.consume_model_attempt()
        budget.consume_model_attempt()
        with self.assertRaises(BudgetStop) as error:
            budget.consume_model_attempt()
        self.assertEqual(error.exception.reason, "step_budget")

    def test_budget_stops_at_deadline(self) -> None:
        budget = TaskBudget(deadline=time.monotonic() - 1)
        with self.assertRaises(BudgetStop) as error:
            budget.check()
        self.assertEqual(error.exception.reason, "time_budget")

    def test_retry_policy_retries_transient_then_succeeds(self) -> None:
        calls = {"count": 0}

        def call() -> str:
            calls["count"] += 1
            if calls["count"] == 1:
                raise RuntimeError("503 service unavailable")
            return "ok"

        self.assertEqual(RetryPolicy(attempts=2, base_delay=0).model(call), "ok")
        self.assertEqual(calls["count"], 2)

    def test_retry_policy_does_not_retry_auth(self) -> None:
        calls = {"count": 0}

        def call() -> str:
            calls["count"] += 1
            raise RuntimeError("401 unauthorized")

        with self.assertRaises(RuntimeError):
            RetryPolicy(attempts=3, base_delay=0).model(call)
        self.assertEqual(calls["count"], 1)
        self.assertEqual(classify_model_error(RuntimeError("401 unauthorized")), "fatal")

    def test_context_compaction_keeps_tool_exchanges_valid(self) -> None:
        counter = TokenCounter(safety=1.0)
        context = ContextManager(counter, max_tokens=10, trigger=0.1, keep_recent_results=1)
        messages = [
            SystemMessage(content="system"),
            HumanMessage(content="user"),
            AIMessage(content="", tool_calls=[{"name": "read_file", "args": {}, "id": "1"}]),
            ToolMessage(content='{"path":"a","text":"one"}', tool_call_id="1"),
            AIMessage(content="", tool_calls=[{"name": "read_file", "args": {}, "id": "2"}]),
            ToolMessage(content='{"path":"b","text":"two"}', tool_call_id="2"),
        ]
        compacted = context.compact(messages)
        self.assertEqual(compacted[0].content, "system")
        self.assertFalse(
            any(message.__class__.__name__ == "ToolMessage" and message.tool_call_id == "1" for message in compacted)
        )
        self.assertTrue(
            any(message.__class__.__name__ == "ToolMessage" and message.tool_call_id == "2" for message in compacted)
        )
        self.assertTrue(any("a" in str(message.content) for message in compacted if message.__class__.__name__ == "SystemMessage"))

    def test_usage_recorder_aggregates_and_optional_cost(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            prices = Path(temporary) / "prices.json"
            prices.write_text(
                '[{"model":"m","input_per_million":1.0,"output_per_million":2.0}]',
                encoding="utf-8",
            )
            usage = UsageRecorder(prices)
            usage.record(
                stage="init.documents",
                task_id="doc",
                model="m",
                usage={"input_tokens": 1000, "output_tokens": 500, "total_tokens": 1500},
            )
            usage.record(
                stage="init.security_history",
                task_id="commit",
                model="m",
                usage={"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
            )
            snapshot = usage.snapshot("init.documents")
            self.assertEqual(snapshot["totals"]["total_tokens"], 1500)
            self.assertAlmostEqual(snapshot["totals"]["cost"], 0.002)
            output = Path(temporary) / "usage.json"
            usage.write(output, "init.documents")
            self.assertTrue(output.is_file())
            written = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(len(written["records"]), 1)
            self.assertEqual(written["records"][0]["stage"], "init.documents")

    def test_usage_limits_and_estimated_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            prices = Path(temporary) / "prices.json"
            prices.write_text(
                '[{"model":"m","input_per_million":1000.0,"output_per_million":0.0}]',
                encoding="utf-8",
            )
            usage = UsageRecorder(prices, max_tokens=10, max_cost=0.001)
            usage.record(
                stage="audit",
                task_id="task",
                model="m",
                usage=None,
                estimated_prompt_tokens=10,
            )
            snapshot = usage.snapshot("audit")
            self.assertEqual(snapshot["totals"]["total_tokens"], 10)
            self.assertEqual(snapshot["totals"]["prompt_tokens"], 10)
            self.assertEqual(snapshot["records"][0]["usage_source"], "estimated")
            self.assertEqual(snapshot["exceeded"], "token_budget")
            self.assertEqual(snapshot["limits"]["max_total_tokens"], 10)

            cost_usage = UsageRecorder(prices, max_cost=0.001)
            cost_usage.record(
                stage="audit",
                task_id="task",
                model="m",
                usage={"input_tokens": 2, "output_tokens": 0, "total_tokens": 2},
            )
            self.assertEqual(cost_usage.exceeded(), "cost_budget")

    def test_tool_result_store_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = ToolResultStore(Path(temporary) / "tool-results")
            reference = store.save("read_file", {"path": "a"}, {"text": "abcdef"})
            self.assertTrue(reference.startswith("tool-results/"))
            result = store.read(reference, 0, 3)
            self.assertEqual(len(result["text"]), 3)
            self.assertTrue(result["truncated"])
            self.assertEqual(result["next_offset"], 3)


if __name__ == "__main__":
    unittest.main()


class _Response:
    def __init__(self, content: str, tool_calls=None) -> None:
        self.content = content
        self.tool_calls = tool_calls or []


class _RepairModel:
    def __init__(self) -> None:
        self.calls = 0

    def invoke(self, _messages):
        self.calls += 1
        if self.calls == 1:
            return _Response("not json")
        return _Response('{"ok": true}')


class _TruncatingTool:
    name = "read_big"

    def invoke(self, _arguments):
        return {"text": "x" * 20000, "path": "big.txt", "truncated": False}


class _ToolModel:
    def __init__(self) -> None:
        self.calls = 0

    def bind_tools(self, _tools):
        return self

    def invoke(self, messages):
        self.calls += 1
        if self.calls == 1:
            return _Response("", [{"name": "read_big", "args": {}, "id": "t1"}])
        return _Response('{"ok": true}')


class _UsageResponse(_Response):
    def __init__(self, content: str = "", tool_calls=None, usage=None) -> None:
        super().__init__(content, tool_calls)
        self.usage_metadata = usage


class _CapModel:
    def __init__(self) -> None:
        self.calls = 0

    def bind_tools(self, tools):
        return self

    async def ainvoke(self, messages):
        self.calls += 1
        if self.calls == 1:
            return _UsageResponse(
                "",
                [{"name": "read_file", "args": {}, "id": "1"}],
                {"input_tokens": 5, "output_tokens": 5, "total_tokens": 10},
            )
        return _UsageResponse('{"ok": true}', usage={"total_tokens": 10})


class _EchoTool:
    name = "read_file"

    def invoke(self, arguments):
        return {"path": "a", "text": "one"}


class RuntimeLoopTest(unittest.TestCase):
    def test_json_repair_runs_once(self) -> None:
        model = _RepairModel()
        result = run_tool_loop(
            model,
            "system",
            "user",
            budget=TaskBudget(max_model_calls=5, hard_task_cap=5),
            json_expected=True,
            max_rounds=2,
        )
        self.assertIn('"ok"', result.content)
        self.assertEqual(model.calls, 2)

    def test_usage_tool_calls_are_per_call_deltas(self) -> None:
        usage = UsageRecorder()
        result = run_tool_loop(
            _ToolModel(),
            "system",
            "user",
            [_EchoTool()],
            budget=TaskBudget(max_model_calls=5, hard_task_cap=5),
            usage=usage,
            json_expected=True,
            max_rounds=2,
        )
        self.assertEqual(result.tool_calls, 1)
        self.assertEqual(usage.snapshot()["totals"]["tool_calls"], 1)

    def test_cost_cap_skips_finalize_model_call(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            prices = Path(temporary) / "prices.json"
            prices.write_text(
                '[{"model":"m","input_per_million":1000.0,"output_per_million":0.0}]',
                encoding="utf-8",
            )
            model = _CapModel()
            model.model_name = "m"
            usage = UsageRecorder(prices, max_cost=0.001)
            result = run_tool_loop(
                model,
                "system",
                "user",
                [_EchoTool()],
                budget=TaskBudget(max_model_calls=5, hard_task_cap=5),
                usage=usage,
                max_rounds=5,
                finalize_on_exhaustion=True,
            )
            self.assertEqual(result.stop_reason, "cost_budget")
            self.assertEqual(model.calls, 1)

    def test_token_cap_skips_finalize_model_call(self) -> None:
        model = _CapModel()
        usage = UsageRecorder(max_tokens=5)
        result = run_tool_loop(
            model,
            "system",
            "user",
            [_EchoTool()],
            budget=TaskBudget(max_model_calls=5, hard_task_cap=5),
            usage=usage,
            max_rounds=5,
            finalize_on_exhaustion=True,
        )
        self.assertEqual(result.stop_reason, "token_budget")
        self.assertEqual(model.calls, 1)

    def test_token_cap_stops_before_next_model_call(self) -> None:
        model = _CapModel()
        usage = UsageRecorder(max_tokens=5)
        with self.assertRaises(BudgetStop) as error:
            run_tool_loop(
                model,
                "system",
                "user",
                [_EchoTool()],
                budget=TaskBudget(max_model_calls=5, hard_task_cap=5),
                usage=usage,
                max_rounds=5,
            )
        self.assertEqual(error.exception.reason, "token_budget")
        self.assertEqual(model.calls, 1)

    def test_compaction_preserves_reasoning_and_receipts(self) -> None:
        counter = TokenCounter(safety=1.0)
        context = ContextManager(counter, max_tokens=2000, trigger=0.1, keep_recent_results=1)
        messages = [
            SystemMessage(content="system"),
            HumanMessage(content="user"),
            AIMessage(
                content="I will inspect auth",
                tool_calls=[{"name": "read_file", "args": {}, "id": "1"}],
            ),
            ToolMessage(content='{"path":"src/auth.py","text":"one"}', tool_call_id="1"),
            AIMessage(content="", tool_calls=[{"name": "read_file", "args": {}, "id": "2"}]),
            ToolMessage(content='{"path":"src/app.py","text":"two"}', tool_call_id="2"),
        ]
        compacted = context.compact(messages)
        text = "\n".join(
            str(message.content)
            for message in compacted
            if message.__class__.__name__ == "SystemMessage"
        )
        self.assertIn("I will inspect auth", text)
        self.assertIn("src/auth.py", text)

    def test_tool_result_is_truncated_and_stored(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = run_tool_loop(
                _ToolModel(),
                "system",
                "user",
                [_TruncatingTool()],
                budget=TaskBudget(max_model_calls=5, hard_task_cap=5),
                artifact_dir=Path(temporary),
                json_expected=True,
                max_rounds=2,
            )
            self.assertTrue(result.receipts[0]["truncated"])
            reference = result.receipts[0]["artifact_ref"]
            self.assertTrue((Path(temporary) / reference).is_file())
