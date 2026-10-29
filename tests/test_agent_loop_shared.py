from __future__ import annotations

import asyncio
import threading
import time
import unittest

from langchain_core.messages import HumanMessage
from langchain_core.tools import StructuredTool

from yasa_vulnagent.agent.budget import TaskBudget
from yasa_vulnagent.agent.context import assert_valid_pairing
from yasa_vulnagent.agent.runtime import run_coroutine, run_tool_loop, run_tool_loop_async


class _Response:
    def __init__(self, content: str = "", tool_calls=None) -> None:
        self.content = content
        self.tool_calls = tool_calls or []


class _AsyncModel:
    def __init__(self, responses: list[_Response]) -> None:
        self.responses = list(responses)
        self.messages: list[list] = []

    def bind_tools(self, tools):
        return self

    async def ainvoke(self, messages):
        self.messages.append(list(messages))
        if self.responses:
            return self.responses.pop(0)
        return _Response('{"ok": true}')


class _TimedTool:
    """Records start/end timestamps so overlap can be asserted."""

    def __init__(self, name: str, delay: float = 0.05) -> None:
        self.name = name
        self.delay = delay
        self.starts: list[float] = []
        self.ends: list[float] = []

    def as_tool(self) -> StructuredTool:
        recorder = self

        def read_file(path: str) -> str:
            """Read one repository file."""
            recorder.starts.append(time.monotonic())
            time.sleep(recorder.delay)
            recorder.ends.append(time.monotonic())
            return f"read {path}"

        return StructuredTool.from_function(func=read_file, name="read_file")


class SharedAgentLoopTest(unittest.TestCase):
    def test_async_model_completes_without_tools(self) -> None:
        model = _AsyncModel([_Response('{"ok": true}')])
        result = asyncio.run(
            run_tool_loop_async(
                model,
                "system",
                "user",
                budget=TaskBudget(max_model_calls=4),
            )
        )
        self.assertEqual(result.stop_reason, "complete")
        self.assertEqual(result.content, '{"ok": true}')
        self.assertEqual(result.rounds, 1)
        self.assertEqual(result.model_calls, 1)

    def test_parallel_read_only_tools_overlap(self) -> None:
        tool_a = _TimedTool("read_file")
        model = _AsyncModel(
            [
                _Response(
                    "",
                    [
                        {"id": "a", "name": "read_file", "args": {"path": "a"}},
                        {"id": "b", "name": "read_file", "args": {"path": "b"}},
                    ],
                ),
                _Response('{"ok": true}'),
            ]
        )
        tool = tool_a.as_tool()
        result = asyncio.run(
            run_tool_loop_async(
                model,
                "system",
                "user",
                tools=[tool],
                budget=TaskBudget(max_model_calls=4),
                parallel_tools=True,
            )
        )
        self.assertEqual(result.tool_calls, 2)
        self.assertEqual(len(tool_a.starts), 2)
        self.assertLess(tool_a.starts[1], tool_a.ends[0])
        self.assertEqual(result.stop_reason, "complete")

    def test_model_semaphore_limits_concurrent_calls(self) -> None:
        class _SlowModel:
            def __init__(self) -> None:
                self.active = 0
                self.max_active = 0

            def bind_tools(self, tools):
                return self

            async def ainvoke(self, messages):
                self.active += 1
                self.max_active = max(self.max_active, self.active)
                await asyncio.sleep(0.05)
                self.active -= 1
                return _Response('{"ok": true}')

        model = _SlowModel()
        semaphore = asyncio.Semaphore(1)

        async def run() -> None:
            await asyncio.gather(
                run_tool_loop_async(
                    model,
                    "system",
                    "user",
                    budget=TaskBudget(max_model_calls=2),
                    model_semaphore=semaphore,
                ),
                run_tool_loop_async(
                    model,
                    "system",
                    "user",
                    budget=TaskBudget(max_model_calls=2),
                    model_semaphore=semaphore,
                ),
            )

        asyncio.run(run())
        self.assertEqual(model.max_active, 1)

    def test_budget_exhaustion_finalizes_without_tools(self) -> None:
        model = _AsyncModel(
            [
                _Response(
                    "",
                    [{"id": "r", "name": "read_file", "args": {"path": "a"}}],
                ),
                _Response('{"partial": true}'),
            ]
        )
        result = asyncio.run(
            run_tool_loop_async(
                model,
                "system",
                "user",
                tools=[_TimedTool("read_file", delay=0.0).as_tool()],
                budget=TaskBudget(max_model_calls=1),
                finalize_on_exhaustion=True,
            )
        )
        self.assertIn(result.stop_reason, {"model_calls", "step_budget"})
        self.assertEqual(result.content, '{"partial": true}')
        self.assertEqual(len(model.messages), 2)
        last = model.messages[-1]
        self.assertIsInstance(last[-1], HumanMessage)
        self.assertIn("Tool budget exhausted", last[-1].content)

    def test_round_limit_finalizes_with_valid_tool_pairing(self) -> None:
        class _LoopingModel(_AsyncModel):
            def bind_tools(self, tools):
                return self

            async def ainvoke(self, messages):
                self.calls = getattr(self, "calls", 0) + 1
                if self.calls <= 2:
                    return _Response(
                        "",
                        [{"id": f"r{self.calls}", "name": "read_file", "args": {"path": "a"}}],
                    )
                return _Response('{"done": true}')

        model = _LoopingModel([])
        result = asyncio.run(
            run_tool_loop_async(
                model,
                "system",
                "user",
                tools=[_TimedTool("read_file", delay=0.0).as_tool()],
                budget=TaskBudget(max_model_calls=8),
                max_rounds=1,
                finalize_on_exhaustion=True,
            )
        )
        assert_valid_pairing(result.messages)
        self.assertEqual(result.stop_reason, "round_limit")

    def test_unknown_tool_error_keeps_the_tool_name(self) -> None:
        model = _AsyncModel(
            [
                _Response(
                    "",
                    [{"id": "x", "name": "does_not_exist", "args": {}}],
                ),
                _Response('{"ok": true}'),
            ]
        )
        result = asyncio.run(
            run_tool_loop_async(
                model,
                "system",
                "user",
                budget=TaskBudget(max_model_calls=4),
            )
        )
        contents = [str(message.content) for message in result.messages]
        self.assertTrue(any("unknown tool: does_not_exist" in text for text in contents))
        self.assertEqual(result.stop_reason, "complete")

    def test_sync_wrapper_runs_from_plain_code(self) -> None:
        model = _AsyncModel([_Response('{"ok": true}')])
        result = run_tool_loop(model, "s", "u", budget=TaskBudget(max_model_calls=2))
        self.assertEqual(result.content, '{"ok": true}')

    def test_run_coroutine_tolerates_an_active_loop(self) -> None:
        async def main() -> str:
            return run_coroutine(asyncio.sleep(0, result="done"))

        self.assertEqual(asyncio.run(main()), "done")

    def test_thread_identity_changes_for_sync_tools(self) -> None:
        seen: list[int] = []

        def read_file(path: str) -> str:
            """Read one repository file."""
            seen.append(threading.get_ident())
            return path

        model = _AsyncModel(
            [
                _Response("", [{"id": "t", "name": "read_file", "args": {"path": "a"}}]),
                _Response('{"ok": true}'),
            ]
        )
        asyncio.run(
            run_tool_loop_async(
                model,
                "s",
                "u",
                tools=[StructuredTool.from_function(func=read_file, name="read_file")],
                budget=TaskBudget(max_model_calls=4),
            )
        )
        self.assertEqual(len(seen), 1)
        self.assertNotEqual(seen[0], threading.get_ident())


if __name__ == "__main__":
    unittest.main()
