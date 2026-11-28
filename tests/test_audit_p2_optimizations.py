from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from yasa_vulnagent.config import Settings
from yasa_vulnagent.stages.audit.mcp_pool import SharedYasaMcp, use_yasa_mcp
from yasa_vulnagent.stages.audit.node import _load_or_create, run_stage
from yasa_vulnagent.stages.audit.storage import (
    AUDIT_ARTIFACT_KEYS,
    audit_paths,
    compact_audit_state,
    hydrate_audit_state,
    persist_audit_state,
    write_json,
)
from yasa_vulnagent.stages.audit.trace.tools import TraceYasaToolbox
from yasa_vulnagent.stages.audit.verify.result import freshly_read
from yasa_vulnagent.workflow.state import RunContext

from audit_fixtures import make_run_state

SOURCE = "src/service.py"
TEXT = (
    "class Service:\n"
    "    def run(self, x):\n"
    "        return exec(x)\n"
)


class _FakeMcpSession:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    async def call_tool(self, name: str, arguments: dict):
        self.calls.append((name, dict(arguments)))
        return SimpleNamespace(
            structuredContent={"tool": name, "ok": True},
            content=[],
        )


class AuditP2OptimizationsTest(unittest.TestCase):
    def test_shared_yasa_mcp_is_lazy_reuses_across_event_loops_and_closes_once(self) -> None:
        events: list[str] = []
        fake_session = _FakeMcpSession()

        @asynccontextmanager
        async def fake_opener(settings, repository):
            del settings, repository
            events.append("open")
            try:
                yield fake_session
            finally:
                events.append("close")

        settings = Settings(api_key=None, base_url="http://localhost", model="fake")
        pool = SharedYasaMcp(settings, Path("."), opener=fake_opener)

        # Lazy: nothing opened before first acquire().
        self.assertEqual(events, [])
        self.assertFalse(pool.is_open)

        context = RunContext(settings=settings, yasa_mcp=pool)

        async def _use(tool_name: str):
            async with use_yasa_mcp(context, Path(".")) as session:
                self.assertIsNotNone(session)
                res = await session.call_tool(tool_name, {"q": tool_name})
                return res.structuredContent

        # Run across 3 separate asyncio.run() event loops (simulating recon -> trace -> verify).
        r1 = asyncio.run(_use("get_function"))
        r2 = asyncio.run(_use("get_call_graph"))
        r3 = asyncio.run(_use("search_symbol"))

        self.assertEqual(r1["tool"], "get_function")
        self.assertEqual(r2["tool"], "get_call_graph")
        self.assertEqual(r3["tool"], "search_symbol")
        self.assertEqual(events, ["open"])
        self.assertEqual(len(fake_session.calls), 3)
        self.assertTrue(pool.is_open)

        pool.close()
        pool.close()  # idempotent
        self.assertEqual(events, ["open", "close"])
        self.assertFalse(pool.is_open)
        self.assertIsNone(asyncio.run(pool.acquire()))

    def test_use_yasa_mcp_falls_back_when_pool_is_absent(self) -> None:
        called = 0

        @asynccontextmanager
        async def local_opener(settings, repository):
            nonlocal called
            del settings, repository
            called += 1
            yield "local-session"

        context = RunContext(
            settings=Settings(api_key=None, base_url="http://localhost", model="fake"),
            yasa_mcp=None,
        )

        async def _run():
            async with use_yasa_mcp(context, Path("."), fallback_opener=local_opener) as session:
                return session

        self.assertEqual(asyncio.run(_run()), "local-session")
        self.assertEqual(called, 1)

    def test_run_stage_closes_shared_mcp_even_on_graph_error(self) -> None:
        closed = False

        class _SpyPool(SharedYasaMcp):
            def close(self) -> None:
                nonlocal closed
                closed = True
                super().close()

        class _BoomGraph:
            def invoke(self, state, **kwargs):
                del state, kwargs
                raise RuntimeError("boom")

        with tempfile.TemporaryDirectory() as temporary:
            state = make_run_state(Path(temporary), entries=[], patches=[])
            runtime = SimpleNamespace(
                context=RunContext(
                    settings=Settings(api_key=None, base_url="http://localhost", model="fake")
                )
            )
            with patch(
                "yasa_vulnagent.stages.audit.node.SharedYasaMcp", _SpyPool
            ), patch(
                "yasa_vulnagent.stages.audit.graph.build_audit_graph",
                return_value=_BoomGraph(),
            ):
                with self.assertRaisesRegex(RuntimeError, "boom"):
                    run_stage(state, runtime=runtime)
            self.assertTrue(closed)

    def test_freshly_read_accepts_yasa_get_class_by_name_with_code_and_methods(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            (repo / "src").mkdir()
            (repo / SOURCE).write_text(TEXT, encoding="utf-8")

            class _ClassSession:
                def __init__(self, payload: dict) -> None:
                    self.payload = payload

                async def call_tool(self, name: str, arguments: dict):
                    del name, arguments
                    return SimpleNamespace(structuredContent=self.payload, content=[])

            # Summary-only (no code body) -> does not satisfy freshly_read
            summary_box = TraceYasaToolbox(
                _ClassSession(
                    {
                        "results": [
                            {"file_path": str(repo / SOURCE), "start_line": 1, "end_line": 3}
                        ]
                    }
                ),
                repo,
            )
            asyncio.run(summary_box.get_class_by_name(name="Service"))
            fresh, missing = freshly_read(
                [{"path": SOURCE, "start_line": 2, "end_line": 3}],
                summary_box.receipts,
            )
            self.assertFalse(fresh)
            self.assertEqual(missing, [SOURCE])

            # Class result with nested method code body -> satisfies freshly_read
            method_box = TraceYasaToolbox(
                _ClassSession(
                    {
                        "results": [
                            {
                                "file_path": str(repo / SOURCE),
                                "start_line": 1,
                                "end_line": 3,
                                "methods": [
                                    {
                                        "name": "run",
                                        "start_line": 2,
                                        "end_line": 3,
                                        "code": "    def run(self, x):\n        return exec(x)",
                                    }
                                ],
                            }
                        ]
                    }
                ),
                repo,
            )
            asyncio.run(method_box.get_class_by_name(name="Service", include_methods=True))
            fresh, missing = freshly_read(
                [{"path": SOURCE, "start_line": 2, "end_line": 3}],
                method_box.receipts,
            )
            self.assertTrue(fresh)
            self.assertEqual(missing, [])

    def test_state_json_is_slim_and_hydrates_collections_from_audit_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = audit_paths(root / "stages")
            paths.root.mkdir(parents=True)
            full_state = {
                "run_id": "run-1",
                "repository": str(root / "repo"),
                "artifact_dir": str(paths.root),
                "state_file": str(paths.state_file),
                "audit_file": str(paths.audit_file),
                "mode": "combined",
                "status": "running",
                "framework": {"executed": ["prepare", "plan"], "visits": {"plan": 1}},
                "scope": {"files": ["src/a.py"]},
                "entries": [{"id": "entry-1", "blob": "x" * 5000}],
                "patches": [{"id": "patch-1"}],
                "tasks": [{"id": "task-1", "status": "planned"}],
                "category_checks": [{"id": "cat-1"}],
                "mechanism_checks": [{"id": "mech-1"}],
                "traces": [{"id": "trace-1"}],
                "summaries": [{"id": "sum-1"}],
                "findings": [{"id": "finding-1", "verdict": "confirmed"}],
                "reviews": [{"id": "review-1", "status": "complete"}],
            }
            write_json(
                paths.audit_file,
                {key: full_state[key] for key in AUDIT_ARTIFACT_KEYS},
            )
            persist_audit_state(full_state)

            saved_state = json.loads(paths.state_file.read_text(encoding="utf-8"))
            self.assertEqual(saved_state["state_storage"], "slim")
            for key in AUDIT_ARTIFACT_KEYS:
                self.assertNotIn(key, saved_state)
            self.assertEqual(saved_state["framework"]["executed"], ["prepare", "plan"])
            self.assertLess(
                paths.state_file.stat().st_size,
                paths.audit_file.stat().st_size,
            )

            # Hydrate restores all audit.json-owned collections transparently.
            hydrated = hydrate_audit_state(saved_state, paths)
            for key in AUDIT_ARTIFACT_KEYS:
                self.assertEqual(hydrated[key], full_state[key])

            # _load_or_create also hydrates on resume.
            resumed = _load_or_create(
                {"run_id": "run-1", "repository": str(root / "repo"), "stages": []},
                paths,
            )
            self.assertEqual(resumed["findings"], full_state["findings"])
            self.assertEqual(resumed["tasks"], full_state["tasks"])
            self.assertEqual(compact_audit_state(resumed)["state_storage"], "slim")


if __name__ == "__main__":
    unittest.main()
