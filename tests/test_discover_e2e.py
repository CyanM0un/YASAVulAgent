from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from yasa_vulnagent.config import Settings
from yasa_vulnagent.stages.discover.ledger import DiscoverLedger
from yasa_vulnagent.stages.discover.node import run_stage
from yasa_vulnagent.workflow.state import RunContext


class _Response:
    def __init__(self, content: str, tool_calls=None) -> None:
        self.content = content
        self.tool_calls = tool_calls or []


class _FakeModel:
    """Offline model: answers screen and planner prompts, never calls tools."""

    def __init__(self) -> None:
        self.calls = 0

    def bind_tools(self, tools):
        return self

    def invoke(self, messages):
        self.calls += 1
        system = str(messages[0].content) if messages else ""
        if "discover.screen" in system:
            return _Response(
                json.dumps(
                    {
                        "scope_status": "complete",
                        "priority": "normal",
                        "summary": "read the scope",
                        "scope": [],
                        "candidates": [],
                        "negative_results": [],
                        "unknowns": [],
                        "deferred": [],
                        "follow_up": [],
                        "deferred_items": [],
                        "feature_observations": [],
                    }
                )
            )
        return _Response(json.dumps({"tasks": [], "dispositions": []}))


class DiscoverEndToEndTest(unittest.TestCase):
    def test_offline_run_writes_usage_and_finishes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            (repository / "src").mkdir(parents=True)
            (repository / "src" / "main.py").write_text(
                "def handler(request):\n    return request.args.get('name')\n",
                encoding="utf-8",
            )
            (repository / "src" / "other.py").write_text(
                "def helper():\n    return 1\n", encoding="utf-8"
            )
            stages_dir = root / "stages"
            (stages_dir / "discover").mkdir(parents=True)
            state = {
                "repository": str(repository),
                "stages_dir": str(stages_dir),
                "stages": [{"name": "init", "status": "partial", "details": {}}],
                "run_file": str(root / "run.json"),
            }
            model = _FakeModel()
            context = RunContext(
                settings=Settings(
                    api_key=None,
                    base_url="http://localhost",
                    model="fake",
                    yasa_bin_path=root / "missing-yasa",
                    yasa_source_path=root / "missing-yasa",
                ),
                model=model,
            )

            update = run_stage(state, runtime=SimpleNamespace(context=context))

            artifact_dir = stages_dir / "discover"
            usage_file = artifact_dir / "usage.json"
            self.assertTrue(usage_file.is_file())
            usage = json.loads(usage_file.read_text(encoding="utf-8"))
            self.assertGreaterEqual(usage["totals"]["calls"], 1)
            self.assertGreaterEqual(model.calls, 1)
            self.assertEqual(update["discover"]["usage"]["calls"], usage["totals"]["calls"])
            self.assertIn(update["discover"]["status"], {"partial", "complete"})
            for name in ("index.json", "confirmed-entries.json", "prepare.json", "init-resources.json", "files.json", "excluded-files.json"):
                self.assertTrue((artifact_dir / name).is_file(), name)
            for name in ("tasks.json", "entries.json", "evidence.json", "dispositions.json", "mechanisms.json", "feature-queries.json", "feature-hits.json"):
                self.assertFalse((artifact_dir / name).exists(), name)
            with DiscoverLedger.open(artifact_dir / "ledger.sqlite") as ledger:
                tasks = ledger.list_tasks()
            self.assertTrue(tasks)
            self.assertTrue(
                all(task.get("status") in {"complete", "partial"} for task in tasks)
            )
            self.assertTrue(
                all(task.get("stop_reason") == "complete" for task in tasks)
            )


if __name__ == "__main__":
    unittest.main()
