from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

from yasa_vulnagent.config import (
    DEFAULT_DOCUMENTS_MODEL_TIMEOUT,
    DEFAULT_DOCUMENTS_SUMMARY_RESERVE,
    load_settings,
)
from yasa_vulnagent.stages.discover.screen.tools import ReadCache, SourceToolbox
from yasa_vulnagent.stages.init.documents.node import summarize
from yasa_vulnagent.workflow.state import RunContext


class _FakeResponse:
    def __init__(self, content: str) -> None:
        self.content = content
        self.tool_calls: list[dict[str, object]] = []
        self.usage_metadata = {"input_tokens": 10, "output_tokens": 10}


class _ConcurrentSummaryModel:
    def __init__(self) -> None:
        self.calls = 0

    def invoke(self, _messages):
        self.calls += 1
        return _FakeResponse(
            json.dumps(
                {
                    "overview": f"Batch overview {self.calls}",
                    "unknowns": [],
                    "warnings": [],
                }
            )
        )


class EvaluationFixesTest(unittest.TestCase):
    def test_documents_timeout_defaults_and_concurrent_batch_summarize(self) -> None:
        self.assertGreaterEqual(DEFAULT_DOCUMENTS_MODEL_TIMEOUT, 120)
        self.assertGreaterEqual(DEFAULT_DOCUMENTS_SUMMARY_RESERVE, 240)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact_dir = root / "stages" / "init" / "documents"
            artifact_dir.mkdir(parents=True)
            model = _ConcurrentSummaryModel()
            settings = load_settings()
            context = RunContext(settings=settings, model=model)
            # Create enough notes to trigger >1 summary batch under the 12k token cap.
            notes = [
                {
                    "document_id": f"doc-{i}",
                    "source": f"docs/doc-{i}.md",
                    "summary": "summary " + ("detail " * 2200),
                    "facts": [],
                    "unknowns": [],
                }
                for i in range(10)
            ]
            state = {
                "repository": str(root),
                "artifact_dir": str(artifact_dir),
                "deadline": time.monotonic() + 300,
                "inventory": [],
                "notes": notes,
                "unknowns": [],
                "warnings": [],
            }
            result = summarize(state, context)
            self.assertTrue(result["overview"])
            # Multiple batch calls + 1 final merge call.
            self.assertGreaterEqual(model.calls, 3)

    def test_read_file_distinguishes_directory_missing_and_out_of_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "src" / "http").mkdir(parents=True)
            (repo / "src" / "http" / "handler.go").write_text("package http\n", encoding="utf-8")
            (repo / "src" / "secret.go").write_text("package main\n", encoding="utf-8")

            toolbox = SourceToolbox(
                repo,
                allowed_paths=["src/http/handler.go"],
                cache=ReadCache(),
            )

            dir_err = toolbox.read_file("src/http")
            self.assertEqual(dir_err["error_kind"], "directory")
            self.assertIn("list_directory('src/http')", dir_err["error"])

            missing_err = toolbox.read_file("src/http/server.go")
            self.assertEqual(missing_err["error_kind"], "missing")
            self.assertIn("src/http/handler.go", missing_err["error"])

            oos_err = toolbox.read_file("src/secret.go")
            self.assertEqual(oos_err["error_kind"], "out_of_scope")
            self.assertIn("outside this task's scope", oos_err["error"])
