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
            self.assertEqual(dir_err["suggested_tool"], "list_directory")
            self.assertEqual(dir_err["suggested_args"], {"path": "src/http"})

            missing_err = toolbox.read_file("src/http/server.go")
            self.assertEqual(missing_err["error_kind"], "missing")
            self.assertIn("src/http/handler.go", missing_err["error"])
            self.assertIn("src/http/handler.go", missing_err["suggested_paths"])

            oos_err = toolbox.read_file("src/secret.go")
            self.assertEqual(oos_err["error_kind"], "out_of_scope")
            self.assertIn("outside this task's scope", oos_err["error"])

    def test_documents_priority_filters_locales_and_fixtures_and_orders_p0_first(self) -> None:
        from yasa_vulnagent.stages.init.documents.tools import DocumentToolbox

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "README.md").write_text("# App\n", encoding="utf-8")
            (repo / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
            (repo / "Dockerfile").write_text("FROM python:3.12\n", encoding="utf-8")
            (repo / "CHANGELOG.md").write_text("# Changes\n", encoding="utf-8")
            (repo / "docs").mkdir()
            (repo / "docs" / "auth.md").write_text("# Auth\n", encoding="utf-8")
            (repo / "internal" / "locale" / "translations").mkdir(parents=True)
            (repo / "internal" / "locale" / "translations" / "hi_IN.json").write_text("{}", encoding="utf-8")
            (repo / "tests" / "fixtures").mkdir(parents=True)
            (repo / "tests" / "fixtures" / "sample.json").write_text("{}", encoding="utf-8")
            (repo / "zh_CN.json").write_text("{}", encoding="utf-8")

            toolbox = DocumentToolbox(repo, repo / ".artifacts")
            seeds = toolbox.seed_candidates()
            self.assertNotIn("internal/locale/translations/hi_IN.json", seeds)
            self.assertNotIn("tests/fixtures/sample.json", seeds)
            self.assertNotIn("zh_CN.json", seeds)
            # P0 files (Dockerfile, README.md, SECURITY.md) must precede docs/auth.md and CHANGELOG.md.
            self.assertLess(seeds.index("README.md"), seeds.index("docs/auth.md"))
            self.assertLess(seeds.index("SECURITY.md"), seeds.index("CHANGELOG.md"))
            self.assertLess(seeds.index("docs/auth.md"), seeds.index("CHANGELOG.md"))

    def test_fuzzy_path_suggestions_in_source_review_and_evidence(self) -> None:
        from yasa_vulnagent.stages.discover.evidence import validate_location
        from yasa_vulnagent.stages.discover.ledger import DiscoverLedger
        from yasa_vulnagent.stages.discover.review.tools import ReviewToolbox

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            (repo / "src" / "endpoints").mkdir(parents=True)
            (repo / "src" / "endpoints" / "CustomEndpoints.java").write_text("class A {}\n", encoding="utf-8")

            source_tb = SourceToolbox(
                repo,
                allowed_paths=["src/endpoints/CustomEndpoints.java"],
                cache=ReadCache(),
            )
            res = source_tb.read_file("src/CustomEndpoint.java")
            self.assertEqual(res["error_kind"], "missing")
            self.assertIn("src/endpoints/CustomEndpoints.java", res["suggested_paths"])

            review_tb = ReviewToolbox(repo, ["src/endpoints/CustomEndpoints.java"])
            r_dir = review_tb.read_file("src/endpoints")
            self.assertEqual(r_dir["error_kind"], "directory")
            r_miss = review_tb.read_file("src/endpoints/CustomEndpoint.java")
            self.assertIn("src/endpoints/CustomEndpoints.java", r_miss["suggested_paths"])

            ledger = DiscoverLedger.open(Path(tmp) / "ledger.sqlite")
            try:
                ledger.replace_inventory(
                    [
                        {
                            "path": "src/endpoints/CustomEndpoints.java",
                            "size": 12,
                            "fingerprint": "fp-1",
                            "content_type": "text",
                            "usage_hint": "production-candidate",
                            "status": "pending",
                        }
                    ],
                    [],
                )
                ev = validate_location(
                    repo,
                    ledger,
                    path="src/endpoints/CustomEndpoint.java",
                    start=1,
                    end=1,
                )
                self.assertFalse(ev["ok"])
                self.assertIn("src/endpoints/CustomEndpoints.java", ev["suggested_paths"])
            finally:
                ledger.close()
