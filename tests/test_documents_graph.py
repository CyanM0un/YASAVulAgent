from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from yasa_vulnagent.config import Settings
from yasa_vulnagent.stages.init.documents.graph import build_documents_graph
from yasa_vulnagent.stages.init.documents.model import (
    DocumentsError,
    DocumentsFatalError,
    build_model,
    invoke_model,
)
from yasa_vulnagent.stages.init.documents.node import _documents_index, read_document
from yasa_vulnagent.stages.init.documents.tools import DocumentToolbox
from yasa_vulnagent.workflow.state import RunContext


class _Response:
    def __init__(self, content: str) -> None:
        self.content = content
        self.tool_calls: list[dict[str, object]] = []


class _Model:
    def bind_tools(self, _tools):
        return self

    def invoke(self, messages):
        prompt = messages[-1].content
        if "Repository root:" in prompt:
            content = '{"documents": [], "unknowns": [], "exclusions": []}'
        elif "Source segment:" in prompt:
            content = (
                '{"summary":"The segment describes the project.",'
                '"facts":[{"claim":"The project has documented behavior.",'
                '"location":"README.md:1-2"}],"unknowns":[],"follow_up":[]}'
            )
        else:
            content = (
                '{"overview":"# Project Overview\\n\\nThe project has documented behavior. '
                'Source: README.md:1-2.","unknowns":[],"warnings":[],"source_count":1}'
            )
        return _Response(content)


class DocumentsGraphTest(unittest.TestCase):
    def test_graph_reads_candidates_and_writes_indexed_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            (repository / "README.md").write_text("# Project\nDocumented behavior.\n", encoding="utf-8")
            (repository / "application.yaml").write_text("server:\n  port: 8080\n", encoding="utf-8")
            artifact_dir = root / "run" / "stages" / "init" / "documents"
            settings = Settings(
                api_key="test-key",
                base_url="https://example.invalid",
                model="test-model",
                documents_timeout=30,
                documents_summary_reserve=0,
                documents_chunk_chars=200,
            )
            state = {
                "repository": str(repository),
                "artifact_dir": str(artifact_dir),
                "deadline": time.monotonic() + 20,
                "inventory": [],
                "notes": [],
                "document_index": 0,
            }

            result = build_documents_graph().invoke(
                state,
                context=RunContext(settings=settings, model=_Model()),
            )

            self.assertEqual(result["documents"]["status"], "complete")
            self.assertEqual(result["documents"]["document_count"], 2)
            self.assertTrue((artifact_dir / "inventory.json").is_file())
            self.assertTrue((artifact_dir / "overview.md").is_file())
            self.assertTrue(list((artifact_dir / "notes").glob("*.json")))
            self.assertTrue(list((artifact_dir / "sources").glob("*.txt")))

    def test_toolbox_rejects_outside_and_secret_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            repository.mkdir()
            (repository / ".env").write_text("LLM_API_KEY=secret\n", encoding="utf-8")
            (repository / ".env.example").write_text("LLM_API_KEY=\n", encoding="utf-8")
            (repository / "guide.pdf").write_bytes(b"not a parsed PDF")
            (repository / "guide.docx").write_bytes(b"not a parsed DOCX")
            (repository / "guide.html").write_text("<p>guide</p>\n", encoding="utf-8")
            toolbox = DocumentToolbox(repository, repository / "artifacts")

            self.assertIn("error", toolbox.read_file(".env"))
            self.assertIn("error", toolbox.read_file("../outside.txt"))
            candidates = toolbox.seed_candidates()
            self.assertIn(".env.example", candidates)
            self.assertIn("guide.pdf", candidates)
            self.assertIn("guide.docx", candidates)
            self.assertIn("guide.html", candidates)

    def test_missing_api_key_is_explicit(self) -> None:
        settings = Settings(api_key=None, base_url="https://example.invalid", model="test-model")
        with self.assertRaisesRegex(DocumentsError, "LLM_API_KEY"):
            build_model(RunContext(settings=settings))

    def test_model_authentication_failure_is_fatal(self) -> None:
        class AuthModel:
            def invoke(self, _messages):
                raise RuntimeError("401 unauthorized")

        with self.assertRaises(DocumentsFatalError):
            invoke_model(AuthModel(), "system", "user")

    def test_document_unknowns_are_preserved_as_partial_gaps(self) -> None:
        state = {
            "repository": ".",
            "artifact_dir": "/tmp/run/stages/init/documents",
            "inventory": [{"status": "read"}],
            "notes": [{"unknowns": ["runtime entry point is not documented"]}],
            "unknowns": [],
            "warnings": [],
        }

        index = _documents_index(state, overview_file="stages/init/documents/overview.md")

        self.assertEqual(index["status"], "partial")
        self.assertIn("runtime entry point is not documented", index["unknowns"])
        self.assertIn("document understanding contains unresolved unknowns", index["gaps"])

    def test_document_read_error_is_persisted_and_does_not_raise(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = {
                "repository": str(root),
                "artifact_dir": str(root / "artifacts"),
                "deadline": time.monotonic() + 30,
                "inventory": [
                    {
                        "id": "missing-doc",
                        "source": "local",
                        "reference": "missing.md",
                        "title": "Missing",
                        "status": "pending",
                        "cursor": 1,
                    }
                ],
                "notes": [],
                "unknowns": [],
                "document_index": 0,
                "warnings": [],
                "summary_reserve": 0,
            }
            settings = Settings(
                api_key="test-key",
                base_url="https://example.invalid",
                model="test-model",
            )

            result = read_document(
                state,
                SimpleNamespace(context=RunContext(settings=settings, model=_Model())),
            )

            self.assertEqual(result["inventory"][0]["status"], "unavailable")
            self.assertEqual(result["inventory"][0]["stop_reason"], "read_error")
            self.assertTrue(any("document read failed" in item for item in result["warnings"]))

    def test_expired_budget_marks_pending_documents_unread_and_partial(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact_dir = root / "artifacts"
            state = {
                "repository": str(root),
                "artifact_dir": str(artifact_dir),
                "deadline": time.monotonic() - 1,
                "inventory": [
                    {
                        "id": "local-doc",
                        "source": "local",
                        "reference": "README.md",
                        "title": "README",
                        "status": "pending",
                        "cursor": 1,
                    }
                ],
                "notes": [],
                "document_index": 0,
                "summary_reserve": 0,
                "warnings": [],
            }
            settings = Settings(
                api_key="test-key",
                base_url="https://example.invalid",
                model="test-model",
            )

            result = read_document(state, RunContext(settings=settings))
            index = _documents_index({**state, **result}, overview_file=None)

            self.assertEqual(result["inventory"][0]["status"], "unread")
            self.assertEqual(result["stop_reason"], "time_budget")
            self.assertEqual(index["status"], "partial")
            self.assertEqual(index["unread_count"], 1)


if __name__ == "__main__":
    unittest.main()
