from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

from langchain_core.messages import ToolMessage

from yasa_vulnagent.config import Settings
from yasa_vulnagent.stages.init.documents.node import read_document
from yasa_vulnagent.workflow.state import RunContext


class _Response:
    def __init__(self, content: str, tool_calls: list[dict[str, object]] | None = None) -> None:
        self.content = content
        self.tool_calls = tool_calls or []


class _AgentModel:
    def __init__(self, read_all: bool) -> None:
        self.read_all = read_all

    def bind_tools(self, _tools):
        return self

    def invoke(self, messages):
        last = messages[-1]
        if isinstance(last, ToolMessage):
            if last.tool_call_id == "c1" and self.read_all:
                return _Response("", [{"name": "read_chunk", "args": {"chunk_id": "c2"}, "id": "c2"}])
            return _Response(
                json.dumps(
                    {
                        "summary": "The README describes behavior.",
                        "facts": [{"claim": "alpha", "location": "README.md:1"}],
                        "unknowns": [],
                        "follow_up": [],
                        "skip_reasons": {},
                    }
                )
            )
        return _Response("", [{"name": "read_chunk", "args": {"chunk_id": "c1"}, "id": "c1"}])


class DocumentsAgentTest(unittest.TestCase):
    def _run(self, *, read_all: bool) -> tuple[dict, Path]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        repository = root / "repository"
        repository.mkdir()
        (repository / "README.md").write_text("alpha\nbeta\n", encoding="utf-8")
        artifact_dir = root / "run" / "stages" / "init" / "documents"
        settings = Settings(
            api_key="test-key",
            base_url="https://example.invalid",
            model="test-model",
            documents_read_mode="agent",
            documents_agent_chunk_tokens=1,
            documents_max_model_calls=10,
            agent_hard_task_cap=10,
            agent_model_retries=1,
        )
        state = {
            "repository": str(repository),
            "artifact_dir": str(artifact_dir),
            "deadline": time.monotonic() + 20,
            "summary_reserve": 0,
            "inventory": [
                {
                    "id": "doc-1",
                    "reference": "README.md",
                    "title": "README",
                    "role": "documentation",
                    "source": "internal",
                    "status": "pending",
                }
            ],
            "notes": [],
            "unknowns": [],
            "warnings": [],
            "document_index": 0,
        }
        result = read_document(state, RunContext(settings=settings, model=_AgentModel(read_all)))
        return result, artifact_dir

    def test_agent_reads_all_chunks_and_records_complete_coverage(self) -> None:
        result, artifact_dir = self._run(read_all=True)
        self.assertEqual(result["inventory"][0]["status"], "read")
        coverage = json.loads((artifact_dir / "coverage.json").read_text(encoding="utf-8"))
        self.assertTrue(coverage["documents"][0]["complete"])
        self.assertTrue(list((artifact_dir / "notes").glob("*.json")))
        self.assertTrue((artifact_dir / "chunks" / "doc-1.json").is_file())

    def test_agent_early_stop_is_partial_not_complete(self) -> None:
        result, artifact_dir = self._run(read_all=False)
        self.assertEqual(result["inventory"][0]["status"], "partial")
        coverage = json.loads((artifact_dir / "coverage.json").read_text(encoding="utf-8"))
        self.assertFalse(coverage["documents"][0]["complete"])
        self.assertTrue(any(item["status"] == "unread" for item in coverage["documents"][0]["chunks"]))


if __name__ == "__main__":
    unittest.main()
