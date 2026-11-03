from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from yasa_vulnagent.stages.init.documents.tools import DocumentToolbox


class DocumentsToolsTest(unittest.TestCase):
    def test_read_file_rejects_oversized_and_binary_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            repository.mkdir()
            (repository / "large.txt").write_text("x" * 100, encoding="utf-8")
            (repository / "binary.txt").write_bytes(b"abc\x00def")
            toolbox = DocumentToolbox(repository, Path(temporary) / "artifacts", max_text_bytes=10)
            self.assertEqual(toolbox.read_file("large.txt")["status"], "too_large")
            self.assertIn("error", toolbox.read_file("binary.txt"))

    def test_listing_and_search_are_paginated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            repository.mkdir()
            for name in ("a.md", "b.md", "c.md"):
                (repository / name).write_text(f"{name}\nneedle\n", encoding="utf-8")
            toolbox = DocumentToolbox(repository, Path(temporary) / "artifacts")
            first = toolbox.list_directory(".", max_entries=1, offset=0)
            self.assertEqual(first["returned"], 1)
            self.assertTrue(first["truncated"])
            self.assertEqual(first["next_cursor"], 1)
            second = toolbox.list_directory(".", max_entries=1, offset=1)
            self.assertEqual(second["entries"][0]["name"], "b.md")
            search = toolbox.search_text("needle", max_results=1, offset=0)
            self.assertEqual(search["returned"], 1)
            self.assertTrue(search["truncated"])

    def test_file_cache_invalidates_on_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            repository.mkdir()
            path = repository / "README.md"
            path.write_text("one\n", encoding="utf-8")
            toolbox = DocumentToolbox(repository, Path(temporary) / "artifacts")
            self.assertIn("one", toolbox.read_file("README.md")["text"])
            self.assertTrue(toolbox._cache)
            time.sleep(0.01)
            path.write_text("two\n", encoding="utf-8")
            self.assertIn("two", toolbox.read_file("README.md")["text"])

    def test_markdown_link_urls_register_without_raising(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            repository.mkdir()
            (repository / "docker.md").write_text(
                "Run on [http://localhost:8000](http://localhost:8000) after start.\n",
                encoding="utf-8",
            )
            toolbox = DocumentToolbox(repository, Path(temporary) / "artifacts")
            result = toolbox.read_file("docker.md")
            self.assertIn("localhost:8000", result["text"])
            self.assertIn("http://localhost:8000", toolbox.allowed_urls)


if __name__ == "__main__":
    unittest.main()
