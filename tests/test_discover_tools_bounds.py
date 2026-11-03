from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from yasa_vulnagent.stages.discover.ledger import DiscoverLedger
from yasa_vulnagent.stages.discover.screen.tools import ReadCache, SourceToolbox


class DiscoverToolBoundsTest(unittest.TestCase):
    def _repository(self, root: Path) -> Path:
        repository = root / "repository"
        repository.mkdir()
        (repository / "ok.py").write_text("needle = 1\n", encoding="utf-8")
        (repository / "big.py").write_text("needle\n" + "x" * 4096, encoding="utf-8")
        for index in range(5):
            (repository / f"f{index}.py").write_text(f"needle {index}\n", encoding="utf-8")
        return repository

    def test_search_skips_oversized_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self._repository(Path(temporary))
            toolbox = SourceToolbox(
                repository,
                allowed_paths=["ok.py", "big.py"],
                search_max_file_bytes=1024,
            )
            result = toolbox.search_text("needle")
            self.assertEqual([item["path"] for item in result["matches"]], ["ok.py"])
            self.assertEqual(result["skipped_large"], 1)

    def test_search_caps_scanned_files_and_pages(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self._repository(Path(temporary))
            paths = [f"f{index}.py" for index in range(5)]
            toolbox = SourceToolbox(
                repository, allowed_paths=paths, max_scan_files=2
            )
            seen: list[str] = []
            cursor = ""
            pages = 0
            while True:
                result = toolbox.search_text("needle", cursor=cursor)
                pages += 1
                seen.extend(item["path"] for item in result["matches"])
                if not result["truncated"]:
                    break
                cursor = str(result["next_cursor"])
                self.assertLessEqual(pages, 5)
            self.assertEqual(sorted(seen), sorted(paths))
            self.assertGreaterEqual(pages, 2)

    def test_read_cache_reuses_content_until_the_file_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "source.py"
            path.write_text("a = 1\n", encoding="utf-8")
            cache = ReadCache()
            first = cache.lines(path)
            self.assertIs(cache.lines(path), first)
            path.write_text("a = 2\nb = 3\n", encoding="utf-8")
            self.assertNotEqual(cache.lines(path), first)

    def test_save_note_enforces_limit_and_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self._repository(Path(temporary))
            ledger_path = Path(temporary) / "ledger.sqlite"
            with DiscoverLedger.open(ledger_path) as ledger:
                ledger.replace_inventory(
                    [
                        {
                            "path": "ok.py",
                            "status": "pending",
                            "usage_hint": "production-candidate",
                            "content_type": "text",
                        }
                    ],
                    [],
                )
                ledger.put_task(
                    {
                        "task_id": "task-1",
                        "kind": "screen",
                        "status": "running",
                        "paths": ["ok.py"],
                    }
                )
                toolbox = SourceToolbox(
                    repository,
                    ledger=ledger,
                    task_id="task-1",
                    allowed_paths=["ok.py"],
                    notes_max=2,
                    note_chars=20,
                )
                self.assertEqual(toolbox.save_note("first", "value one")["status"], "ok")
                self.assertEqual(toolbox.save_note("second", "x" * 50)["status"], "ok")
                self.assertIn("error", toolbox.save_note("third", "nope"))
                notes = toolbox.notes_text()
                self.assertIn("first: value one", notes)
                self.assertIn("x" * 20, notes)
                self.assertEqual(ledger.note_count("task-1"), 2)

    def test_search_accepts_a_single_file_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self._repository(Path(temporary))
            toolbox = SourceToolbox(repository, allowed_paths=["ok.py", "f0.py"])
            result = toolbox.search_text("needle", path="ok.py")
            self.assertEqual([item["path"] for item in result["matches"]], ["ok.py"])

    def test_search_skips_scope_entries_that_are_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self._repository(Path(temporary))
            toolbox = SourceToolbox(repository, allowed_paths=[".", "ok.py"])
            result = toolbox.search_text("needle")
            self.assertEqual([item["path"] for item in result["matches"]], ["ok.py"])
            self.assertEqual(
                [item for item in toolbox.receipts if item.get("status") == "error"], []
            )

    def test_search_reports_missing_and_out_of_scope_paths_alike(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self._repository(Path(temporary))
            toolbox = SourceToolbox(repository, allowed_paths=["ok.py"])
            existing = toolbox.search_text("needle", path="f0.py")
            missing = toolbox.search_text("needle", path="nope.py")
            self.assertEqual(
                existing["error"],
                "file is unavailable; it is missing or outside this task's scope",
            )
            self.assertEqual(existing["error"], missing["error"])


if __name__ == "__main__":
    unittest.main()
