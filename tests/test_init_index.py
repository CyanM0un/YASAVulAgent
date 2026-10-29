from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from yasa_vulnagent.stages.init.index import InitIndex


class InitIndexTest(unittest.TestCase):
    def test_indexes_and_searches_notes_commits_units(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            index = InitIndex(Path(temporary) / "index.sqlite")
            index.upsert_note(
                {
                    "document_id": "doc-1",
                    "source": "README.md",
                    "summary": "authentication is enabled by default",
                    "facts": [],
                    "unknowns": [],
                }
            )
            index.upsert_commit(
                {
                    "commit": "a" * 40,
                    "subject": "fix authentication bypass",
                    "reason": "adds a missing authorization check",
                }
            )
            index.upsert_unit(
                "a" * 40,
                {"id": "u1", "kind": "authorization", "summary": "checks the caller", "paths": ["Auth.java"]},
            )
            self.assertEqual(index.search_notes("authentication")["results"][0]["document_id"], "doc-1")
            self.assertEqual(index.search_commits("bypass")["results"][0]["sha"], "a" * 40)
            self.assertEqual(index.search_units("caller")["results"][0]["unit_id"], "u1")
            index.close()

    def test_quotes_are_escaped_and_empty_query_is_safe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            index = InitIndex(Path(temporary) / "index.sqlite")
            index.upsert_note({"document_id": "doc-1", "summary": 'a "quoted" term'})
            self.assertEqual(index.search_notes("")["results"], [])
            self.assertEqual(index.search_notes('"quoted"')["results"][0]["note_id"], "doc-1")
            index.close()


if __name__ == "__main__":
    unittest.main()
