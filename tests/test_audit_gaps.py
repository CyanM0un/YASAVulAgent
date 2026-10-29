from __future__ import annotations

import unittest

from yasa_vulnagent.stages.audit.gaps import (
    make_gap,
    normalize_gap,
    normalize_gaps,
    replace_source_gaps,
)


class AuditGapTest(unittest.TestCase):
    def test_legacy_string_and_message_are_canonical(self) -> None:
        string_gap = normalize_gap("missing input", "prepare")
        message_gap = normalize_gap(
            {"source": "legacy", "message": "old gap", "paths": ["a.py"]},
            "prepare",
        )

        self.assertEqual(set(string_gap or {}), {"id", "source", "reason", "paths"})
        self.assertEqual(string_gap["source"], "prepare")
        self.assertEqual(message_gap["source"], "legacy")
        self.assertEqual(message_gap["reason"], "old gap")
        self.assertEqual(message_gap["paths"], ["a.py"])

    def test_gap_ids_are_stable_and_deduplicated(self) -> None:
        first = make_gap("plan", "duplicate", ["a.py"])
        second = make_gap("plan", "duplicate", ["a.py"])

        self.assertEqual(first, second)
        self.assertEqual(len(normalize_gaps([first, second])), 1)

    def test_replace_source_preserves_other_sources(self) -> None:
        gaps = [make_gap("prepare", "old"), make_gap("trace", "keep")]
        result = replace_source_gaps(gaps, "prepare", ["new"])

        self.assertEqual([gap["source"] for gap in result], ["trace", "prepare"])
        self.assertEqual(result[1]["reason"], "new")


if __name__ == "__main__":
    unittest.main()
