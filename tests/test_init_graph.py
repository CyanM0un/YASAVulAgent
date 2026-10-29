from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from yasa_vulnagent.stages.init import graph as init_graph
from yasa_vulnagent.stages.init.cwe.node import run as run_cwe
from yasa_vulnagent.stages.init.cwe.node import validate_cwe


class InitGraphTest(unittest.TestCase):
    def test_nodes_run_in_legacy_order_without_persist(self) -> None:
        events: list[str] = []

        def record(name: str):
            def node(state):
                del state
                events.append(name)
                return {}

            return node

        with (
            patch.object(init_graph, "run_yasa", side_effect=record("yasa")),
            patch.object(init_graph, "run_documents", side_effect=record("documents")),
            patch.object(init_graph, "run_cwe", side_effect=record("cwe")),
            patch.object(init_graph, "run_security_history", side_effect=record("security_history")),
        ):
            init_graph.build_init_graph().invoke({})

        self.assertEqual(events, ["yasa", "documents", "cwe", "security_history"])

    def test_invalid_cwe_is_logged_and_persisted_as_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "missing.zip"
            with self.assertLogs("yasa_vulnagent.stages.init.cwe.node", level="WARNING") as logs:
                update = run_cwe({"config": {"cwe_archive_path": str(archive)}})

        self.assertEqual(update["init_checks"]["cwe"]["status"], "unavailable")
        self.assertFalse(update["init_checks"]["cwe"]["valid"])
        self.assertEqual(len(logs.records), 1)
        self.assertIn("reason=missing", logs.output[0])

    def test_incomplete_cwe_is_logged_and_persisted_as_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "incomplete.zip"
            with zipfile.ZipFile(archive, "w") as archive_file:
                archive_file.writestr(
                    "1435.xml",
                    b'<Root xmlns="http://cwe.mitre.org/cwe-7">'
                    b"<Weaknesses><Weakness ID=\"20\" /></Weaknesses>"
                    b"</Root>",
                )
            with self.assertLogs("yasa_vulnagent.stages.init.cwe.node", level="WARNING") as logs:
                update = run_cwe({"config": {"cwe_archive_path": str(archive)}})

        self.assertEqual(update["init_checks"]["cwe"]["status"], "unavailable")
        self.assertEqual(update["init_checks"]["cwe"]["entry_count"], 1)
        self.assertIn("missing_ids=", logs.output[0])

    def test_missing_cwe_does_not_skip_later_init_nodes(self) -> None:
        events: list[str] = []

        def record(name: str):
            def node(state):
                del state
                events.append(name)
                return {}

            return node

        with (
            patch.object(init_graph, "run_yasa", side_effect=record("yasa")),
            patch.object(init_graph, "run_documents", side_effect=record("documents")),
            patch.object(init_graph, "run_security_history", side_effect=record("security_history")),
            tempfile.TemporaryDirectory() as temporary,
        ):
            archive = Path(temporary) / "missing.zip"
            with self.assertLogs("yasa_vulnagent.stages.init.cwe.node", level="WARNING"):
                init_graph.build_init_graph().invoke(
                    {"config": {"cwe_archive_path": str(archive)}}
                )

        self.assertEqual(events, ["yasa", "documents", "security_history"])


class CweValidationTest(unittest.TestCase):
    def test_copied_archive_is_valid(self) -> None:
        archive = Path(__file__).parents[1] / ".knowledge" / "cwe-top25-1435.xml.zip"
        result = validate_cwe(archive)
        self.assertTrue(result["valid"])
        self.assertEqual(result["entry_count"], 25)
        self.assertEqual(result["missing_ids"], [])

    def test_bad_zip_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "bad.zip"
            archive.write_bytes(b"not a zip")
            result = validate_cwe(archive)

        self.assertFalse(result["valid"])
        self.assertTrue(result["reason"].startswith("invalid archive:"))

    def test_invalid_xml_is_invalid(self) -> None:
        archive = self._write_archive(b"<not-cwe>")
        result = validate_cwe(archive)
        self.assertFalse(result["valid"])
        self.assertTrue(result["reason"].startswith("invalid XML:"))

    def test_missing_top25_ids_are_reported_in_memory(self) -> None:
        xml = (
            b'<Root xmlns="http://cwe.mitre.org/cwe-7">'
            b"<Weaknesses><Weakness ID=\"20\" /></Weaknesses>"
            b"</Root>"
        )
        archive = self._write_archive(xml)
        result = validate_cwe(archive)
        self.assertFalse(result["valid"])
        self.assertEqual(result["entry_count"], 1)
        self.assertIn("22", result["missing_ids"])

    def _write_archive(self, content: bytes) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        archive = Path(temporary.name) / "cwe.zip"
        with zipfile.ZipFile(archive, "w") as archive_file:
            archive_file.writestr("1435.xml", content)
        return archive


if __name__ == "__main__":
    unittest.main()
