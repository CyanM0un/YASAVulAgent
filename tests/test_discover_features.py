from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from yasa_vulnagent.stages.discover.features import (
    build_source_hints,
    execute_query,
    process_observations,
    validate_observation,
)
from yasa_vulnagent.stages.discover.ledger import DiscoverLedger


class DiscoverFeatureTest(unittest.TestCase):
    def _ledger(self, root: Path) -> DiscoverLedger:
        repository = root / "repository"
        repository.mkdir()
        (repository / "Controller.java").write_text(
            "@RestController\n"
            "class Controller {\n"
            "  @RequestMapping(\"/input\")\n"
            "  void handle(String value) { use(value); }\n"
            "}\n",
            encoding="utf-8",
        )
        (repository / "Wrapper.java").write_text(
            "class Wrapper {\n"
            "  @RequestMapping(\"/wrapped\")\n"
            "  void wrapped(String value) { use(value); }\n"
            "}\n",
            encoding="utf-8",
        )
        artifact = root / "artifacts"
        artifact.mkdir()
        ledger = DiscoverLedger.open(artifact / "ledger.sqlite")
        ledger.replace_inventory(
            [
                {
                    "path": "Controller.java",
                    "size": (repository / "Controller.java").stat().st_size,
                    "fingerprint": "controller-fp",
                    "content_type": "text",
                    "usage_hint": "production-candidate",
                    "status": "pending",
                },
                {
                    "path": "Wrapper.java",
                    "size": (repository / "Wrapper.java").stat().st_size,
                    "fingerprint": "wrapper-fp",
                    "content_type": "text",
                    "usage_hint": "production-candidate",
                    "status": "pending",
                },
            ],
            [],
        )
        return ledger

    def test_observation_creates_global_candidates_and_confirm_tasks_without_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ledger = self._ledger(root)
            try:
                observatory = {
                    "kind": "annotation_usage",
                    "name": "@RequestMapping",
                    "role": "registration",
                    "definition": {
                        "path": "Controller.java",
                        "line_start": 3,
                        "line_end": 3,
                    },
                    "evidence_refs": ["source:Controller.java:3-3"],
                    "query": {
                        "kind": "annotation_usage",
                        "target": "@RequestMapping",
                        "regex": False,
                        "scope": [],
                        "max_results": 200,
                    },
                }
                summary = process_observations(
                    root / "repository",
                    ledger,
                    [observatory],
                    task_id="screen-0001",
                    artifact_dir=root / "artifacts",
                )
                self.assertEqual(summary["candidates"], 2)
                self.assertEqual(summary["tasks"], 2)
                self.assertEqual(ledger.count_mechanisms(), 1)
                self.assertEqual(ledger.count_feature_queries(), 1)
                self.assertEqual(ledger.count_feature_hits(), 2)
                self.assertEqual(len(ledger.entries(status="candidate")), 2)
                self.assertEqual(len(ledger.list_tasks(kind_prefix="confirm")), 2)
                self.assertEqual(ledger.query_rows()[0]["complete"], True)
                self.assertEqual(ledger.connection.execute("SELECT COUNT(*) FROM read_receipts").fetchone()[0], 0)
                self.assertEqual(ledger.get_file("Wrapper.java")["status"], "candidate")
                again = process_observations(
                    root / "repository",
                    ledger,
                    [observatory],
                    task_id="screen-0001b",
                    artifact_dir=root / "artifacts",
                )
                self.assertEqual(again["candidates"], 0)
                self.assertEqual(again["tasks"], 0)
                self.assertEqual(ledger.count_feature_queries(), 1)
                self.assertEqual(ledger.count_feature_hits(), 2)
            finally:
                ledger.close()

    def test_invalid_observation_does_not_query(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ledger = self._ledger(root)
            try:
                summary = process_observations(
                    root / "repository",
                    ledger,
                    [
                        {
                            "kind": "annotation_usage",
                            "name": "@Missing",
                            "definition": {
                                "path": "Controller.java",
                                "line_start": 99,
                                "line_end": 99,
                            },
                            "evidence_refs": ["source:Controller.java:99-99"],
                            "query": {"kind": "annotation_usage", "target": "@Missing"},
                        }
                    ],
                    task_id="screen-0002",
                    artifact_dir=root / "artifacts",
                )
                self.assertEqual(summary["candidates"], 0)
                self.assertEqual(ledger.count_feature_queries(), 0)
                self.assertTrue(summary["warnings"])
            finally:
                ledger.close()

    def test_invalid_regex_is_warned_without_creating_a_query(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ledger = self._ledger(root)
            try:
                summary = process_observations(
                    root / "repository",
                    ledger,
                    [
                        {
                            "kind": "text",
                            "name": "input",
                            "role": "source",
                            "definition": {
                                "path": "Controller.java",
                                "line_start": 3,
                                "line_end": 3,
                            },
                            "evidence_refs": ["source:Controller.java:3-3"],
                            "query": {
                                "kind": "text",
                                "target": "[",
                                "regex": True,
                            },
                        }
                    ],
                    task_id="screen-0003",
                    artifact_dir=root / "artifacts",
                )
                self.assertEqual(ledger.count_feature_queries(), 0)
                self.assertEqual(summary["candidates"], 0)
                self.assertTrue(
                    any("invalid feature query regex" in item for item in summary["warnings"])
                )
            finally:
                ledger.close()

    def test_definition_requires_a_same_task_non_truncated_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ledger = self._ledger(root)
            try:
                observation = {
                    "kind": "text",
                    "name": "input",
                    "role": "source",
                    "definition": {
                        "path": "Controller.java",
                        "line_start": 3,
                        "line_end": 3,
                    },
                    "evidence_refs": ["source:Controller.java:3-3"],
                    "query": {
                        "kind": "text",
                        "target": "use",
                        "regex": False,
                        "scope": [],
                        "max_results": 20,
                    },
                }
                blocked = process_observations(
                    root / "repository",
                    ledger,
                    [observation],
                    task_id="screen-0004",
                    artifact_dir=root / "artifacts",
                    read_ranges_by_task={"screen-0004": []},
                )
                self.assertEqual(blocked["candidates"], 0)
                self.assertEqual(ledger.count_feature_queries(), 0)
                self.assertTrue(
                    any("not read in this task" in item for item in blocked["warnings"])
                )

                truncated = process_observations(
                    root / "repository",
                    ledger,
                    [observation],
                    task_id="screen-0004b",
                    artifact_dir=root / "artifacts",
                    read_ranges_by_task={
                        "screen-0004b": [
                            {
                                "tool": "read_file",
                                "path": "Controller.java",
                                "start_line": 1,
                                "end_line": 5,
                                "total_lines": 5,
                                "truncated": True,
                                "status": "ok",
                            }
                        ]
                    },
                )
                self.assertEqual(truncated["candidates"], 0)
                self.assertEqual(ledger.count_feature_queries(), 0)
                self.assertTrue(
                    any("not read in this task" in item for item in truncated["warnings"])
                )

                covered = process_observations(
                    root / "repository",
                    ledger,
                    [observation],
                    task_id="screen-0004c",
                    artifact_dir=root / "artifacts",
                    read_ranges_by_task={
                        "screen-0004c": [
                            {
                                "tool": "read_file",
                                "path": "Controller.java",
                                "start_line": 1,
                                "end_line": 5,
                                "total_lines": 5,
                                "truncated": False,
                                "status": "ok",
                            }
                        ]
                    },
                )
                self.assertEqual(covered["candidates"], 2)
                self.assertEqual(ledger.count_feature_queries(), 1)
            finally:
                ledger.close()

    def test_query_kinds_and_truncation_cursor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ledger = self._ledger(root)
            try:
                repository = root / "repository"
                (repository / "Extra.java").write_text(
                    "class Extra { void run() { use(value); use(value); } }\n",
                    encoding="utf-8",
                )
                ledger.replace_inventory(
                    [
                        *[
                            {
                                "path": file["path"],
                                "size": file["size"],
                                "fingerprint": file["fingerprint"],
                                "content_type": "text",
                                "usage_hint": "production-candidate",
                                "status": "pending",
                            }
                            for file in ledger.iter_files(limit=1000)
                        ],
                        {
                            "path": "Extra.java",
                            "size": (repository / "Extra.java").stat().st_size,
                            "fingerprint": "extra-fp",
                            "content_type": "text",
                            "usage_hint": "production-candidate",
                            "status": "pending",
                        },
                    ],
                    [],
                )
                first = execute_query(
                    repository,
                    ledger,
                    {"kind": "function_call", "target": "use", "max_results": 1},
                )
                self.assertTrue(first["truncated"])
                self.assertEqual(first["returned"], 1)
                second = execute_query(
                    repository,
                    ledger,
                    {
                        "kind": "function_call",
                        "target": "use",
                        "cursor": first["next_cursor"],
                        "max_results": 1,
                    },
                )
                self.assertEqual(second["returned"], 1)
                self.assertNotEqual(
                    first["results"][0]["line_start"],
                    second["results"][0]["line_start"],
                )
                symbol = execute_query(
                    repository,
                    ledger,
                    {"kind": "symbol_reference", "target": "use", "max_results": 10},
                )
                self.assertEqual(len(symbol["results"]), 4)
                text = execute_query(
                    repository,
                    ledger,
                    {"kind": "text", "target": "use", "max_results": 10},
                )
                self.assertEqual(len(text["results"]), 4)
                regex = execute_query(
                    repository,
                    ledger,
                    {
                        "kind": "text",
                        "target": r"void\s+run",
                        "regex": True,
                        "max_results": 10,
                    },
                )
                self.assertEqual(len(regex["results"]), 1)
            finally:
                ledger.close()

    def test_source_hints_are_model_ordering_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ledger = self._ledger(root)
            try:
                ledger.put_entry(
                    {
                        "entry_id": "entry-source",
                        "status": "candidate",
                        "kind": "input-candidate",
                        "role": "source",
                        "location": {"path": "Controller.java", "line_start": 4, "line_end": 4},
                        "summary": "input",
                        "evidence_refs": [],
                    }
                )
                hints = build_source_hints(ledger)
                self.assertEqual(hints["source_paths"], ["Controller.java"])
                self.assertIn("ordering suggestions", hints["note"])
            finally:
                ledger.close()


if __name__ == "__main__":
    unittest.main()
