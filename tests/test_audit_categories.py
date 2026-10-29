from __future__ import annotations

import json
import unittest
from importlib.resources import files

from yasa_vulnagent.stages.audit.categories import load_category_manifest


class AuditCategoryManifestTest(unittest.TestCase):
    def test_default_manifest_is_loadable(self) -> None:
        manifest = load_category_manifest()

        self.assertEqual(manifest.profile_version, 1)
        self.assertEqual(len(manifest.categories), 11)
        self.assertEqual(len(manifest.patch_checks), 3)
        self.assertEqual(
            [check.kind for check in manifest.patch_checks],
            ["original_path", "bypass", "same_mechanism"],
        )
        self.assertEqual(
            {category.id for category in manifest.for_kind("entry")},
            {category.id for category in manifest.categories},
        )

    def test_detailed_catalog_matches_manifest(self) -> None:
        manifest = load_category_manifest()
        path = files("yasa_vulnagent.stages.audit").joinpath("category_details.json")
        payload = json.loads(path.read_text(encoding="utf-8"))
        details = payload["categories"]

        self.assertEqual(set(details), {category.id for category in manifest.categories})
        for category in manifest.categories:
            self.assertIn("cwe_ids", details[category.id])
            self.assertIn("checks", details[category.id])
            self.assertTrue(details[category.id]["checks"])
            self.assertTrue(
                all(isinstance(check, str) and check for check in details[category.id]["checks"])
            )

    def test_injection_catalog_covers_expected_families(self) -> None:
        path = files("yasa_vulnagent.stages.audit").joinpath("category_details.json")
        details = json.loads(path.read_text(encoding="utf-8"))["categories"]
        injection = details["injection_interpretation"]

        for cwe in (20, 74, 77, 78, 79, 89, 90, 93, 94, 113, 117, 235, 643, 917, 943, 1236, 1321, 1336):
            self.assertIn(cwe, injection["cwe_ids"])
        text = "\n".join(injection["checks"])
        for label in ("SQL", "NoSQL", "OS command", "template", "LDAP", "XPath", "XSS", "CSV"):
            self.assertIn(label, text)

    def test_open_exploration_has_checks_without_fixed_cwes(self) -> None:
        path = files("yasa_vulnagent.stages.audit").joinpath("category_details.json")
        details = json.loads(path.read_text(encoding="utf-8"))["categories"]
        open_exploration = details["open_exploration"]

        self.assertEqual(open_exploration["cwe_ids"], [])
        self.assertTrue(open_exploration["checks"])


if __name__ == "__main__":
    unittest.main()
