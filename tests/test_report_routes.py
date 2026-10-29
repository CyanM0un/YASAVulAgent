from __future__ import annotations

import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from yasa_vulnagent.stages.report.cvss import base_score, severity
from yasa_vulnagent.stages.report.routes import default_route, normalize_route, scan, selection


@contextmanager
def _security_repo(text: str):
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        (root / "SECURITY.md").write_text(text, encoding="utf-8")
        yield root


class ReportCvssTest(unittest.TestCase):
    def test_cvss_31_scores_match_known_vectors(self) -> None:
        cases = {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 8.8,
            "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N": 2.9,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,
        }
        for vector, expected in cases.items():
            self.assertAlmostEqual(base_score("3.1", vector), expected, places=1)

    def test_invalid_vector_and_severity(self) -> None:
        self.assertIsNone(base_score("3.1", "CVSS:3.1/AV:N"))
        self.assertEqual(severity(9.8), "critical")
        self.assertEqual(severity(8.8), "high")
        self.assertEqual(severity(6.9), "medium")
        self.assertEqual(severity(3.9), "low")
        self.assertEqual(severity(0.0), "none")


class ReportRoutesTest(unittest.TestCase):
    def test_email_candidate_and_confirmation(self) -> None:
        with _security_repo(
            "# Security\n\nPlease report vulnerabilities to security@example.com.\n"
            "Do not open a public issue.\n"
        ) as root:
            found = scan(root)
            self.assertIn("security@example.com", found["emails"])
            decision = {
                "kind": "email",
                "status": "confirmed",
                "source": "SECURITY.md",
                "recipient": "security@example.com",
                "evidence": [
                    {
                        "source": "SECURITY.md",
                        "quote": "report vulnerabilities to security@example.com",
                    }
                ],
            }
            route, gaps = normalize_route(decision, found, language="en")
        self.assertEqual(route["status"], "confirmed")
        self.assertEqual(route["recipient"], "security@example.com")
        self.assertEqual(gaps, [])

    def test_bad_quote_downgrades_to_default(self) -> None:
        with _security_repo(
            "# Security\n\nPlease report vulnerabilities to security@example.com.\n"
        ) as root:
            found = scan(root)
            decision = {
                "kind": "email",
                "status": "confirmed",
                "source": "SECURITY.md",
                "recipient": "security@example.com",
                "evidence": [{"source": "SECURITY.md", "quote": "made up quote"}],
            }
            route, gaps = normalize_route(decision, found, language="en")
            selected = selection(route, found, language="en")
        self.assertEqual(route["status"], "candidate")
        self.assertTrue(gaps)
        self.assertEqual(selected["status"], "default")
        self.assertEqual(selected["kind"], "github_advisory")

    def test_security_txt_contact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "security.txt").write_text(
                "Contact: mailto:security@example.org\nPreferred-Languages: en, zh\n",
                encoding="utf-8",
            )
            found = scan(root)
        self.assertIn("security@example.org", found["emails"])
        self.assertTrue(any(item["kind"] == "email" for item in found["candidates"]))

    def test_github_remote_derives_candidate_not_confirmed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch(
                "yasa_vulnagent.stages.report.routes._github_slug",
                return_value={
                    "owner": "acme",
                    "repo": "widget",
                    "url": "https://github.com/acme/widget",
                    "advisory_url": "https://github.com/acme/widget/security/advisories/new",
                },
            ):
                found = scan(root)
        self.assertEqual(found["github"]["owner"], "acme")
        candidate = next(
            item for item in found["candidates"] if item["kind"] == "github_advisory"
        )
        self.assertEqual(candidate["status"], "candidate")
        self.assertIn("unverified", candidate["notes"].lower())

    def test_no_policy_uses_default(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            found = scan(Path(temporary))
            selected = selection(default_route({}), found, language="en")
        self.assertEqual(selected["kind"], "github_advisory")
        self.assertEqual(selected["status"], "default")
        self.assertFalse(selected["notes"] == "")

    def test_unknown_decision_keeps_unknown_route(self) -> None:
        with _security_repo("# Security\n\nContact security@example.com\n") as root:
            found = scan(root)
            route, gaps = normalize_route(
                {"kind": "email", "status": "unknown", "source": "SECURITY.md"},
                found,
                language="en",
            )
            selected = selection(route, found, language="en")
        self.assertEqual(route["status"], "unknown")
        self.assertEqual(selected["status"], "unknown")
        self.assertTrue(gaps)


if __name__ == "__main__":
    unittest.main()
