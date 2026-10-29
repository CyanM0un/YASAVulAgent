from __future__ import annotations

import unittest

from yasa_vulnagent.stages.report.contract import (
    body_errors,
    body_score_errors,
    body_sha256,
    cwe_errors,
    derive_fields,
    redact,
    review_errors,
)
from yasa_vulnagent.stages.report.schema import REVIEW_CHECKS


def valid_body(
    *,
    score: str = "9.8",
    severity: str = "critical",
    cwe: str = "CWE-78",
    vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
) -> str:
    filler = (
        "The request value crosses the intended security boundary and reaches "
        "the command execution path without an effective guard. "
    ) * 8
    return f"""# Title
Remote command execution in the widget request handler

# Summary

Affected component: `widget/handler.py`. Tested revision: `abc123`.
The request parameter crosses the command-execution boundary.
Base score: {score} ({severity}). Vector: {vector}.

# Details

## Root cause

The request value is passed to a shell command without quoting. {filler}

## Attack preconditions

The attacker can send an authenticated request to the widget endpoint.

## Expected versus observed behavior

Expected: the value is data, not shell syntax. Observed: the value is executed
as a shell command.

# Proof of concept

## Setup

Start the widget service with the documented test configuration.

## Steps

Send the following request:

```http
POST /widget HTTP/1.1
Host: localhost
Content-Type: application/json

{{"name": "a; id"}}
```

Expected: the name is stored literally. Observed: the response contains the
output of `id`.

## Cleanup

Stop the service and remove the temporary data directory.

# Impact

An authenticated user can run commands as the service account. {cwe} describes
the weakness. {filler}

## Remediation

Pass the value as an argument list instead of a shell string, and add a
regression test that rejects shell metacharacters.

## Regression test

Add a test that sends the same request and asserts that no command output is
returned.
"""


class ReportContractTest(unittest.TestCase):
    def test_valid_body_passes(self) -> None:
        body = valid_body()
        self.assertEqual(body_errors(body), [])
        self.assertEqual(
            body_score_errors(
                body,
                {
                    "base_score": 9.8,
                    "severity": "critical",
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                },
            ),
            [],
        )
        fields = derive_fields(body)
        self.assertEqual(fields["title"], "Remote command execution in the widget request handler")
        self.assertIn("widget/handler.py", fields["summary"])
        self.assertIn("POST /widget", fields["steps_to_reproduce"])
        self.assertIn("authenticated user", fields["impact"])

    def test_section_order_and_placeholders_rejected(self) -> None:
        body = valid_body().replace("# Details", "# Detail")
        self.assertTrue(any("top-level sections" in item for item in body_errors(body)))
        body = valid_body() + "\nTODO: add impact\n"
        self.assertTrue(any("placeholder" in item for item in body_errors(body)))

    def test_secret_and_internal_and_absolute_path_rejected(self) -> None:
        for extra in (
            "\npassword=supersecret\n",
            "\nstages/validate/validation.json\n",
            "\n/home/analyst/work/repo/widget.py\n",
        ):
            body = valid_body() + extra
            self.assertTrue(body_errors(body), extra)

    def test_redaction(self) -> None:
        text = "token=abc123 -----BEGIN RSA PRIVATE KEY----- x -----END RSA PRIVATE KEY-----"
        redacted = redact(text)
        self.assertIn("[REDACTED]", redacted)
        self.assertNotIn("abc123", redacted)
        self.assertNotIn("PRIVATE KEY----- x", redacted)

    def test_redacted_secret_is_allowed(self) -> None:
        body = redact(valid_body() + "\npassword=supersecret\n")
        self.assertIn("password=[REDACTED]", body)
        self.assertEqual(body_errors(body), [])

    def test_cwe_must_be_audit_supported(self) -> None:
        self.assertEqual(cwe_errors(["CWE-78"], ["CWE-78"]), [])
        self.assertTrue(cwe_errors(["CWE-78"], []))
        self.assertTrue(cwe_errors(["CWE-78"], ["CWE-79"]))
        self.assertTrue(cwe_errors(["CWE-78"], ["78"]))

    def test_review_requires_all_checks(self) -> None:
        review = {
            "status": "approved",
            "independent": True,
            "conclusion": "checked",
            "checks": {name: True for name in REVIEW_CHECKS},
            "issues": [],
        }
        self.assertEqual(review_errors(review), [])
        broken = dict(review)
        broken["checks"] = dict(review["checks"])
        broken["checks"]["cvss_justified"] = False
        self.assertTrue(review_errors(broken))
        self.assertTrue(review_errors({**review, "independent": False}))

    def test_hash_changes_with_body(self) -> None:
        self.assertNotEqual(body_sha256("a"), body_sha256("b"))


if __name__ == "__main__":
    unittest.main()
