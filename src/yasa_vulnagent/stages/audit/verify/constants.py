"""Bounded audit verify constants.

Verify reuses the audit-stage budget and existing agent caps. These values are
code constants, not settings.
"""

from __future__ import annotations

MAX_EVIDENCE_ITEMS = 16
VERIFIER_MAX_ROUNDS = 18
REVIEW_MAX_ROUNDS = 14
SECOND_VERIFIER_MAX_ROUNDS = 18
REQUEST_TIMEOUT_SECONDS = 180
MODEL_TIMEOUT_SECONDS = 180
