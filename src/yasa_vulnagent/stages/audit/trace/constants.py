"""Bounded trace constants.

These are code constants, not settings: trace uses the audit-stage budget and
the existing agent caps. Promote one only when tuning proves necessary.
"""

from __future__ import annotations

TRIAGE_ROUNDS = 2
TRIAGE_MAX_UNITS = 12
MAX_SPECIALISTS = 3
SPECIALIST_CONCURRENCY = 2
SPECIALIST_MAX_ROUNDS = 12
LEAD_MAX_ROUNDS = 24
SUMMARY_MAX_PER_TASK = 3
SUMMARY_MAX_REUSE = 10
MAX_FOCUS_UNITS = 5
MAX_FLOWS_PER_TASK = 40
MAX_EVIDENCE_CHARS = 400
REQUEST_TIMEOUT_SECONDS = 180
MODEL_TIMEOUT_SECONDS = 180
