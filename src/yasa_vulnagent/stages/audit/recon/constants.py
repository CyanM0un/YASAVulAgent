"""Bounded recon constants.

These are code constants, not settings. Recon uses the audit-stage budget and
the existing agent caps; promote a value only when tuning proves necessary.
"""

from __future__ import annotations

MAX_CONSTRAINTS = 20
MAX_OPERATIONS = 30
MAX_INVESTIGATIONS = 20
MAX_LOGIC_TASKS = 8
MAX_EVIDENCE = 8
MAX_OVERVIEW_CHARS = 12_000
MAX_TRACE_VIEWS = 20
MAX_SUMMARY_VIEWS = 20
RECON_MAX_ROUNDS = 40
REQUEST_TIMEOUT_SECONDS = 180
MODEL_TIMEOUT_SECONDS = 180
