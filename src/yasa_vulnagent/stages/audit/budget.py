"""Audit-stage wall-clock budget shared by all audit nodes."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AuditBudget:
    """One stage-wide deadline; task budgets are carved from it."""

    deadline: float
    started_at: float

    @classmethod
    def create(cls, timeout: int) -> "AuditBudget":
        now = time.monotonic()
        return cls(deadline=now + max(1, int(timeout)), started_at=now)

    def remaining_seconds(self) -> float:
        return max(0.0, self.deadline - time.monotonic())

    def expired(self) -> bool:
        return self.remaining_seconds() <= 0

    def effective_verify_reserve(self, reserve_seconds: int) -> float:
        """Reserve up to 40% of total audit time so verify is not starved by trace."""
        reserve = max(0.0, float(reserve_seconds))
        total = max(0.0, self.deadline - self.started_at)
        if reserve <= 0 or total <= 0:
            return 0.0
        return min(reserve, total * 0.4)

    def trace_deadline(self, reserve_seconds: int) -> float:
        return max(self.started_at, self.deadline - self.effective_verify_reserve(reserve_seconds))

    def trace_expired(self, reserve_seconds: int) -> bool:
        return time.monotonic() >= self.trace_deadline(reserve_seconds)

    def snapshot(self) -> dict[str, float]:
        return {
            "remaining_seconds": self.remaining_seconds(),
            "elapsed_seconds": max(0.0, time.monotonic() - self.started_at),
        }


@dataclass
class AuditTaskBudget:
    """Thread-safe per-task model-call budget."""

    deadline: float
    max_model_calls: int
    model_calls: int = 0
    _lock: Any = field(default_factory=threading.Lock, repr=False)

    def consume_model_call(self) -> bool:
        with self._lock:
            if time.monotonic() >= self.deadline or self.model_calls >= self.max_model_calls:
                return False
            self.model_calls += 1
            return True

    def remaining_seconds(self) -> float:
        return max(0.0, self.deadline - time.monotonic())

    def snapshot(self) -> dict[str, Any]:
        return {
            "model_calls": self.model_calls,
            "max_model_calls": self.max_model_calls,
            "remaining_seconds": self.remaining_seconds(),
        }
