from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any


class BudgetStop(RuntimeError):
    """Raised when a task-level runtime budget is exhausted."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class TaskBudget:
    """Layered task budget: deadline, model attempts, and a hard safety cap."""

    deadline: float | None = None
    max_model_calls: int = 96
    max_rounds_per_invocation: int = 32
    hard_task_cap: int = 128
    model_calls: int = 0
    tool_rounds: int = 0

    def check(self) -> None:
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise BudgetStop("time_budget")
        if self.model_calls >= min(self.max_model_calls, self.hard_task_cap):
            raise BudgetStop("step_budget")

    def consume_model_attempt(self) -> None:
        self.check()
        self.model_calls += 1

    def consume_tool_round(self) -> None:
        self.check()
        self.tool_rounds += 1

    def remaining_seconds(self) -> float | None:
        if self.deadline is None:
            return None
        return max(0.0, self.deadline - time.monotonic())

    def exhausted_reason(self) -> str:
        if self.remaining_seconds() == 0:
            return "time_budget"
        if self.model_calls >= min(self.max_model_calls, self.hard_task_cap):
            return "step_budget"
        return ""

    def snapshot(self) -> dict[str, int | str | None]:
        return {
            "model_calls": self.model_calls,
            "tool_rounds": self.tool_rounds,
            "max_model_calls": self.max_model_calls,
            "max_rounds_per_invocation": self.max_rounds_per_invocation,
            "hard_task_cap": self.hard_task_cap,
            "stop_reason": self.exhausted_reason(),
        }


class SharedBudgetAdapter:
    """Expose a wave-shared budget through the TaskBudget interface.

    Screen and planner budgets are shared by concurrent tasks and only offer
    ``consume_model_call``. The agent loop needs the TaskBudget surface, so
    this adapter maps one onto the other without copying or resetting the
    shared counters.
    """

    def __init__(self, shared: Any) -> None:
        self.shared = shared
        self.model_calls = 0
        self.tool_rounds = 0

    @property
    def deadline(self) -> float | None:
        return getattr(self.shared, "deadline", None)

    def remaining_seconds(self) -> float | None:
        method = getattr(self.shared, "remaining_seconds", None)
        if method is None:
            return None
        value = method()
        return None if value is None else max(0.0, float(value))

    def check(self) -> None:
        remaining = self.remaining_seconds()
        if remaining is not None and remaining <= 0:
            raise BudgetStop("time_budget")

    def consume_model_attempt(self) -> None:
        self.check()
        if not self.shared.consume_model_call():
            raise BudgetStop("time_budget" if self.remaining_seconds() == 0 else "step_budget")
        self.model_calls += 1

    def consume_tool_round(self) -> None:
        self.check()
        self.tool_rounds += 1

    def exhausted_reason(self) -> str:
        if self.remaining_seconds() == 0:
            return "time_budget"
        return ""

    def snapshot(self) -> dict[str, Any]:
        return {
            "model_calls": self.model_calls,
            "tool_rounds": self.tool_rounds,
            "remaining_seconds": self.remaining_seconds(),
            "shared": self.shared.snapshot() if hasattr(self.shared, "snapshot") else {},
        }
