from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any


class UsageRecorder:
    """Thread-safe token usage accounting for one run.

    Limits are soft: a call is recorded after it completes, so one final call may
    overshoot a limit.  ``exceeded`` is checked before the next model call.
    """

    def __init__(
        self,
        price_table: Path | None = None,
        *,
        max_tokens: int = 0,
        max_cost: float = 0.0,
    ) -> None:
        self._lock = threading.Lock()
        self._records: list[dict[str, Any]] = []
        self._prices = _load_prices(price_table)
        self._max_tokens = max(0, int(max_tokens))
        self._max_cost = max(0.0, float(max_cost))
        self._totals: dict[str, float | int] = {
            "calls": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "estimated_prompt_tokens": 0,
            "attempts": 0,
            "retries": 0,
            "compactions": 0,
            "tool_calls": 0,
            "cost": 0.0,
        }

    def configure_limits(
        self,
        *,
        max_tokens: int | None = None,
        max_cost: float | None = None,
    ) -> None:
        if max_tokens is not None:
            if int(max_tokens) < 0:
                raise ValueError("max_tokens must be non-negative")
            self._max_tokens = int(max_tokens)
        if max_cost is not None:
            if float(max_cost) < 0:
                raise ValueError("max_cost must be non-negative")
            self._max_cost = float(max_cost)

    def exceeded(self) -> str:
        """Return the first exhausted soft limit, or an empty string."""
        with self._lock:
            return self._exceeded_locked()

    def record(
        self,
        *,
        stage: str,
        task_id: str,
        model: str,
        usage: Any,
        estimated_prompt_tokens: int = 0,
        attempts: int = 1,
        retries: int = 0,
        compactions: int = 0,
        tool_calls: int = 0,
        source: str = "provider",
    ) -> None:
        prompt, completion, total = _usage_values(usage)
        estimated = int(estimated_prompt_tokens)
        if total <= 0 and estimated > 0:
            prompt = estimated
            total = estimated
            if source == "provider":
                source = "estimated"
        record = {
            "stage": stage,
            "task_id": task_id,
            "model": model,
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "total_tokens": total,
            "estimated_prompt_tokens": estimated,
            "attempts": int(attempts),
            "retries": int(retries),
            "compactions": int(compactions),
            "tool_calls": int(tool_calls),
            "usage_source": source,
        }
        record["cost"] = self._cost(record)
        with self._lock:
            self._records.append(record)
            for key in (
                "calls",
                "prompt_tokens",
                "completion_tokens",
                "total_tokens",
                "estimated_prompt_tokens",
                "attempts",
                "retries",
                "compactions",
                "tool_calls",
            ):
                self._totals[key] += 1 if key == "calls" else int(record[key])
            self._totals["cost"] = float(self._totals["cost"]) + float(record["cost"] or 0.0)

    def add_retry(self, count: int = 1) -> None:
        """Retries are recorded with their successful call; nothing global to mutate."""

    def snapshot(self, stage: str | None = None) -> dict[str, Any]:
        with self._lock:
            records = [dict(item) for item in self._records if stage is None or item["stage"] == stage]
        return _summarize(records, limits=self._limits(), exceeded=self.exceeded())

    def write(self, path: Path, stage_prefix: str | None = None) -> None:
        with self._lock:
            records = [
                dict(item)
                for item in self._records
                if stage_prefix is None or str(item["stage"]).startswith(stage_prefix)
            ]
        payload = _summarize(
            records,
            limits=self._limits(),
            exceeded=self.exceeded(),
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        temporary.replace(path)

    def _limits(self) -> dict[str, Any]:
        return {
            "max_total_tokens": self._max_tokens,
            "max_total_cost": self._max_cost,
            "cost_enforced": bool(self._prices),
        }

    def _exceeded_locked(self) -> str:
        if self._max_tokens > 0 and self._totals["total_tokens"] >= self._max_tokens:
            return "token_budget"
        if self._max_cost > 0 and self._prices and self._totals["cost"] >= self._max_cost:
            return "cost_budget"
        return ""

    def _cost(self, record: dict[str, Any]) -> float | None:
        if not self._prices:
            return None
        price = self._prices.get(record["model"])
        if not price:
            return None
        return round(
            record["prompt_tokens"] / 1_000_000 * float(price.get("input_per_million", 0.0))
            + record["completion_tokens"] / 1_000_000 * float(price.get("output_per_million", 0.0)),
            8,
        )


def _summarize(
    records: list[dict[str, Any]],
    *,
    limits: dict[str, Any] | None = None,
    exceeded: str = "",
) -> dict[str, Any]:
    totals = {
        "calls": len(records),
        "prompt_tokens": sum(item["prompt_tokens"] for item in records),
        "completion_tokens": sum(item["completion_tokens"] for item in records),
        "total_tokens": sum(item["total_tokens"] for item in records),
        "estimated_prompt_tokens": sum(item["estimated_prompt_tokens"] for item in records),
        "attempts": sum(item["attempts"] for item in records),
        "retries": sum(item["retries"] for item in records),
        "compactions": sum(item["compactions"] for item in records),
        "tool_calls": sum(item["tool_calls"] for item in records),
        "cost": sum(item["cost"] or 0.0 for item in records),
    }
    by_stage: dict[str, dict[str, int]] = {}
    by_task: dict[str, dict[str, int]] = {}
    for item in records:
        for bucket, key in ((by_stage, item["stage"]), (by_task, item["task_id"])):
            target = bucket.setdefault(
                key,
                {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "calls": 0},
            )
            target["prompt_tokens"] += item["prompt_tokens"]
            target["completion_tokens"] += item["completion_tokens"]
            target["total_tokens"] += item["total_tokens"]
            target["calls"] += 1
    return {
        "totals": totals,
        "limits": dict(limits or {}),
        "exceeded": exceeded,
        "by_stage": by_stage,
        "by_task": by_task,
        "records": records,
    }


def _usage_values(usage: Any) -> tuple[int, int, int]:
    if usage is None:
        return 0, 0, 0
    if isinstance(usage, dict):
        prompt = int(usage.get("input_tokens", usage.get("prompt_tokens", 0)) or 0)
        completion = int(usage.get("output_tokens", usage.get("completion_tokens", 0)) or 0)
        total = int(usage.get("total_tokens", prompt + completion) or 0)
        return prompt, completion, total
    prompt = int(getattr(usage, "input_tokens", 0) or 0)
    completion = int(getattr(usage, "output_tokens", 0) or 0)
    total = int(getattr(usage, "total_tokens", prompt + completion) or 0)
    return prompt, completion, total


def _load_prices(path: Path | None) -> dict[str, dict[str, Any]]:
    if path is None or not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    values: dict[str, dict[str, Any]] = {}
    items = payload if isinstance(payload, list) else [payload]
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("model"), str):
            values[item["model"]] = item
    return values
