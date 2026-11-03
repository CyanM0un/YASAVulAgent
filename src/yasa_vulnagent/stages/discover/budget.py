from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ...workflow.state import RunContext


def exceeded_reason(state: dict[str, Any], context: RunContext | None) -> str:
    """Return why discover must stop spending, or "" when a budget remains."""
    settings = context.settings if context is not None else None
    if settings is None:
        return ""
    deadline = str(state.get("discover_deadline") or "")
    if int(getattr(settings, "discover_timeout", 0)) > 0 and deadline:
        try:
            expired = datetime.fromisoformat(deadline) <= datetime.now(timezone.utc)
        except (TypeError, ValueError):
            expired = False
        if expired:
            return (
                f"discover time budget exhausted: DISCOVER_TIMEOUT={settings.discover_timeout}s "
                "elapsed; finalizing with the work already recorded"
            )
    limit = int(getattr(settings, "discover_max_total_tokens", 0))
    if limit > 0 and context is not None and context.usage is not None:
        totals = context.usage.snapshot().get("totals", {})
        used = int(totals.get("total_tokens", 0))
        if used >= limit:
            return (
                f"discover token budget exhausted: {used} >= "
                f"DISCOVER_MAX_TOTAL_TOKENS={limit}; finalizing with the work already recorded"
            )
    return ""
