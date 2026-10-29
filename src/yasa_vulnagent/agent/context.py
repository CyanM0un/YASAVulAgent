from __future__ import annotations

import copy
import json
from typing import Any, Iterable

from .tokens import TokenCounter


class ContextManager:
    """Token-aware compaction that keeps tool exchanges structurally valid."""

    def __init__(
        self,
        counter: TokenCounter,
        *,
        max_tokens: int = 40_000,
        trigger: float = 0.8,
        keep_recent_results: int = 3,
    ) -> None:
        self.counter = counter
        self.max_tokens = max(1, int(max_tokens))
        self.trigger = min(1.0, max(0.1, float(trigger)))
        self.keep_recent_results = max(1, int(keep_recent_results))

    def should_compact(self, messages: list[Any]) -> bool:
        return self.counter.count_messages(messages) > int(self.max_tokens * self.trigger)

    def compact(self, messages: list[Any]) -> list[Any]:
        from langchain_core.messages import HumanMessage, SystemMessage

        if len(messages) <= 2:
            return messages
        head = [messages[0]]
        if isinstance(messages[1], HumanMessage):
            head.append(messages[1])
        carried: list[str] = []
        index = len(head)
        while index < len(messages) and isinstance(messages[index], SystemMessage):
            carried.append(str(messages[index].content))
            index += 1
        exchanges = _tool_exchanges(messages)
        if not exchanges:
            return _keep_recent(messages, self.keep_recent_results * 2 + 2)
        keep = exchanges[-self.keep_recent_results :]
        drop = exchanges[: -self.keep_recent_results]
        receipts = [
            receipt for exchange in drop for receipt in _exchange_receipts(exchange)
        ]
        receipts = list(dict.fromkeys(receipts))[-24:]
        digest: list[str] = []
        for exchange in drop:
            for message in exchange:
                text = _assistant_text(message)
                if text:
                    digest.append(_short(" ".join(text.split()), 300))
        digest = list(dict.fromkeys(digest))[-12:]
        compacted = list(head)
        if receipts or digest:
            lines = [
                *carried,
                f"{len(drop)} earlier tool exchanges were compacted; "
                "full results are in tool-results/.",
            ]
            if digest:
                lines.append("Earlier reasoning:")
                lines.extend(f"- {item}" for item in digest)
            if receipts:
                lines.append("Earlier tool receipts:")
                lines.extend(receipts)
            text = "\n".join(lines)
            compacted.append(SystemMessage(content=text[: self.max_tokens * 2]))
        elif carried:
            compacted.append(SystemMessage(content="\n".join(carried)[: self.max_tokens * 2]))
        for exchange in keep:
            compacted.extend(exchange)
        assert_valid_pairing(compacted)
        return compacted


def compact_json(
    value: Any,
    limit: int,
    *,
    drop_keys: Iterable[str] = (),
) -> str:
    """Serialize ``value`` under ``limit`` characters without breaking JSON.

    Optional subtrees listed in ``drop_keys`` are removed first (dotted keys),
    then the longest string leaves are head/tail trimmed. The result always
    parses as JSON and carries ``_truncated`` when something was removed.
    """
    limit = max(1, int(limit))
    current = copy.deepcopy(value)
    text = _dumps(current)
    truncated = False
    for path in drop_keys:
        if len(text) <= limit:
            break
        if _drop_path(current, path):
            truncated = True
            text = _dumps(current)
    if len(text) > limit:
        current = _shrink_strings(current, limit)
        truncated = True
        text = _dumps(current)
    if not truncated:
        return text
    base = current if isinstance(current, dict) else {"items": current}
    marker = {**base, "_truncated": True}
    text = _dumps(marker)
    if len(text) > limit:
        text = _dumps(_shrink_strings(marker, max(1, limit - 30)))
    return text


def assert_valid_pairing(messages: list[Any]) -> None:
    """Raise when a tool message has no matching assistant tool call (or vice versa)."""
    pending: set[str] = set()
    for message in messages:
        calls = getattr(message, "tool_calls", None) or []
        if calls:
            pending.update(str(call.get("id", "")) for call in calls)
            continue
        if _is_tool_message(message):
            call_id = str(getattr(message, "tool_call_id", ""))
            if call_id not in pending:
                raise AssertionError(f"tool message {call_id!r} has no preceding tool call")
            pending.discard(call_id)
    if pending:
        raise AssertionError(f"tool calls without results: {sorted(pending)}")


def _dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, default=str)


def _drop_path(value: Any, path: str) -> bool:
    parts = [part for part in str(path).split(".") if part]
    if not parts:
        return False
    node = value
    for part in parts[:-1]:
        if not isinstance(node, dict) or part not in node:
            return False
        node = node[part]
    if isinstance(node, dict) and parts[-1] in node:
        del node[parts[-1]]
        return True
    return False


def _string_leaves(value: Any, parent: Any = None, key: Any = None) -> list[tuple[Any, Any, str]]:
    leaves: list[tuple[Any, Any, str]] = []
    if isinstance(value, str):
        if parent is not None:
            leaves.append((parent, key, value))
    elif isinstance(value, dict):
        for child_key, child in value.items():
            leaves.extend(_string_leaves(child, value, child_key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            leaves.extend(_string_leaves(child, value, index))
    return leaves


def _shrink_strings(value: Any, limit: int) -> Any:
    for _ in range(256):
        if len(_dumps(value)) <= limit:
            break
        leaves = _string_leaves(value)
        if not leaves:
            break
        parent, key, text = max(leaves, key=lambda item: len(item[2]))
        if len(text) <= 80:
            break
        keep = max(80, len(text) // 2)
        head = keep // 2
        tail = keep - head
        parent[key] = text[:head] + "\n[...truncated...]\n" + text[-tail:]
    return value


def _tool_exchanges(messages: list[Any]) -> list[list[Any]]:
    exchanges: list[list[Any]] = []
    index = 0
    while index < len(messages):
        message = messages[index]
        calls = getattr(message, "tool_calls", None) or []
        if calls:
            exchange = [message]
            index += 1
            while index < len(messages) and _is_tool_message(messages[index]):
                exchange.append(messages[index])
                index += 1
            exchanges.append(exchange)
            continue
        index += 1
    return exchanges


def _assistant_text(message: Any) -> str:
    if _is_tool_message(message) or _is_human(message):
        return ""
    if message.__class__.__name__ == "SystemMessage":
        return ""
    content = getattr(message, "content", "")
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts = [
            block.get("text", "")
            for block in content
            if isinstance(block, dict) and isinstance(block.get("text"), str)
        ]
        return " ".join(part for part in parts if part).strip()
    return ""


def _is_tool_message(message: Any) -> bool:
    return message.__class__.__name__ == "ToolMessage"


def _is_human(message: Any) -> bool:
    return message.__class__.__name__ == "HumanMessage"


def _exchange_receipts(exchange: list[Any]) -> list[str]:
    lines: list[str] = []
    for message in exchange:
        if not _is_tool_message(message):
            continue
        content = getattr(message, "content", "")
        parsed = _json_object(content)
        if parsed is None:
            lines.append(_short(str(content), 240))
            continue
        fields = []
        for key in ("tool", "path", "source", "range", "start_line", "end_line", "status", "truncated", "next_cursor", "next_line", "artifact_ref"):
            if key in parsed and parsed[key] not in (None, "", []):
                fields.append(f"{key}={parsed[key]}")
        if fields:
            lines.append("; ".join(fields))
        else:
            lines.append(_short(str(content), 240))
    return lines


def _json_object(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, str):
        return value if isinstance(value, dict) else None
    text = value.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if len(lines) >= 3:
            text = "\n".join(lines[1:-1]).strip()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _short(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + "..."


def _keep_recent(messages: list[Any], count: int) -> list[Any]:
    if len(messages) <= count:
        return messages
    head_count = 2 if len(messages) > 1 and _is_human(messages[1]) else 1
    start = max(head_count, len(messages) - count)
    return [*messages[:head_count], *messages[start:]]
