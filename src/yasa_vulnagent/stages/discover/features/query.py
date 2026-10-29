from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

from ..ledger import DiscoverLedger


QUERY_KINDS = {"annotation_usage", "text", "symbol_reference", "function_call"}
MAX_REGEX_CHARS = 512
MAX_FILE_CHARS = 2_000_000


class FeatureQueryError(ValueError):
    """A feature query specification cannot be executed safely."""


def _relative(path: str) -> str:
    return str(path).removeprefix("./")


def _pattern(
    kind: str, target: str, regex: bool, max_regex_chars: int = MAX_REGEX_CHARS
) -> re.Pattern[str]:
    if not target.strip():
        raise FeatureQueryError("feature query target is empty")
    if regex:
        if len(target) > max(1, int(max_regex_chars)):
            raise FeatureQueryError("feature query regex is too long")
        try:
            return re.compile(target)
        except re.error as exc:
            raise FeatureQueryError(f"invalid feature query regex: {exc}") from exc
    literal = re.escape(target)
    if kind in {"symbol_reference", "function_call"}:
        literal = rf"(?<![\w$]){literal}(?![\w$])"
    if kind == "function_call":
        literal = rf"{literal}\s*\("
    return re.compile(literal)


def validate_query_pattern(
    kind: str,
    target: str,
    regex: bool,
    max_regex_chars: int = MAX_REGEX_CHARS,
) -> None:
    _pattern(kind, target, regex, max_regex_chars)


def execute_query(
    repository: Path,
    ledger: DiscoverLedger,
    spec: dict[str, Any],
    *,
    default_max_results: int = 200,
    timeout_seconds: int = 30,
    max_regex_chars: int = MAX_REGEX_CHARS,
) -> dict[str, Any]:
    kind = str(spec.get("kind", "text"))
    if kind not in QUERY_KINDS:
        raise FeatureQueryError(f"unsupported feature query kind: {kind}")
    target = str(spec.get("target", ""))
    regex = bool(spec.get("regex", False))
    pattern = _pattern(kind, target, regex, max_regex_chars)
    scope = {
        _relative(str(item))
        for item in spec.get("scope", [])
        if str(item).strip()
    }
    try:
        max_results = max(1, min(int(spec.get("max_results", default_max_results)), 1000))
    except (TypeError, ValueError):
        max_results = default_max_results
    cursor = max(0, int(spec.get("cursor", 0)))
    deadline = time.monotonic() + max(1, int(timeout_seconds))
    eligible = [
        str(file.get("path", ""))
        for file in ledger.iter_files(limit=1000)
        if file.get("usage_hint") == "production-candidate"
        and file.get("content_type") == "text"
        and file.get("status") != "unavailable"
        and (not scope or str(file.get("path", "")) in scope)
    ]
    results: list[dict[str, Any]] = []
    limitations: list[str] = []
    errors: list[str] = []
    index = 0
    truncated = False
    for path in eligible:
        if time.monotonic() >= deadline:
            limitations.append("feature query deadline reached")
            truncated = True
            break
        file_path = repository / path
        try:
            if file_path.stat().st_size > MAX_FILE_CHARS:
                limitations.append(f"file too large for feature query: {path}")
                continue
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            errors.append(f"{path}: {exc}")
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            for match in pattern.finditer(line):
                if index < cursor:
                    index += 1
                    continue
                if len(results) >= max_results:
                    truncated = True
                    break
                index += 1
                results.append(
                    {
                        "path": path,
                        "line_start": line_number,
                        "line_end": line_number,
                        "text": line.strip()[:4000],
                        "match_start": match.start(),
                        "match_end": match.end(),
                    }
                )
            if truncated:
                break
        if truncated:
            break
    next_cursor = cursor + len(results)
    if not truncated and not limitations and not errors:
        complete = True
    else:
        complete = False
    return {
        "kind": kind,
        "target": target,
        "regex": regex,
        "scope": sorted(scope),
        "cursor": cursor,
        "next_cursor": next_cursor,
        "returned": len(results),
        "results": results,
        "truncated": truncated,
        "complete": complete,
        "limitations": limitations,
        "errors": errors,
    }
