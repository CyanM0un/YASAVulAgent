from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from .ledger import DiscoverLedger


_REF_RE = re.compile(
    r"^(?:(?P<prefix>source|review|read):)?"
    r"(?P<path>.+?):(?P<start>\d+)-(?P<end>\d+)$"
)


def _relative(path: str) -> str:
    return str(path).removeprefix("./")


def line_count(path: Path) -> int:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return sum(1 for _line in handle)
    except OSError:
        return 0


def validate_location(
    repository: Path,
    ledger: DiscoverLedger,
    *,
    path: str,
    start: int,
    end: int,
    fingerprint: str = "",
) -> dict[str, Any]:
    relative = _relative(path)
    if not relative or relative.startswith("/") or ".." in Path(relative).parts:
        return {"ok": False, "error": "evidence path is not repository-relative"}
    row = ledger.get_file(relative)
    if row is None:
        return {"ok": False, "error": f"evidence path is not in inventory: {relative}"}
    if row.get("content_type") != "text" or row.get("usage_hint") != "production-candidate":
        return {"ok": False, "error": f"evidence path is not production text: {relative}"}
    if int(start) < 1 or int(end) < int(start):
        return {"ok": False, "error": "evidence line range is invalid"}
    total = line_count(repository / relative)
    if total and int(end) > total:
        return {"ok": False, "error": f"evidence line range exceeds {relative}:{total}"}
    current = str(row.get("fingerprint", ""))
    if fingerprint and current and str(fingerprint) != current:
        return {"ok": False, "error": f"evidence fingerprint changed: {relative}"}
    return {
        "ok": True,
        "path": relative,
        "line_start": int(start),
        "line_end": int(end),
        "fingerprint": current,
    }


def validate_refs(
    repository: Path,
    ledger: DiscoverLedger,
    refs: list[Any],
    *,
    allow_entries: bool = True,
) -> tuple[list[str], list[str]]:
    """Return canonical refs and readable errors for review/confirm evidence."""
    canonical: list[str] = []
    errors: list[str] = []
    for value in refs:
        ref = str(value).strip()
        if not ref:
            continue
        if ref.startswith("entry:"):
            entry_id = ref.split(":", 1)[1]
            if allow_entries and ledger.get_entry(entry_id):
                canonical.append(ref)
            else:
                errors.append(f"unknown entry evidence: {ref}")
            continue
        if ref.startswith("evidence:"):
            evidence_id = ref.split(":", 1)[1]
            evidence = ledger.get_evidence(evidence_id)
            if evidence is None:
                errors.append(f"unknown evidence id: {ref}")
                continue
            result = validate_location(
                repository,
                ledger,
                path=str(evidence.get("source_file", "")),
                start=int(evidence.get("line_start", 0) or 0),
                end=int(evidence.get("line_end", 0) or 0),
                fingerprint=str(evidence.get("source_fingerprint", "")),
            )
            if result.get("ok"):
                canonical.append(ref)
            else:
                errors.append(str(result.get("error", f"invalid evidence: {ref}")))
            continue
        match = _REF_RE.match(ref)
        if not match:
            errors.append(f"evidence ref is not verifiable: {ref}")
            continue
        result = validate_location(
            repository,
            ledger,
            path=match.group("path"),
            start=int(match.group("start")),
            end=int(match.group("end")),
        )
        if result.get("ok"):
            canonical.append(ref)
        else:
            errors.append(str(result.get("error", f"invalid evidence: {ref}")))
    return canonical, errors


def make_evidence(
    *,
    kind: str,
    path: str,
    start: int,
    end: int,
    fingerprint: str,
    excerpt: str = "",
    summary: str = "",
) -> dict[str, Any]:
    evidence_id = "evidence-" + hashlib.sha256(
        f"{kind}:{path}:{start}:{end}:{fingerprint}".encode()
    ).hexdigest()[:16]
    return {
        "evidence_id": evidence_id,
        "kind": kind,
        "source_file": _relative(path),
        "source_fingerprint": fingerprint,
        "line_start": int(start),
        "line_end": int(end),
        "excerpt": excerpt[:4000],
        "summary": summary[:4000],
    }


def location_ref(path: str, start: int, end: int) -> str:
    return f"source:{_relative(path)}:{int(start)}-{int(end)}"
