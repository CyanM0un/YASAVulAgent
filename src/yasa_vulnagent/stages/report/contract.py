"""Deterministic report contracts: body, CVSS, routing, and review gates."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from . import cvss
from .schema import REVIEW_CHECKS, SEVERITIES

SECTION_NAMES = ("Title", "Summary", "Details", "Proof of concept", "Impact")
MIN_BODY_CHARS = 800
MAX_BODY_CHARS = 30_000

_PLACEHOLDER = re.compile(
    r"(?i)(?:\b(?:TODO|TBD|FIXME|XXX)\b|\{\{|\}\}|"
    r"\[(?:product|component|what is|specific|required|operating|expected|"
    r"remediation|commands|first|the decisive|cwe name|deployments|only the|"
    r"legitimate|insert|describe))"
)
_INTERNAL = re.compile(
    r"(?i)(?:\.yasa-vulnagent|\.vulagent|opencode|run[-_]context|"
    r"stages/(?:validate|audit|discover|report)|validation\.json|audit\.json|"
    r"run_id|finding_id|tool-results|agent\.json|notes\.jsonl)"
)
_ABSOLUTE_PATH = re.compile(
    r"(?<![\w.])/(?:home|Users|media|mnt|tmp|private|var/folders|workspace)/"
    r"|[A-Za-z]:\\Users\\"
)
_SECRET = re.compile(
    r"(?i)(?:"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\bgh[pousr]_[A-Za-z0-9]{20,}\b|"
    r"\bgithub_pat_[A-Za-z0-9_]{20,}\b|"
    r"\bsk-[A-Za-z0-9]{20,}\b|"
    r"\bAKIA[0-9A-Z]{16}\b|"
    r"(?:api[_-]?key|token|secret|password|authorization|cookie)\s*[=:]\s*\S+"
    r")"
)
_SECRET_VALUE = re.compile(
    r"(?i)((?:api[_-]?key|token|secret|password|authorization|cookie)\s*[=:]\s*)"
    r"([^\s\"']+)"
)
def _headings(body: str) -> list[tuple[str, int, int]]:
    """Return top-level headings outside fenced code blocks."""
    result: list[tuple[str, int, int]] = []
    offset = 0
    fenced = False
    for line in str(body or "").splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith(("```", "~~~")):
            fenced = not fenced
        elif not fenced:
            match = re.match(r"^#\s+(.+?)\s*$", line.rstrip("\r\n"))
            if match:
                result.append((match.group(1).strip(), offset, offset + len(line)))
        offset += len(line)
    return result


def redact(text: str) -> str:
    value = str(text or "")
    value = re.sub(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        "[REDACTED PRIVATE KEY]",
        value,
        flags=re.DOTALL,
    )
    value = re.sub(
        r"(?i)(authorization\s*:\s*)(?:bearer\s+)?[^\s\"']+",
        r"\1[REDACTED]",
        value,
    )
    value = _SECRET_VALUE.sub(r"\1[REDACTED]", value)
    for pattern in (
        r"\bgh[pousr]_[A-Za-z0-9]{20,}\b",
        r"\bgithub_pat_[A-Za-z0-9_]{20,}\b",
        r"\bsk-[A-Za-z0-9]{20,}\b",
        r"\bAKIA[0-9A-Z]{16}\b",
    ):
        value = re.sub(pattern, "[REDACTED]", value)
    return value


def body_sha256(body: str) -> str:
    return hashlib.sha256(str(body or "").encode("utf-8")).hexdigest()


def _sections(body: str) -> dict[str, str]:
    matches = _headings(body)
    result: dict[str, str] = {}
    for index, (name, _start, end) in enumerate(matches):
        next_start = matches[index + 1][1] if index + 1 < len(matches) else len(body)
        result[name.lower()] = body[end:next_start].strip()
    return result


def section(body: str, name: str) -> str:
    return _sections(body).get(name.lower(), "")


def body_errors(body: str) -> list[str]:
    value = str(body or "").strip()
    errors: list[str] = []
    if not value:
        return ["body is empty"]
    if len(value) < MIN_BODY_CHARS:
        errors.append(f"body is shorter than {MIN_BODY_CHARS} characters")
    if len(value) > MAX_BODY_CHARS:
        errors.append(f"body is longer than {MAX_BODY_CHARS} characters")

    headings = [name for name, _start, _end in _headings(value)]
    expected = list(SECTION_NAMES)
    if headings != expected:
        errors.append(
            "body must contain exactly these top-level sections in order: "
            + ", ".join(f"# {name}" for name in expected)
        )
    sections = _sections(value)
    for name in SECTION_NAMES:
        if not sections.get(name.lower()):
            errors.append(f"section # {name} is empty")

    lowered = value.lower()
    required = {
        "affected component": "affected component",
        "root cause": "root cause",
        "precondition": "attack preconditions",
        "expected": "expected behavior",
        "observed": "observed behavior",
        "remediation": "remediation",
        "impact": "impact",
    }
    for marker, label in required.items():
        if marker not in lowered:
            errors.append(f"body must include {label}")
    if "tested" not in lowered or not any(
        word in lowered for word in ("revision", "commit", "version")
    ):
        errors.append("body must identify the tested revision")
    if not re.search(r"CWE-\d+", value, flags=re.IGNORECASE):
        errors.append("body must include at least one CWE identifier")
    if "cvss:3.1/" not in lowered and "cvss:4.0/" not in lowered:
        errors.append("body must include a CVSS vector")

    if _PLACEHOLDER.search(value):
        errors.append("body still contains a placeholder or template marker")
    if _INTERNAL.search(value):
        errors.append("body contains internal workflow text")
    if _ABSOLUTE_PATH.search(value):
        errors.append("body contains a machine-specific absolute path")
    secret_scan = re.sub(r"\[REDACTED(?: [A-Z ]+)?\]", "", value)
    if _SECRET.search(secret_scan):
        errors.append("body contains a credential-like value")
    return errors


def derive_fields(body: str) -> dict[str, str]:
    return {
        "title": section(body, "Title").splitlines()[0].strip()
        if section(body, "Title")
        else "",
        "summary": section(body, "Summary"),
        "description": str(body or "").strip(),
        "impact": section(body, "Impact"),
        "steps_to_reproduce": section(body, "Proof of concept"),
    }


def review_errors(review: Any) -> list[str]:
    if not isinstance(review, dict):
        return ["review must be an object"]
    errors: list[str] = []
    if review.get("status") != "approved":
        errors.append("review status must be approved")
    if review.get("independent") is not True:
        errors.append("review must be independent")
    if not str(review.get("conclusion") or "").strip():
        errors.append("review must include a conclusion")
    checks = review.get("checks")
    if not isinstance(checks, dict):
        errors.append("review checks must be an object")
    else:
        for name in REVIEW_CHECKS:
            if checks.get(name) is not True:
                errors.append(f"review check {name} did not pass")
    if review.get("issues"):
        errors.append("approved review must not carry blocking issues")
    return errors


def cvss_value(value: Any) -> tuple[dict[str, Any] | None, list[str]]:
    errors: list[str] = []
    if not isinstance(value, dict):
        return None, ["cvss must be an object"]
    version = str(value.get("version") or "")
    vector = str(value.get("vector") or "").strip()
    justification = str(value.get("justification") or "").strip()
    if version not in {"3.1", "4.0"}:
        errors.append("cvss.version must be 3.1 or 4.0")
    if not vector:
        errors.append("cvss.vector is required")
    if not justification:
        errors.append("cvss.justification is required")
    if errors:
        return None, errors
    score = cvss.base_score(version, vector)
    if score is None:
        errors.append(f"cvss.vector could not be recalculated for CVSS {version}")
        return None, errors
    severity = cvss.severity(score)
    if severity not in SEVERITIES:
        errors.append("cvss severity is not supported")
    return {
        "version": version,
        "vector": vector,
        "base_score": score,
        "severity": severity,
        "justification": justification,
    }, errors


def cwe_errors(audit_cwe: list[str], selected: Any) -> list[str]:
    if not isinstance(selected, list) or not selected:
        return ["at least one CWE is required"]
    values = [str(item).strip().upper() for item in selected]
    if any(not re.fullmatch(r"CWE-\d+", item) for item in values):
        return ["CWE values must use the CWE-<number> form"]
    allowed = {str(item).upper() for item in audit_cwe}
    unknown = [item for item in values if item not in allowed]
    if unknown:
        return ["CWE values are not supported by the audit finding: " + ", ".join(unknown)]
    return []


def body_score_errors(body: str, value: dict[str, Any]) -> list[str]:
    text = str(body or "")
    errors: list[str] = []
    score = cvss.score_text(float(value["base_score"]))
    if str(value["vector"]).lower() not in text.lower():
        errors.append("body must include the reported CVSS vector")
    if score not in text:
        errors.append(f"body must include the recalculated CVSS base score {score}")
    if str(value["severity"]).lower() not in text.lower():
        errors.append(f"body must include the recalculated severity {value['severity']}")
    return errors
