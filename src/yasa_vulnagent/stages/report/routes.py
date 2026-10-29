"""Deterministic repository submission-route discovery and validation."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

from .schema import ROUTE_KINDS

POLICY_PATHS = (
    "SECURITY.md",
    "SECURITY.txt",
    ".github/SECURITY.md",
    ".github/SECURITY.txt",
    "docs/SECURITY.md",
    "docs/security.md",
    "security/SECURITY.md",
    "security.txt",
    ".well-known/security.txt",
    ".github/ISSUE_TEMPLATE/config.yml",
    "README.md",
    "CONTRIBUTING.md",
    "SUPPORT.md",
)
MAX_SOURCE_CHARS = 12_000
MAX_SOURCES = 20
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_URL = re.compile(r"https?://[^\s)>\]\"']+")
_FORM_HOSTS = (
    "hackerone.com",
    "bugcrowd.com",
    "intigriti.com",
    "yeswehack.com",
    "huntr.com",
    "openbugbounty.org",
)


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", str(text or "")).strip().lower()


def _github_slug(repository: Path) -> dict[str, str]:
    try:
        result = subprocess.run(
            ["git", "-C", str(repository), "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    if result.returncode != 0:
        return {}
    match = re.search(
        r"github\.com[:/]+([^/\s]+)/([^/\s]+?)(?:\.git)?/?$",
        result.stdout.strip(),
    )
    if not match:
        return {}
    owner, repo = match.group(1), match.group(2)
    return {
        "owner": owner,
        "repo": repo,
        "url": f"https://github.com/{owner}/{repo}",
        "advisory_url": f"https://github.com/{owner}/{repo}/security/advisories/new",
    }


def _read_sources(repository: Path) -> list[dict[str, str]]:
    sources: list[dict[str, str]] = []
    seen: set[Path] = set()
    for relative in POLICY_PATHS:
        path = repository / relative
        try:
            resolved = path.resolve()
            resolved.relative_to(repository.resolve())
        except (OSError, ValueError):
            continue
        if resolved in seen or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        seen.add(resolved)
        sources.append({"path": relative, "text": text[:MAX_SOURCE_CHARS]})
        if len(sources) >= MAX_SOURCES:
            break
    return sources


def default_route(github: dict[str, str]) -> dict[str, Any]:
    return {
        "kind": "github_advisory",
        "status": "default",
        "source": "default route",
        "recipient": "",
        "submission_url": github.get("advisory_url", ""),
        "required_fields": [
            "title",
            "summary",
            "description",
            "impact",
            "steps_to_reproduce",
        ],
        "language": "",
        "subject_template": "",
        "length_limit": None,
        "encryption": None,
        "attachment_rules": None,
        "evidence": [],
        "notes": (
            "No repository-specific private reporting route has been confirmed; "
            "this is a GitHub-advisory-shaped local draft, not proof that the "
            "project accepts private reports."
        ),
    }


def _candidates(sources: list[dict[str, str]], github: dict[str, str]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for source in sources:
        path = source["path"]
        text = source["text"]
        for email in _EMAIL.findall(text):
            key = ("email", email.lower())
            if key in seen:
                continue
            seen.add(key)
            candidates.append(
                {
                    "kind": "email",
                    "status": "candidate",
                    "source": path,
                    "recipient": email,
                    "submission_url": "",
                    "notes": "Email address found in repository policy text.",
                }
            )
        for raw in _URL.findall(text):
            url = raw.rstrip(".,;:")
            lowered = url.lower()
            if "github.com" in lowered and "security/advisories" in lowered:
                kind = "github_advisory"
            elif any(host in lowered for host in _FORM_HOSTS):
                kind = "web_form"
            elif "github.com" in lowered and "security" in lowered:
                kind = "security_policy"
            elif "report" in lowered or "vulnerab" in lowered:
                kind = "web_form"
            else:
                continue
            key = (kind, url.lower())
            if key in seen:
                continue
            seen.add(key)
            candidates.append(
                {
                    "kind": kind,
                    "status": "candidate",
                    "source": path,
                    "recipient": "",
                    "submission_url": url,
                    "notes": "Submission URL found in repository policy text.",
                }
            )
    if github.get("advisory_url"):
        key = ("github_advisory", github["advisory_url"].lower())
        if key not in seen:
            candidates.append(
                {
                    "kind": "github_advisory",
                    "status": "candidate",
                    "source": "git remote",
                    "recipient": "",
                    "submission_url": github["advisory_url"],
                    "notes": "Derived from the GitHub remote; enablement is unverified.",
                }
            )
    return candidates


def scan(repository: Path) -> dict[str, Any]:
    repository = Path(repository).resolve()
    sources = _read_sources(repository)
    github = _github_slug(repository)
    candidates = _candidates(sources, github)
    return {
        "repository": str(repository),
        "sources": sources,
        "emails": sorted({item["recipient"] for item in candidates if item["recipient"]}),
        "urls": sorted({item["submission_url"] for item in candidates if item["submission_url"]}),
        "github": github,
        "candidates": candidates,
        "default_route": default_route(github),
    }


def _empty_route(*, language: str) -> dict[str, Any]:
    route = default_route({})
    route["language"] = language
    return route


def normalize_route(
    decision: Any,
    scan_result: dict[str, Any],
    *,
    language: str,
) -> tuple[dict[str, Any], list[str]]:
    """Validate a model route decision against scanned repository evidence."""
    gaps: list[str] = []
    if not isinstance(decision, dict):
        route = _empty_route(language=language)
        route["notes"] = "Route decision was not an object; using the default advisory route."
        return route, ["route decision was not an object"]

    kind = str(decision.get("kind") or "unknown").strip()
    status = str(decision.get("status") or "candidate").strip()
    recipient = str(decision.get("recipient") or "").strip()
    if recipient.lower().startswith("mailto:"):
        recipient = recipient[7:].strip()
    route: dict[str, Any] = {
        "kind": kind if kind in ROUTE_KINDS else "unknown",
        "status": status if status in {"confirmed", "candidate", "default", "unavailable", "unknown"} else "candidate",
        "source": str(decision.get("source") or "").strip(),
        "recipient": recipient,
        "submission_url": str(decision.get("submission_url") or "").strip().rstrip(".,;"),
        "required_fields": [
            str(item).strip()
            for item in decision.get("required_fields", [])
            if str(item).strip()
        ]
        if isinstance(decision.get("required_fields"), list)
        else [],
        "language": str(decision.get("language") or language).strip() or language,
        "subject_template": str(decision.get("subject_template") or "").strip(),
        "length_limit": decision.get("length_limit"),
        "encryption": decision.get("encryption"),
        "attachment_rules": decision.get("attachment_rules"),
        "evidence": [],
        "notes": str(decision.get("notes") or "").strip(),
    }

    sources = {item["path"]: item["text"] for item in scan_result["sources"]}
    valid_evidence: list[dict[str, str]] = []
    for item in decision.get("evidence", []) if isinstance(decision.get("evidence"), list) else []:
        if not isinstance(item, dict):
            continue
        source = str(item.get("source") or "").strip()
        quote = str(item.get("quote") or "").strip()
        if not source or not quote:
            continue
        text = sources.get(source)
        if text is None:
            gaps.append(f"route evidence cites an unscanned source: {source}")
            continue
        if _norm(quote) not in _norm(text):
            gaps.append(f"route evidence quote was not found in {source}")
            continue
        valid_evidence.append({"source": source, "quote": quote})
    route["evidence"] = valid_evidence

    if route["status"] == "confirmed":
        if not valid_evidence:
            route["status"] = "candidate"
            gaps.append("confirmed route has no verifiable policy quote")
        elif kind == "email":
            recipient = route["recipient"].lower()
            if not recipient or recipient not in _norm(" ".join(sources.values())) or not any(
                recipient == email.lower() for email in scan_result["emails"]
            ):
                route["status"] = "candidate"
                gaps.append("confirmed email route does not match a scanned address")
        elif kind in {"github_advisory", "github_form", "web_form"}:
            url = route["submission_url"].lower()
            if not url or not any(
                url == candidate["submission_url"].lower()
                for candidate in scan_result["candidates"]
            ):
                route["status"] = "candidate"
                gaps.append("confirmed route URL does not match a scanned candidate")
            elif kind == "github_advisory":
                combined = _norm(" ".join(sources.values()))
                if not any(word in combined for word in ("advisory", "private", "security report")):
                    route["status"] = "candidate"
                    gaps.append("policy does not clearly enable a private advisory route")
        elif kind in {"security_policy", "unknown"}:
            route["status"] = "candidate"
            gaps.append("route kind is not a submission destination")
    elif route["status"] == "unknown":
        gaps.append("route candidates conflict or remain unresolved")

    if not route["language"]:
        route["language"] = language
    if route["status"] != "confirmed" and route["kind"] == "unknown":
        route["kind"] = "unknown"
    return route, gaps


def selection(route: dict[str, Any], scan_result: dict[str, Any], *, language: str) -> dict[str, Any]:
    """Use the default advisory route when no route can be confirmed."""
    if route.get("status") == "confirmed":
        route["language"] = route.get("language") or language
        return route
    default = dict(scan_result["default_route"])
    default["language"] = language
    if route.get("status") == "unknown":
        default["notes"] = (
            "Route candidates conflict or are unresolved; the default advisory body "
            "was generated locally. Resolve the policy conflict before submitting."
        )
        default["status"] = "unknown"
        return default
    if route.get("status") == "unavailable":
        default["notes"] = (
            "The policy appears to reject private reports; the default advisory body "
            "was generated locally."
        )
    return default
