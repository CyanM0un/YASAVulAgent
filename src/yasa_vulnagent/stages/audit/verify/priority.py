"""Deterministic candidate prioritization for audit verify and optional validate fallback."""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping


_CATEGORY_TIER_SCORE: dict[str, tuple[int, int]] = {
    # (tier_order_asc, score_bonus)
    "injection_interpretation": (1, 30),
    "files_paths_archives_uploads": (1, 30),
    "parsing_deserialization_representation": (1, 30),
    "network_protocol_boundaries": (1, 30),
    "identity_authentication_authorization": (2, 22),
    "state_workflow_business_logic": (2, 22),
    "secrets_sensitive_data": (3, 12),
    "configuration_dependency_supply_chain": (3, 12),
    "resource_exhaustion_availability": (4, 5),
    "open_exploration": (4, 5),
}

_COMPLETENESS_SCORE: dict[str, int] = {
    "complete": 40,
    "sink_only": 10,
    "source_only": 5,
}

_NEGATIVE_OBSERVATION_PATTERNS = (
    re.compile(r"\bno\s+(?:route-level|branch-level|unauthenticated|direct|viable|exploitable)\b.*\b(?:path|bypass|route|way)\b", re.I),
    re.compile(r"\b(?:precondition|condition)\b.*\bis\s+not\s+satisfied\b", re.I),
    re.compile(r"\bno\s+(?:bypass|vulnerability|exploit|injection)\s+(?:was\s+)?found\b", re.I),
    re.compile(r"\bproperly\s+(?:enforced|validated|sanitized|protected|escaped)\b", re.I),
    re.compile(r"\bcannot\s+(?:reach|bypass|trigger|exploit)\b", re.I),
)


def is_negative_observation(finding: Mapping[str, Any]) -> bool:
    """Return True when a candidate title explicitly describes a non-bug / blocked path."""
    title = str(finding.get("title", "") or "").strip()
    if not title:
        return False
    return any(pattern.search(title) for pattern in _NEGATIVE_OBSERVATION_PATTERNS)


def candidate_score(finding: Mapping[str, Any]) -> int:
    """Score one candidate finding deterministically without calling a model."""
    score = 0
    completeness = str(finding.get("completeness", "") or "").strip().lower()
    score += _COMPLETENESS_SCORE.get(completeness, 0)

    if str(finding.get("reachability", "") or "").strip().lower() == "reachable":
        score += 25
    if str(finding.get("triggerability", "") or "").strip().lower() == "triggerable":
        score += 25

    category = str(finding.get("category", "") or "").strip().lower()
    _, category_bonus = _CATEGORY_TIER_SCORE.get(category, (4, 5))
    score += category_bonus

    prerequisites = finding.get("prerequisites")
    prereq_count = len(prerequisites) if isinstance(prerequisites, list) else 0
    score += max(0, 12 - 3 * prereq_count)

    missing_facts = finding.get("missing_facts")
    missing_count = len(missing_facts) if isinstance(missing_facts, list) else 0
    score += max(0, 10 - 2 * missing_count)

    cwe_ids = finding.get("cwe_ids")
    if isinstance(cwe_ids, list) and cwe_ids:
        score += 4

    evidence = finding.get("evidence")
    if isinstance(evidence, list) and len(evidence) >= 2:
        score += 5

    if is_negative_observation(finding):
        score -= 40

    return score


def prioritize_candidates(candidates: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Order candidates by score within each category, then round-robin across categories.

    Round-robin interleaving ordered by category impact tier ensures high-impact
    categories (injection, path traversal, deserialization, SSRF) are verified early
    rather than starved by large volumes of authz candidates.
    """
    items = [item for item in candidates if isinstance(item, dict)]
    if len(items) <= 1:
        return items

    buckets: dict[str, list[dict[str, Any]]] = {}
    for item in items:
        category = str(item.get("category", "") or "uncategorized").strip().lower() or "uncategorized"
        buckets.setdefault(category, []).append(item)

    for bucket in buckets.values():
        bucket.sort(key=lambda item: (-candidate_score(item), str(item.get("id", ""))))

    # Order categories by impact tier first, then highest top-candidate score, then name.
    category_order = sorted(
        buckets.keys(),
        key=lambda cat: (
            _CATEGORY_TIER_SCORE.get(cat, (4, 5))[0],
            -candidate_score(buckets[cat][0]),
            cat,
        ),
    )

    # Separate strong non-negative items from negative observations so negative
    # observations never cut ahead of real candidates via category round-robin.
    positive_buckets: dict[str, list[dict[str, Any]]] = {}
    negative_items: list[dict[str, Any]] = []
    for cat in category_order:
        pos = [item for item in buckets[cat] if not is_negative_observation(item)]
        neg = [item for item in buckets[cat] if is_negative_observation(item)]
        if pos:
            positive_buckets[cat] = pos
        negative_items.extend(neg)

    ordered: list[dict[str, Any]] = []
    active = [cat for cat in category_order if cat in positive_buckets]
    while active:
        next_active: list[str] = []
        for cat in active:
            queue = positive_buckets[cat]
            ordered.append(queue.pop(0))
            if queue:
                next_active.append(cat)
        active = next_active

    negative_items.sort(key=lambda item: (-candidate_score(item), str(item.get("id", ""))))
    ordered.extend(negative_items)
    return ordered


def fallback_eligible_candidates(
    findings: Iterable[dict[str, Any]],
    *,
    limit: int,
) -> list[dict[str, Any]]:
    """Select up to ``limit`` highest-priority unverified candidates for opt-in validate fallback."""
    cap = max(0, int(limit))
    if cap <= 0:
        return []
    qualified = [
        item
        for item in findings
        if isinstance(item, dict)
        and str(item.get("verdict", "")) == "candidate"
        and str(item.get("completeness", "")).strip().lower() == "complete"
        and str(item.get("reachability", "")).strip().lower() == "reachable"
        and str(item.get("triggerability", "")).strip().lower() == "triggerable"
        and not is_negative_observation(item)
    ]
    return prioritize_candidates(qualified)[:cap]
