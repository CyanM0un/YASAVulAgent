"""CVSS base-score calculation and severity mapping."""

from __future__ import annotations

import math


def _round_up_one_decimal(value: float) -> float:
    return math.ceil((value - 1e-10) * 10.0) / 10.0


def _score31(vector: str) -> float | None:
    if not vector.startswith("CVSS:3.1/"):
        return None
    metrics: dict[str, str] = {}
    for token in vector.split("/")[1:]:
        if ":" not in token:
            return None
        key, value = token.split(":", 1)
        metrics[key] = value
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if set(metrics) != required:
        return None
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(metrics["AV"])
    ac = {"L": 0.77, "H": 0.44}.get(metrics["AC"])
    ui = {"N": 0.85, "R": 0.62}.get(metrics["UI"])
    impact_metric = {"N": 0.0, "L": 0.22, "H": 0.56}
    c = impact_metric.get(metrics["C"])
    i = impact_metric.get(metrics["I"])
    a = impact_metric.get(metrics["A"])
    if (
        av is None
        or ac is None
        or ui is None
        or c is None
        or i is None
        or a is None
        or metrics["S"] not in {"U", "C"}
    ):
        return None
    pr = (
        {"N": 0.85, "L": 0.62, "H": 0.27}
        if metrics["S"] == "U"
        else {"N": 0.85, "L": 0.68, "H": 0.50}
    ).get(metrics["PR"])
    if pr is None:
        return None
    isc = 1 - (1 - c) * (1 - i) * (1 - a)
    if metrics["S"] == "U":
        impact = 6.42 * isc
    else:
        impact = 7.52 * (isc - 0.029) - 3.25 * ((isc - 0.02) ** 15)
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    total = impact + exploitability
    if metrics["S"] == "C":
        total *= 1.08
    return _round_up_one_decimal(min(total, 10.0))


def _score40(vector: str) -> float | None:
    if not vector.startswith("CVSS:4.0/"):
        return None
    try:
        from cvss import CVSS4  # type: ignore
    except ImportError:
        return None
    try:
        return float(CVSS4(vector).base_score)
    except Exception:
        return None


def base_score(version: str, vector: str) -> float | None:
    if version == "3.1":
        return _score31(vector)
    if version == "4.0":
        return _score40(vector)
    return None


def severity(score: float) -> str:
    if score == 0:
        return "none"
    if score < 4:
        return "low"
    if score < 7:
        return "medium"
    if score < 9:
        return "high"
    return "critical"


def score_text(score: float) -> str:
    return f"{score:.1f}"
