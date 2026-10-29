"""Report-stage artifact paths and small JSON/text helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ReportPaths:
    root: Path
    state_file: Path
    report_file: Path
    routes_file: Path
    index_file: Path
    usage_file: Path
    summary_file: Path
    findings_dir: Path
    submissions_dir: Path


def report_paths(stages_dir: Path) -> ReportPaths:
    root = Path(stages_dir) / "report"
    return ReportPaths(
        root=root,
        state_file=root / "state.json",
        report_file=root / "report.json",
        routes_file=root / "routes.json",
        index_file=root / "index.json",
        usage_file=root / "usage.json",
        summary_file=root / "summary.md",
        findings_dir=root / "findings",
        submissions_dir=root / "submissions",
    )


def finding_dir(paths: ReportPaths, finding_id: str) -> Path:
    from .schema import finding_key

    return paths.findings_dir / finding_key(finding_id)


def ensure_dirs(paths: ReportPaths) -> None:
    paths.root.mkdir(parents=True, exist_ok=True)
    paths.findings_dir.mkdir(parents=True, exist_ok=True)
    paths.submissions_dir.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, value: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def read_json(path: Path) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def write_text(path: Path, value: str) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value.rstrip() + "\n", encoding="utf-8")
