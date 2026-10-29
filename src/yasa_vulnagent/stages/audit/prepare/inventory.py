"""Read-only projection of the discover inventory into the audit scope."""

from __future__ import annotations

import sqlite3
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ScopeInventory:
    files: list[str]
    excluded_count: int
    source: str
    gaps: list[str]


def load_scope(ledger_file: Path) -> ScopeInventory:
    """Read the full file list from the already-built discover ledger."""
    ledger_file = Path(ledger_file)
    if not ledger_file.is_file():
        raise ValueError(f"discover inventory is unavailable: {ledger_file}")
    try:
        connection = sqlite3.connect(f"{ledger_file.as_uri()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute("SELECT path FROM files ORDER BY path").fetchall()
            excluded_count = int(
                connection.execute("SELECT COUNT(*) FROM excluded_files").fetchone()[0]
            )
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise ValueError(f"discover inventory is unreadable: {ledger_file}: {exc}") from exc

    files: list[str] = []
    gaps: list[str] = []
    for row in rows:
        path = safe_relative(str(row["path"]))
        if path is None:
            gaps.append("discover inventory contains an unsafe path")
            continue
        files.append(path)
    if not files:
        gaps.append("discover inventory contains no project files")
    return ScopeInventory(
        files=files,
        excluded_count=excluded_count,
        source="discover-ledger",
        gaps=gaps,
    )


def current_revision(repository: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repository,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError):
        return "working-tree"
    return result.stdout.strip() or "working-tree"


def safe_relative(value: str) -> str | None:
    if not value or "\\" in value:
        return None
    try:
        path = Path(value)
    except ValueError:
        return None
    if path == Path(".") or path.is_absolute() or ".." in path.parts:
        return None
    return path.as_posix() if path.as_posix() == value else None
