from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path
from typing import Any


LARGE_TEXT_BYTES = 1024 * 1024

_EXCLUDED_PARTS = {
    ".codegraph",
    ".git",
    ".gradle",
    ".idea",
    ".mypy_cache",
    ".next",
    ".pytest_cache",
    ".tox",
    ".venv",
    ".vulnagent",
    ".yasa",
    ".yasa-vulnagent",
    "__pycache__",
    "coverage",
    "dist",
    "generated",
    "node_modules",
    "target",
    "third_party",
    "vendor",
}
_REFERENCE_PARTS = {
    "demo",
    "demos",
    "example",
    "examples",
    "fixture",
    "fixtures",
    "sample",
    "samples",
    "test",
    "tests",
}
_DOCUMENT_SUFFIXES = {".adoc", ".md", ".markdown", ".rst", ".txt"}
_CONFIG_SUFFIXES = {
    ".conf",
    ".config",
    ".env",
    ".ini",
    ".json",
    ".properties",
    ".toml",
    ".xml",
    ".yaml",
    ".yml",
}
_SCRIPT_NAMES = {
    "dockerfile",
    "makefile",
    "procfile",
    "requirements.txt",
    "setup.cfg",
    "setup.py",
}


class InventoryError(RuntimeError):
    """Raised when a detected Git repository cannot be enumerated safely."""


def build_inventory(
    repository: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str], str]:
    """Enumerate candidate files and return files, exclusions, gaps and source."""
    git_entries = _git_entries(repository)
    if git_entries is None:
        entries, enumeration_gaps = _filesystem_entries(repository)
        source = "filesystem"
    else:
        entries = git_entries
        enumeration_gaps = []
        source = "git"

    files: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    gaps: list[str] = list(enumeration_gaps)
    seen: set[str] = set()
    for path, origin in entries:
        try:
            relative = path.relative_to(repository).as_posix()
        except ValueError:
            gaps.append(f"inventory path is outside repository: {path}")
            continue
        if relative in seen:
            continue
        seen.add(relative)
        if path.is_symlink():
            excluded.append({"path": relative, "reason": "symlink-path"})
            continue
        reason = _exclusion_reason(path, repository)
        if reason:
            excluded.append({"path": relative, "reason": reason})
            continue
        record, error = _file_record(path, relative, origin)
        if error:
            gaps.append(f"unable to inspect {relative}: {error}")
        files.append(record)
    files.sort(key=lambda item: str(item.get("path", "")))
    excluded.sort(key=lambda item: str(item.get("path", "")))
    return files, excluded, _unique(gaps), source


def _git_entries(repository: Path) -> list[tuple[Path, str]] | None:
    try:
        root_result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=repository,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    git_root = Path(root_result.stdout.decode().strip()).resolve()
    selected_root = repository.resolve()

    tracked = _git_paths(
        repository,
        ["git", "ls-files", "--cached", "-z"],
        git_root,
    )
    untracked = _git_paths(
        repository,
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        git_root,
    )
    entries: dict[str, tuple[Path, str]] = {}
    for path in tracked:
        if _under(path, selected_root):
            entries[path.relative_to(selected_root).as_posix()] = (path, "git-tracked")
    for path in untracked:
        if _under(path, selected_root):
            entries.setdefault(
                path.relative_to(selected_root).as_posix(),
                (path, "git-untracked"),
            )
    return [entries[key] for key in sorted(entries)]


def _git_paths(repository: Path, command: list[str], git_root: Path) -> list[Path]:
    try:
        completed = subprocess.run(
            command,
            cwd=repository,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise InventoryError(f"Git inventory failed: {' '.join(command)}") from exc
    return [git_root / item.decode("utf-8", "surrogateescape") for item in completed.stdout.split(b"\0") if item]


def _filesystem_entries(repository: Path) -> tuple[list[tuple[Path, str]], list[str]]:
    entries: list[tuple[Path, str]] = []
    gaps: list[str] = []

    def onerror(error: OSError) -> None:
        location = error.filename or str(repository)
        gaps.append(f"unable to enumerate {location}: {error}")

    for root, directories, filenames in os.walk(
        repository,
        followlinks=False,
        onerror=onerror,
    ):
        root_path = Path(root)
        kept_directories: list[str] = []
        for name in sorted(directories):
            child = root_path / name
            relative = child.relative_to(repository).as_posix()
            if child.is_symlink():
                entries.append((child, "filesystem"))
                continue
            if _exclusion_reason(child, repository, directory=True):
                entries.append((child, "filesystem"))
                continue
            kept_directories.append(name)
        directories[:] = kept_directories
        for name in sorted(filenames):
            entries.append((root_path / name, "filesystem"))
    return entries, gaps


def _file_record(path: Path, relative: str, origin: str) -> tuple[dict[str, Any], str | None]:
    base: dict[str, Any] = {
        "path": relative,
        "size": 0,
        "fingerprint": "",
        "content_type": "unknown",
        "kind": "unknown",
        "usage_hint": "production-candidate",
        "source_origin": origin,
        "large": False,
        "status": "pending",
        "task_ids": [],
        "entry_ids": [],
    }
    try:
        size = path.stat().st_size
        with path.open("rb") as source:
            probe = source.read(8192)
    except OSError as exc:
        base.update({"status": "unavailable", "error": str(exc)})
        return base, str(exc)

    content_type = _content_type(probe)
    base["size"] = size
    base["content_type"] = content_type
    base["large"] = size > LARGE_TEXT_BYTES
    base["kind"], base["usage_hint"] = _usage(path, relative, content_type)
    if content_type == "binary":
        base["status"] = "metadata"
        base["usage_hint"] = "binary-metadata"
        return base, None
    try:
        base["fingerprint"] = _hash_file(path)
    except OSError as exc:
        base.update({"status": "unavailable", "error": str(exc)})
        return base, str(exc)
    return base, None


def _content_type(probe: bytes) -> str:
    if b"\0" in probe:
        return "binary"
    try:
        probe.decode("utf-8")
    except UnicodeDecodeError:
        return "binary"
    return "text"


def _usage(path: Path, relative: str, content_type: str) -> tuple[str, str]:
    if content_type == "binary":
        return "binary", "binary-metadata"
    parts = {part.lower() for part in Path(relative).parts[:-1]}
    name = path.name.lower()
    suffix = path.suffix.lower()
    if parts & _REFERENCE_PARTS:
        return "reference", "reference-material"
    if suffix in _DOCUMENT_SUFFIXES or name.startswith("readme"):
        return "documentation", "reference-material"
    if suffix in _CONFIG_SUFFIXES or name in {".env", ".env.example"}:
        return "configuration", "production-candidate"
    if name in _SCRIPT_NAMES or not suffix:
        return "source", "production-candidate"
    return "source", "production-candidate"


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _exclusion_reason(path: Path, repository: Path, *, directory: bool = False) -> str | None:
    try:
        relative_parts = path.relative_to(repository).parts
    except ValueError:
        return "outside-repository"
    parts = {part.lower() for part in relative_parts if part != path.name or directory}
    if parts & _EXCLUDED_PARTS:
        return "generated-dependency-or-runtime-path"
    if path.name == ".git" or path.name.lower() in _EXCLUDED_PARTS:
        return "generated-dependency-or-runtime-path"
    return None


def _under(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))
