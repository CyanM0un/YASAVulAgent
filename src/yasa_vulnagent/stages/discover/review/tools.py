from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from langchain_core.tools import StructuredTool


class ReviewToolbox:
    """Bounded source access for debt review; reads never become coverage receipts."""

    def __init__(
        self,
        repository: Path,
        allowed_paths: Iterable[str],
        *,
        max_file_bytes: int = 2_097_152,
    ) -> None:
        self.repository = repository.expanduser().resolve()
        self.allowed_paths = {
            Path(path).as_posix().removeprefix("./") for path in allowed_paths if path
        }
        self.max_file_bytes = max(1, int(max_file_bytes))
        self.receipts: list[dict[str, Any]] = []

    def read_file(
        self,
        path: str,
        start_line: int = 1,
        end_line: int | None = None,
    ) -> dict[str, Any]:
        relative = Path(str(path)).as_posix().removeprefix("./")
        if relative not in self.allowed_paths:
            return {"error": "path is not related to open debt", "tool": "read_file", "path": relative}
        file_path = (self.repository / relative).resolve()
        try:
            file_path.relative_to(self.repository)
        except ValueError:
            return {"error": "path escapes repository", "tool": "read_file", "path": relative}
        if not file_path.is_file():
            return {"error": "file is unavailable", "tool": "read_file", "path": relative}
        try:
            if file_path.stat().st_size > self.max_file_bytes:
                return {"error": "file is too large for a review read", "tool": "read_file", "path": relative}
        except OSError as exc:
            return {"error": str(exc), "tool": "read_file", "path": relative}
        try:
            lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            return {"error": str(exc), "tool": "read_file", "path": relative}
        start = max(1, int(start_line))
        total_lines = len(lines)
        if start > total_lines:
            text = ""
            actual_end = total_lines
        else:
            requested_end = total_lines if end_line is None else max(start, min(int(end_line), total_lines))
            text = "\n".join(lines[start - 1 : requested_end])
            actual_end = start + text.count("\n")
            if text and actual_end < requested_end:
                actual_end = max(start, actual_end)
        receipt = {
            "tool": "read_file",
            "path": relative,
            "start_line": start,
            "end_line": actual_end,
            "total_lines": total_lines,
            "truncated": actual_end < total_lines,
            "chars": len(text),
            "status": "ok",
        }
        self.receipts.append(receipt)
        return {"path": relative, "text": text, **receipt}

    def langchain_tools(self) -> list[StructuredTool]:
        return [
            StructuredTool.from_function(
                func=self.read_file,
                name="read_file",
                description="Read a bounded line range from a file related to open review debt.",
            )
        ]
