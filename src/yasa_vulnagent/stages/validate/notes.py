"""Per-finding notes that survive compaction and resume."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


class NoteStore:
    def __init__(self, path: Path, *, max_notes: int = 20, note_chars: int = 2000) -> None:
        self.path = Path(path)
        self.max_notes = max(1, int(max_notes))
        self.note_chars = max(1, int(note_chars))

    def add(self, key: str, text: str) -> dict[str, object]:
        if self.count() >= self.max_notes:
            return {"error": f"note limit reached ({self.max_notes})", "tool": "save_note"}
        record = {
            "key": str(key).strip()[:120] or "note",
            "text": str(text).strip()[: self.note_chars],
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        return {"status": "ok", "tool": "save_note", "key": record["key"]}

    def entries(self) -> list[dict[str, str]]:
        if not self.path.is_file():
            return []
        entries: list[dict[str, str]] = []
        for line in self.path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if isinstance(value, dict) and str(value.get("text", "")).strip():
                entries.append({"key": str(value.get("key", "")), "text": str(value["text"])})
        return entries[-self.max_notes :]

    def count(self) -> int:
        return len(self.entries())

    def text(self, limit: int = 3000) -> str:
        entries = self.entries()
        if not entries:
            return ""
        lines = ["Previously saved notes (re-read source before relying on them):"]
        lines.extend(f"- {item['key']}: {item['text']}" for item in entries)
        return "\n".join(lines)[: max(1, int(limit))]
