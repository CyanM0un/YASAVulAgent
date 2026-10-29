from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Any

from ....config import DEFAULT_CWE_ARCHIVE_PATH, resolve_project_path
from ....observability import trace_node
from ....workflow.state import RunState


logger = logging.getLogger(__name__)

TOP25_VIEW_ID = "1435"
TOP25_IDS = {
    "120", "121", "122", "125", "20", "200", "22", "284", "306", "352",
    "416", "434", "476", "502", "639", "77", "770", "78", "787", "79",
    "862", "863", "89", "918", "94",
}


def _extract_text(archive: Path) -> str:
    with zipfile.ZipFile(archive) as archive_file:
        names = [name for name in archive_file.namelist() if not name.endswith("/")]
        if not names:
            raise ValueError(f"CWE archive is empty: {archive}")
        return archive_file.read(names[0]).decode("utf-8-sig", errors="replace")


def validate_cwe(archive: Path) -> dict[str, Any]:
    if not archive.is_file():
        return {"valid": False, "reason": "missing", "path": str(archive)}

    try:
        raw = _extract_text(archive)
    except (OSError, ValueError, zipfile.BadZipFile, UnicodeError) as exc:
        return {"valid": False, "reason": f"invalid archive: {exc}", "path": str(archive)}

    try:
        root_element = ET.fromstring(raw)
        namespace = {"c": "http://cwe.mitre.org/cwe-7"}
        ids = {
            item.attrib["ID"]
            for item in root_element.findall("./c:Weaknesses/c:Weakness", namespace)
            if item.attrib.get("ID")
        }
    except ET.ParseError as exc:
        return {"valid": False, "reason": f"invalid XML: {exc}", "path": str(archive)}

    missing = sorted(TOP25_IDS - ids, key=int)
    return {
        "valid": not missing,
        "path": str(archive),
        "version": "2025",
        "view_id": TOP25_VIEW_ID,
        "entry_count": len(ids),
        "missing_ids": missing,
    }


@trace_node("init.cwe")
def run(state: RunState) -> dict[str, object]:
    configured_path = state.get("config", {}).get("cwe_archive_path")
    archive = resolve_project_path(configured_path or DEFAULT_CWE_ARCHIVE_PATH)
    result = validate_cwe(archive)
    check = {
        "status": "complete" if result["valid"] else "unavailable",
        **result,
    }
    if result["valid"]:
        logger.info(
            "init node completed node=cwe path=%s entries=%s",
            result["path"],
            result["entry_count"],
        )
    else:
        missing_ids = result.get("missing_ids", [])
        reason = result.get("reason") or f"missing_ids={','.join(missing_ids)}"
        logger.warning(
            "init node cwe unavailable path=%s reason=%s",
            result["path"],
            reason,
        )
    checks = dict(state.get("init_checks", {}))
    checks["cwe"] = check
    return {"init_checks": checks}
