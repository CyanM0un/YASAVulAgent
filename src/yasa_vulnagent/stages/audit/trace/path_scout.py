"""Deterministic call-chain scouting before unit triage."""

from __future__ import annotations

import hashlib
from typing import Any, Mapping


def unit_id(path: str, function_fqn: str, start_line: int, end_line: int) -> str:
    value = f"{path}\0{function_fqn}\0{start_line}\0{end_line}"
    return "unit-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


async def scout_task(task: Mapping[str, Any], execution: Any) -> dict[str, Any]:
    source = execution.source_toolbox()
    yasa = execution.yasa_toolbox()
    roots = _roots(task, execution)
    chains: list[dict[str, Any]] = []
    excerpts: list[dict[str, Any]] = []
    status = "available" if yasa is not None else "unavailable"
    for index, root in enumerate(roots):
        nodes = [root]
        if yasa is not None and root.get("name"):
            payload = await yasa.get_call_graph(
                name=str(root["name"]),
                file_path=str(root.get("path", "")),
                line=int(root.get("start_line", 0)),
                depth=3,
                max_callees_per_node=3,
            )
            nodes = _call_graph_nodes(payload, root) or nodes
            if isinstance(payload, dict) and payload.get("truncated"):
                status = "truncated"
        _read_nodes(source, nodes, excerpts)
        chains.append({"chain_id": f"chain-{index + 1}", "nodes": nodes[:12]})
    return {
        "chains": chains,
        "excerpts": _dedupe_excerpts(excerpts),
        "dynamic_suspected": status != "available",
        "yasa": {"status": status},
    }


async def expand_frontier(
    task: Mapping[str, Any],
    scout: Mapping[str, Any],
    units: list[dict[str, Any]],
    execution: Any,
) -> dict[str, Any]:
    """Expand only the units marked for another triage round."""
    existing = [dict(chain) for chain in scout.get("chains", []) if isinstance(chain, dict)]
    excerpts = [dict(item) for item in scout.get("excerpts", []) if isinstance(item, dict)]
    source = execution.source_toolbox()
    yasa = execution.yasa_toolbox()
    by_parent: dict[str, list[dict[str, Any]]] = {}
    for unit in units[:12]:
        parent = str(unit.get("unit_id", ""))
        if not parent:
            continue
        nodes: list[dict[str, Any]] = []
        if yasa is not None and unit.get("function_fqn"):
            payload = await yasa.get_call_graph(
                function_fqn=str(unit["function_fqn"]),
                file_path=str(unit.get("path", "")),
                line=int(unit.get("start_line", 0)),
                depth=2,
                max_callees_per_node=3,
            )
            nodes = _call_graph_nodes(payload, unit)
        _read_nodes(source, nodes, excerpts)
        if nodes:
            by_parent[parent] = nodes
            existing.append(
                {
                    "chain_id": f"expand-{len(existing) + 1}",
                    "parent_unit_id": parent,
                    "nodes": nodes[:12],
                }
            )
    return {
        **dict(scout),
        "chains": existing,
        "excerpts": _dedupe_excerpts(excerpts),
        "expanded_unit_ids": sorted(by_parent),
    }


def _roots(task: Mapping[str, Any], execution: Any) -> list[dict[str, Any]]:
    roots: list[dict[str, Any]] = []
    if str(task.get("kind", "")) == "entry":
        for entry_id in task.get("entry_ids", []):
            entry = execution.entries_by_id.get(str(entry_id), {})
            location = entry.get("entry_location") if isinstance(entry, dict) else {}
            if not isinstance(location, dict):
                continue
            path = str(location.get("path", ""))
            start = int(location.get("start_line", location.get("line_start", 1)) or 1)
            end = int(location.get("end_line", location.get("line_end", start)) or start)
            roots.append(
                {
                    "unit_id": unit_id(path, str(entry.get("name", "")), start, end),
                    "path": path,
                    "function_fqn": str(entry.get("name", "")),
                    "name": str(entry.get("name", "")),
                    "start_line": start,
                    "end_line": end,
                    "role": "entry",
                }
            )
    else:
        for patch_id in task.get("patch_ids", []):
            patch = execution.patches_by_id.get(str(patch_id), {})
            for unit in patch.get("units", []) if isinstance(patch, dict) else []:
                if not isinstance(unit, dict):
                    continue
                for path in unit.get("paths", []) or patch.get("changed_paths", []):
                    roots.append(
                        {
                            "unit_id": unit_id(str(path), str(unit.get("id", "")), 1, 1),
                            "path": str(path),
                            "function_fqn": str(unit.get("id", "")),
                            "name": "",
                            "start_line": 1,
                            "end_line": 1,
                            "role": "patch",
                            "patch_id": str(patch_id),
                            "unit_ref": str(unit.get("id", "")),
                        }
                    )
        if not roots:
            for path in task.get("paths", []):
                roots.append(
                    {
                        "unit_id": unit_id(str(path), "", 1, 1),
                        "path": str(path),
                        "function_fqn": "",
                        "name": "",
                        "start_line": 1,
                        "end_line": 1,
                        "role": "path",
                    }
                )
    return _dedupe_roots(roots)


def _call_graph_nodes(payload: Any, root: Mapping[str, Any]) -> list[dict[str, Any]]:
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, list) or not results:
        return []
    nodes: list[dict[str, Any]] = []
    for result in results[:3]:
        if not isinstance(result, dict):
            continue
        caller = result.get("caller") if isinstance(result.get("caller"), dict) else {}
        nodes.append(_node(caller, root))
        for callee in result.get("callees", []) if isinstance(result.get("callees"), list) else []:
            _flatten_callee(callee, nodes, depth=1)
    return [node for node in nodes if node.get("path")]


def _flatten_callee(callee: Any, nodes: list[dict[str, Any]], *, depth: int) -> None:
    if depth > 3 or not isinstance(callee, dict) or len(nodes) >= 12:
        return
    location = callee.get("location") if isinstance(callee.get("location"), dict) else {}
    path = str(location.get("file_path") or callee.get("file_path") or "")
    fqn = str(
        callee.get("function_fqn")
        or callee.get("fqn")
        or callee.get("function_name")
        or callee.get("name")
        or ""
    )
    start = int(location.get("start_line") or callee.get("start_line") or callee.get("line") or 1)
    end = int(location.get("end_line") or callee.get("end_line") or start)
    node = {
        "unit_id": unit_id(path, fqn, start, end),
        "path": path,
        "function_fqn": fqn,
        "name": fqn.rsplit(".", 1)[-1] if fqn else "",
        "start_line": start,
        "end_line": end,
        "role": "callee",
    }
    if node["path"]:
        nodes.append(node)
    for child in callee.get("callees", []) if isinstance(callee.get("callees"), list) else []:
        _flatten_callee(child, nodes, depth=depth + 1)


def _node(raw: Mapping[str, Any], root: Mapping[str, Any]) -> dict[str, Any]:
    location = raw.get("location") if isinstance(raw.get("location"), dict) else {}
    path = str(
        raw.get("file_path") or location.get("file_path") or root.get("path", "")
    )
    start = int(
        raw.get("line")
        or raw.get("start_line")
        or location.get("start_line")
        or root.get("start_line", 1)
        or 1
    )
    fqn = str(
        raw.get("function_fqn")
        or raw.get("fqn")
        or raw.get("function_name")
        or raw.get("name")
        or root.get("function_fqn", "")
    )
    return {
        "unit_id": unit_id(path, fqn, start, start),
        "path": path,
        "function_fqn": fqn,
        "name": fqn.rsplit(".", 1)[-1],
        "start_line": start,
        "end_line": start,
        "role": "caller",
    }


def _read_nodes(source: Any, nodes: list[dict[str, Any]], excerpts: list[dict[str, Any]]) -> None:
    for node in nodes[:8]:
        path = str(node.get("path", ""))
        if not path:
            continue
        start = max(1, int(node.get("start_line", 1)))
        end = max(start, min(start + 119, int(node.get("end_line", start)) or start))
        result = source.read_file(path, start_line=start, end_line=end)
        if isinstance(result, dict) and not result.get("error"):
            node["excerpt_lines"] = [start, int(result.get("end_line", end))]
            excerpts.append(
                {
                    "unit_id": node.get("unit_id", ""),
                    "path": path,
                    "start_line": start,
                    "end_line": int(result.get("end_line", end)),
                    "text": str(result.get("text", ""))[:6000],
                }
            )


def _dedupe_roots(roots: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for root in roots:
        if root.get("path"):
            result[str(root["unit_id"])] = root
    return list(result.values())


def _dedupe_excerpts(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: dict[tuple[str, int, int], dict[str, Any]] = {}
    for item in items:
        key = (str(item.get("path", "")), int(item.get("start_line", 0)), int(item.get("end_line", 0)))
        result[key] = item
    return list(result.values())

