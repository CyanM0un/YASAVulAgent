"""Read-only tools exposed to trace agents."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from langchain_core.tools import StructuredTool

from ...discover.screen.tools import YasaToolbox


class TraceYasaToolbox(YasaToolbox):
    """Nine-tool YASA adapter for structural navigation."""

    _TOOL_NAMES = (
        "search_symbol",
        "get_function",
        "get_class_by_name",
        "get_import_by_file",
        "get_file_by_keyword",
        "get_api_by_name",
        "get_call_graph",
        "get_function_by_call",
        "get_reference_by_function",
    )

    def langchain_tools(self) -> list[StructuredTool]:
        return [
            StructuredTool.from_function(
                coroutine=self.search_symbol,
                name="search_symbol",
                description="Search YASA symbols for structural navigation.",
            ),
            StructuredTool.from_function(
                coroutine=self.get_function,
                name="get_function",
                description="Get a bounded YASA function definition.",
            ),
            StructuredTool.from_function(
                coroutine=self.get_class_by_name,
                name="get_class_by_name",
                description="Get a bounded YASA class definition.",
            ),
            StructuredTool.from_function(
                coroutine=self.get_import_by_file,
                name="get_import_by_file",
                description="Get imports recorded for one file.",
            ),
            StructuredTool.from_function(
                coroutine=self.get_file_by_keyword,
                name="get_file_by_keyword",
                description="Find files by a content keyword.",
            ),
            StructuredTool.from_function(
                coroutine=self.get_api_by_name,
                name="get_api_by_name",
                description="Find the implementation of a route, API, or function name.",
            ),
            StructuredTool.from_function(
                coroutine=self.get_call_graph,
                name="get_call_graph",
                description="Expand the callee tree of one function.",
            ),
            StructuredTool.from_function(
                coroutine=self.get_function_by_call,
                name="get_function_by_call",
                description="Resolve a call site to its function definition.",
            ),
            StructuredTool.from_function(
                coroutine=self.get_reference_by_function,
                name="get_reference_by_function",
                description="Find call sites that reference one function.",
            ),
        ]

    async def get_function(
        self,
        name: str = "",
        function_fqn: str = "",
        file_path: str = "",
        code: str = "",
        detail_level: str = "summary",
        max_results: int = 20,
    ) -> dict[str, Any]:
        payload = await super().get_function(
            name=name,
            function_fqn=function_fqn,
            file_path=file_path,
            code=code,
            detail_level=detail_level,
            max_results=max_results,
        )
        if self.receipts and self.receipts[-1].get("tool") == "get_function":
            spans = _extract_code_spans(payload, self.repository)
            if spans:
                self.receipts[-1]["spans"] = spans
        return payload

    async def get_file_by_keyword(
        self,
        keyword: str = "",
        use_regex: bool = False,
        detail_level: str = "summary",
        offset: int = 0,
        max_results: int = 10,
    ) -> dict[str, Any]:
        return await self._call(
            "get_file_by_keyword",
            {
                "keyword": keyword,
                "use_regex": use_regex,
                "detail_level": detail_level,
                "offset": offset,
                "max_results": max_results,
            },
        )

    async def get_api_by_name(
        self,
        api_name: str = "",
        use_regex: bool = False,
        max_results: int = 20,
    ) -> dict[str, Any]:
        return await self._call(
            "get_api_by_name",
            {
                "api_name": api_name,
                "use_regex": use_regex,
                "max_results": max_results,
            },
        )

    async def get_call_graph(
        self,
        name: str = "",
        function_fqn: str = "",
        file_path: str = "",
        line: int = 0,
        depth: int = 3,
        max_callees_per_node: int = 3,
    ) -> dict[str, Any]:
        return await self._call(
            "get_call_graph",
            {
                "name": name,
                "function_fqn": function_fqn,
                "file_path": file_path,
                "line": line,
                "depth": depth,
                "max_callees_per_node": max_callees_per_node,
                "detail_level": "summary",
            },
        )

    async def get_function_by_call(
        self,
        function_call: str = "",
        file_path: str = "",
        line: int = 0,
        fuzzy_match: bool = True,
        max_results: int = 10,
    ) -> dict[str, Any]:
        return await self._call(
            "get_function_by_call",
            {
                "function_call": function_call,
                "file_path": file_path,
                "line": line,
                "fuzzy_match": fuzzy_match,
                "max_results": max_results,
            },
        )

    async def get_reference_by_function(
        self,
        name: str = "",
        function_fqn: str = "",
        file_path: str = "",
        line: int = 0,
        max_results: int = 20,
    ) -> dict[str, Any]:
        return await self._call(
            "get_reference_by_function",
            {
                "name": name,
                "function_fqn": function_fqn,
                "file_path": file_path,
                "line": line,
                "max_results": max_results,
            },
        )


def _extract_code_spans(payload: Any, repository: Path) -> list[dict[str, Any]]:
    """Extract normalized source spans from YASA get_function results that include code."""
    if not isinstance(payload, dict):
        return []
    results = payload.get("results")
    if not isinstance(results, list):
        return []
    repo_root = repository.expanduser().resolve()
    spans: list[dict[str, Any]] = []
    seen: set[tuple[str, int, int]] = set()
    for item in results:
        if not isinstance(item, dict):
            continue
        body = (
            item.get("code")
            or item.get("source")
            or item.get("source_code")
            or item.get("body")
            or ""
        )
        if not isinstance(body, str) or not body.strip():
            continue
        location = item.get("location") if isinstance(item.get("location"), dict) else {}
        raw_path = str(
            item.get("file_path")
            or location.get("file_path")
            or item.get("path")
            or ""
        ).strip()
        if not raw_path:
            continue
        normalized = _relative_path(raw_path, repo_root)
        if not normalized:
            continue
        try:
            start = int(
                item.get("start_line")
                or location.get("start_line")
                or item.get("line")
                or 0
            )
            end = int(
                item.get("end_line")
                or location.get("end_line")
                or start
            )
        except (TypeError, ValueError):
            continue
        if start <= 0 or end < start:
            continue
        key = (normalized, start, end)
        if key in seen:
            continue
        seen.add(key)
        spans.append({"path": normalized, "start_line": start, "end_line": end})
    return spans


def _relative_path(raw_path: str, repo_root: Path) -> str:
    candidate = Path(raw_path)
    if candidate.is_absolute():
        try:
            return candidate.resolve().relative_to(repo_root).as_posix()
        except ValueError:
            return ""
    return raw_path.replace("\\", "/").removeprefix("./")
