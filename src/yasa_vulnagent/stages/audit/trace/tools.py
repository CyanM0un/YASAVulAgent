"""Read-only tools exposed to trace agents."""

from __future__ import annotations

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
