from __future__ import annotations

import logging
from pathlib import Path

from ....observability import trace_node
from .runner import YasaRunner
from ....workflow.state import RunState


logger = logging.getLogger(__name__)


@trace_node("init.yasa")
def run(state: RunState) -> dict[str, object]:
    repository = Path(state["repository"])
    result = YasaRunner.from_state(state).run(repository)
    logger.info(
        "init node completed node=yasa status_valid=%s mcp_tool=%s mcp_result_count=%s",
        result["status_valid"],
        result["mcp_tool"],
        result["mcp_result_count"],
    )
    return {"init_checks": {"yasa": {"status": "complete", **result}}}
