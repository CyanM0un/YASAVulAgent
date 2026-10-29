from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from yasa_vulnagent.config import Settings
from yasa_vulnagent.stages.audit.graph import (
    _record_transition,
    build_audit_graph,
)
from yasa_vulnagent.stages.audit.schema import empty_state
from yasa_vulnagent.stages.audit.storage import audit_paths
from yasa_vulnagent.stages.audit.trace.node import trace
from yasa_vulnagent.stages.audit.verify.node import verify
from yasa_vulnagent.workflow.state import RunContext

from audit_fixtures import make_run_state, references_for


class AuditGraphTest(unittest.TestCase):
    def _state(self, root: Path) -> tuple[dict, object]:
        run_state = make_run_state(
            root,
            entries=[],
            patches=[],
            init_status="complete",
            discover_status="complete",
            overview=True,
        )
        paths = audit_paths(run_state["stages_dir"])
        state = empty_state(run_state, paths)
        state["references"] = references_for(run_state)
        return state, paths

    def test_default_path_visits_nodes_in_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state, _paths = self._state(Path(temporary))
            graph = build_audit_graph()
            result = graph.invoke(
                state,
                context=RunContext(
                    settings=Settings(api_key=None, base_url="http://localhost", model="fake")
                ),
            )

            self.assertEqual(
                result["framework"]["executed"],
                ["prepare", "plan", "trace", "recon", "trace", "verify", "gate", "finalize"],
            )
            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["stop_reason"], "gate_partial")

    def test_compiled_graph_has_expected_nodes(self) -> None:
        graph = build_audit_graph().get_graph()
        names = set(graph.nodes)
        self.assertTrue(
            {"prepare", "plan", "trace", "recon", "verify", "gate", "finalize"}.issubset(names)
        )

    def test_finalize_is_only_reachable_from_gate(self) -> None:
        graph = build_audit_graph().get_graph()
        edges = {(edge.source, edge.target) for edge in graph.edges}
        self.assertIn(("gate", "finalize"), edges)
        self.assertNotIn(("trace", "finalize"), edges)
        self.assertNotIn(("verify", "finalize"), edges)

    def test_verify_finalize_request_is_routed_through_gate(self) -> None:
        state = {"framework": {"executed": [], "visits": {}}, "warnings": []}
        result = _record_transition(state, "verify", "finalize")  # type: ignore[arg-type]
        self.assertEqual(result["next_action"], "gate")
        self.assertTrue(any("routed through gate" in warning for warning in result["warnings"]))

    def test_invalid_action_is_rejected(self) -> None:
        state = {"framework": {"executed": [], "visits": {}}, "warnings": []}
        with self.assertRaises(ValueError):
            _record_transition(state, "trace", "bogus")  # type: ignore[arg-type]

    def test_trace_routes_to_recon_then_verify(self) -> None:
        self.assertEqual(trace({"framework": {"recon_done": False}})["next_action"], "recon")
        self.assertEqual(trace({"framework": {"recon_done": True}})["next_action"], "verify")

    def test_verify_without_artifacts_routes_to_gate(self) -> None:
        result = verify({"framework": {}})
        self.assertEqual(result["next_action"], "gate")
        self.assertTrue(result["framework"]["verify_done"])

    def test_node_visit_limit_routes_to_gate(self) -> None:
        state = {
            "framework": {"executed": [], "visits": {"trace": 4}},
            "warnings": [],
        }
        result = _record_transition(state, "trace", "recon")  # type: ignore[arg-type]
        self.assertEqual(result["next_action"], "gate")
        self.assertEqual(result["stop_reason"], "node_visit_limit")


if __name__ == "__main__":
    unittest.main()
