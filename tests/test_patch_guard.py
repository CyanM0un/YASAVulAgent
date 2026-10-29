from __future__ import annotations

import unittest
from types import SimpleNamespace

from yasa_vulnagent.config import Settings
from yasa_vulnagent.stages.init.security_history.patch_graph import build_graph


class PatchPromptGuardTest(unittest.TestCase):
    def test_oversized_prompt_returns_partial_without_calling_model(self) -> None:
        settings = Settings(
            api_key="test",
            base_url="https://example.invalid",
            model="fake",
            agent_context_tokens=1,
            agent_compaction_trigger=0.8,
        )
        state = {
            "candidate": {"commit": "a" * 40, "parent": "b" * 40},
            "review": {},
            "changed_paths": [],
            "units": [{"id": "u1", "summary": "x" * 1000}],
        }
        result = build_graph.__wrapped__(
            state,
            SimpleNamespace(context=SimpleNamespace(settings=settings, usage=None)),
        )
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["error"], "patch_graph_prompt_too_large")


if __name__ == "__main__":
    unittest.main()
