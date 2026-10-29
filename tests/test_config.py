from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from yasa_vulnagent.config import load_settings


class DiscoverLimitConfigTest(unittest.TestCase):
    def _load(self, **env: str):
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing.env"
            with patch.dict(os.environ, env, clear=True):
                return load_settings(env_file=missing)

    def test_discover_limit_defaults(self) -> None:
        settings = self._load()

        self.assertEqual(settings.discover_recursion_limit, 50)
        self.assertEqual(settings.screen_task_max_rounds, 16)
        self.assertEqual(settings.screen_wave_timeout, 1200)
        self.assertEqual(settings.screen_wave_model_calls, 96)
        self.assertEqual(settings.planner_max_calls, 6)
        self.assertEqual(settings.safe_dict()["discover_recursion_limit"], 50)
        self.assertEqual(settings.safe_dict()["screen_task_max_rounds"], 16)

    def test_discover_limits_read_from_environment(self) -> None:
        settings = self._load(
            DISCOVER_RECURSION_LIMIT="81",
            DISCOVER_SCREEN_TASK_MAX_ROUNDS="24",
            DISCOVER_SCREEN_WAVE_TIMEOUT="1800",
            DISCOVER_SCREEN_WAVE_MODEL_CALLS="144",
        )

        self.assertEqual(settings.discover_recursion_limit, 81)
        self.assertEqual(settings.screen_task_max_rounds, 24)
        self.assertEqual(settings.screen_wave_timeout, 1800)
        self.assertEqual(settings.screen_wave_model_calls, 144)

    def test_explicit_legacy_budget_values_still_apply(self) -> None:
        settings = self._load(
            DISCOVER_SCREEN_WAVE_TIMEOUT="600",
            DISCOVER_SCREEN_WAVE_MODEL_CALLS="48",
            DISCOVER_SCREEN_TASK_MAX_ROUNDS="12",
        )

        self.assertEqual(settings.screen_wave_timeout, 600)
        self.assertEqual(settings.screen_wave_model_calls, 48)
        self.assertEqual(settings.screen_task_max_rounds, 12)

    def test_zero_is_rejected(self) -> None:
        for name in ("DISCOVER_RECURSION_LIMIT", "DISCOVER_SCREEN_TASK_MAX_ROUNDS"):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    self._load(**{name: "0"})


class AuditConfigTest(unittest.TestCase):
    def _load(self, **env: str):
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing.env"
            with patch.dict(os.environ, env, clear=True):
                return load_settings(env_file=missing)

    def test_audit_defaults(self) -> None:
        settings = self._load()

        self.assertEqual(settings.audit_mode, "combined")
        self.assertEqual(settings.audit_timeout, 3600)
        self.assertEqual(settings.audit_recursion_limit, 50)
        self.assertEqual(settings.audit_max_agents, 4)
        self.assertEqual(settings.audit_plan_batch_size, 100)
        self.assertEqual(settings.audit_max_total_tokens, 0)
        self.assertEqual(settings.audit_max_total_cost, 0.0)
        self.assertEqual(settings.audit_model_concurrency, 4)
        self.assertEqual(settings.safe_dict()["audit_mode"], "combined")
        self.assertEqual(settings.safe_dict()["audit_max_agents"], 4)
        self.assertEqual(settings.safe_dict()["audit_plan_batch_size"], 100)
        self.assertEqual(settings.safe_dict()["audit_max_total_tokens"], 0)
        self.assertEqual(settings.safe_dict()["audit_model_concurrency"], 4)

    def test_audit_values_read_from_environment(self) -> None:
        settings = self._load(
            AUDIT_MODE="patches",
            AUDIT_TIMEOUT="1200",
            AUDIT_RECURSION_LIMIT="81",
            AUDIT_MAX_AGENTS="2",
            AUDIT_PLAN_BATCH_SIZE="25",
            AUDIT_MAX_TOTAL_TOKENS="1000000",
            AUDIT_MAX_TOTAL_COST="2.5",
            AUDIT_MODEL_CONCURRENCY="2",
        )

        self.assertEqual(settings.audit_mode, "patches")
        self.assertEqual(settings.audit_timeout, 1200)
        self.assertEqual(settings.audit_recursion_limit, 81)
        self.assertEqual(settings.audit_max_agents, 2)
        self.assertEqual(settings.audit_plan_batch_size, 25)
        self.assertEqual(settings.audit_max_total_tokens, 1000000)
        self.assertEqual(settings.audit_max_total_cost, 2.5)
        self.assertEqual(settings.audit_model_concurrency, 2)

    def test_invalid_audit_mode_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._load(AUDIT_MODE="everything")

    def test_zero_cost_and_token_budgets_are_allowed(self) -> None:
        settings = self._load(AUDIT_MAX_TOTAL_TOKENS="0", AUDIT_MAX_TOTAL_COST="0")
        self.assertEqual(settings.audit_max_total_tokens, 0)
        self.assertEqual(settings.audit_max_total_cost, 0.0)

    def test_negative_audit_budgets_are_rejected(self) -> None:
        for name in ("AUDIT_MAX_TOTAL_TOKENS", "AUDIT_MAX_TOTAL_COST"):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    self._load(**{name: "-1"})

    def test_zero_audit_budget_is_rejected(self) -> None:
        for name in (
            "AUDIT_TIMEOUT",
            "AUDIT_RECURSION_LIMIT",
            "AUDIT_MAX_AGENTS",
            "AUDIT_PLAN_BATCH_SIZE",
            "AUDIT_MODEL_CONCURRENCY",
        ):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    self._load(**{name: "0"})


if __name__ == "__main__":
    unittest.main()
