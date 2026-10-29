from __future__ import annotations

import logging
from io import StringIO
import tempfile
import unittest
from pathlib import Path

from yasa_vulnagent.observability import ProgressReporter, start_run_logging


class ObservabilityTest(unittest.TestCase):
    def test_progress_reports_heartbeat_and_elapsed_time(self) -> None:
        stream = StringIO()
        logger = logging.getLogger("observability-test")
        handler = logging.StreamHandler(stream)
        logger.handlers = [handler]
        logger.setLevel(logging.INFO)
        logger.propagate = False
        now = [0.0]
        reporter = ProgressReporter(logger, heartbeat_interval=30.0, clock=lambda: now[0])
        try:
            reporter.start("demo.node")
            now[0] = 31.0
            reporter.heartbeat()
            now[0] = 33.5
            reporter.finish("demo.node")
        finally:
            reporter.close()
            handler.close()
            logger.handlers = []

        output = stream.getvalue()
        self.assertIn("progress start step=demo.node", output)
        self.assertIn("progress heartbeat step=demo.node waiting_seconds=31.0", output)
        self.assertIn("progress finish step=demo.node status=complete elapsed_seconds=33.500", output)

    def test_run_log_is_created_and_receives_progress(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_file = Path(temporary) / "run.json"
            session = start_run_logging(run_file)
            try:
                session.progress.start("workflow")
                session.progress.finish("workflow")
            finally:
                session.close()

            log = run_file.with_name("run.log")
            self.assertTrue(log.is_file())
            content = log.read_text(encoding="utf-8")
            self.assertIn("progress start step=workflow", content)
            self.assertIn("progress finish step=workflow", content)
            self.assertNotIn("api_key", content)


if __name__ == "__main__":
    unittest.main()
