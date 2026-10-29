from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from functools import wraps
from pathlib import Path
from typing import Any, Callable, TypeVar
from urllib.parse import urlsplit, urlunsplit


_LOGGER = logging.getLogger("yasa_vulnagent.progress")
_F = TypeVar("_F", bound=Callable[..., Any])


class ProgressReporter:
    """Emit bounded node progress and periodic heartbeats for one run."""

    def __init__(
        self,
        logger: logging.Logger | None = None,
        *,
        heartbeat_interval: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.logger = logger or _LOGGER
        self.heartbeat_interval = max(0.1, heartbeat_interval)
        self._clock = clock
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._steps: dict[int, list[dict[str, float | str]]] = {}
        self._thread = threading.Thread(
            target=self._heartbeat_loop,
            name="yasa-vulnagent-heartbeat",
            daemon=True,
        )
        self._thread.start()

    def start(self, step: str, **fields: object) -> None:
        now = self._clock()
        thread_id = threading.get_ident()
        with self._lock:
            self._steps.setdefault(thread_id, []).append(
                {"step": step, "started_at": now, "last_activity": now}
            )
        self.logger.info("progress start step=%s%s", step, _format_fields(fields))

    def update(self, step: str, message: str, **fields: object) -> None:
        now = self._clock()
        thread_id = threading.get_ident()
        with self._lock:
            stack = self._steps.get(thread_id, [])
            frame = next((item for item in reversed(stack) if item["step"] == step), None)
            if frame is not None:
                frame["last_activity"] = now
        self.logger.info(
            "progress update step=%s message=%s%s",
            step,
            message,
            _format_fields(fields),
        )

    def finish(self, step: str, status: str = "complete", **fields: object) -> None:
        now = self._clock()
        thread_id = threading.get_ident()
        with self._lock:
            stack = self._steps.get(thread_id, [])
            index = next(
                (index for index in range(len(stack) - 1, -1, -1) if stack[index]["step"] == step),
                None,
            )
            started_at = stack[index]["started_at"] if index is not None else None
            if index is not None:
                stack.pop(index)
            if not stack:
                self._steps.pop(thread_id, None)
        elapsed = ""
        if started_at is not None:
            elapsed = f" elapsed_seconds={max(0.0, now - started_at):.3f}"
        self.logger.info(
            "progress finish step=%s status=%s%s%s",
            step,
            status,
            elapsed,
            _format_fields(fields),
        )

    def heartbeat(self) -> None:
        now = self._clock()
        with self._lock:
            frames = [stack[-1] for stack in self._steps.values() if stack]
        if not frames:
            return
        waiting_frames = [
            (str(frame["step"]), max(0.0, now - float(frame["last_activity"])))
            for frame in frames
        ]
        step, waiting = max(waiting_frames, key=lambda item: item[1])
        if waiting < self.heartbeat_interval:
            return
        self.logger.info(
            "progress heartbeat step=%s waiting_seconds=%.1f",
            step,
            waiting,
        )

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=min(1.0, self.heartbeat_interval))
        with self._lock:
            self._steps.clear()

    def _heartbeat_loop(self) -> None:
        while not self._stop.wait(self.heartbeat_interval):
            self.heartbeat()


@dataclass
class RunLogSession:
    """Own the per-run file handler and its progress reporter."""

    log_path: Path
    handler: logging.Handler
    progress: ProgressReporter
    root_logger: logging.Logger
    previous_root_level: int
    package_logger: logging.Logger
    previous_package_level: int
    previous_handler_levels: list[tuple[logging.Handler, int]]
    console_handler: logging.Handler | None

    def close(self) -> None:
        self.progress.close()
        self.handler.flush()
        self.root_logger.removeHandler(self.handler)
        self.handler.close()
        if self.console_handler is not None:
            self.root_logger.removeHandler(self.console_handler)
            self.console_handler.close()
        self.root_logger.setLevel(self.previous_root_level)
        self.package_logger.setLevel(self.previous_package_level)
        for handler, level in self.previous_handler_levels:
            handler.setLevel(level)


def start_run_logging(run_file: Path) -> RunLogSession:
    """Attach terminal and ``run.log`` logging for one workflow invocation."""
    root_logger = logging.getLogger()
    console_handler: logging.Handler | None = None
    if not root_logger.handlers:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        )
        root_logger.addHandler(console_handler)
    previous_root_level = root_logger.level
    package_logger = logging.getLogger("yasa_vulnagent")
    previous_package_level = package_logger.level
    previous_handler_levels: list[tuple[logging.Handler, int]] = []
    package_logger.setLevel(logging.DEBUG)
    for handler in root_logger.handlers:
        if isinstance(handler, logging.StreamHandler) and not isinstance(
            handler, logging.FileHandler
        ):
            previous_handler_levels.append((handler, handler.level))
            if handler.level == logging.NOTSET or handler.level < logging.INFO:
                handler.setLevel(logging.INFO)

    log_path = run_file.expanduser().resolve().with_name("run.log")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(log_path, mode="a", encoding="utf-8")
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    root_logger.addHandler(handler)
    progress = ProgressReporter()
    _LOGGER.info("run logging started log_file=%s", log_path)
    return RunLogSession(
        log_path=log_path,
        handler=handler,
        progress=progress,
        root_logger=root_logger,
        previous_root_level=previous_root_level,
        package_logger=package_logger,
        previous_package_level=previous_package_level,
        previous_handler_levels=previous_handler_levels,
        console_handler=console_handler,
    )


def runtime_progress(runtime: object | None) -> ProgressReporter | None:
    context = getattr(runtime, "context", None)
    progress = getattr(context, "progress", None)
    return progress if isinstance(progress, ProgressReporter) else None


def start_step(runtime: object | None, step: str, **fields: object) -> None:
    progress = runtime_progress(runtime)
    if progress is not None:
        progress.start(step, **fields)
    else:
        _LOGGER.info("progress start step=%s%s", step, _format_fields(fields))


def finish_step(
    runtime: object | None,
    step: str,
    status: str = "complete",
    **fields: object,
) -> None:
    progress = runtime_progress(runtime)
    if progress is not None:
        progress.finish(step, status=status, **fields)
    else:
        _LOGGER.info(
            "progress finish step=%s status=%s%s",
            step,
            status,
            _format_fields(fields),
        )


def trace_node(step: str) -> Callable[[_F], _F]:
    """Trace a LangGraph node without changing its state contract."""

    def decorator(function: _F) -> _F:
        @wraps(function)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            runtime = kwargs.get("runtime")
            if runtime is None and len(args) > 1:
                runtime = args[1]
            start_step(runtime, step)
            try:
                result = function(*args, **kwargs)
            except Exception as exc:
                finish_step(runtime, step, status="failed", error_type=type(exc).__name__)
                raise
            fields: dict[str, object] = {}
            status = _result_status(result)
            if isinstance(result, dict):
                fields["result_keys"] = ",".join(sorted(str(key) for key in result))
            finish_step(runtime, step, status=status, **fields)
            return result

        return wrapped  # type: ignore[return-value]

    return decorator


def _format_fields(fields: dict[str, object]) -> str:
    if not fields:
        return ""
    return " " + " ".join(
        f"{key}={str(value).replace(chr(10), ' ')[:200]}" for key, value in fields.items()
    )


def safe_reference(value: object) -> str:
    """Keep URLs useful in logs without persisting query-string credentials."""
    text = str(value)
    parsed = urlsplit(text)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
    return text


def _result_status(result: object) -> str:
    if isinstance(result, dict):
        stages = result.get("stages")
        if isinstance(stages, list) and stages and isinstance(stages[-1], dict):
            stage_status = stages[-1].get("status")
            if isinstance(stage_status, str) and stage_status != "running":
                return stage_status
        direct = result.get("status")
        if isinstance(direct, str) and direct in {
            "failed",
            "partial",
            "unavailable",
            "timeout",
        }:
            return direct
        for value in result.values():
            nested = _result_status(value)
            if nested != "complete":
                return nested
    elif isinstance(result, list):
        for value in result:
            nested = _result_status(value)
            if nested != "complete":
                return nested
    return "complete"
