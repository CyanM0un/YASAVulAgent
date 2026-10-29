from __future__ import annotations

from pathlib import Path

from langgraph.runtime import Runtime

from ..config import AUDIT_MODES, load_settings
from ..observability import start_run_logging
from ..storage import create_run, load_state, mark_failed, save_state
from ..stages.audit.node import run_stage as audit_stage
from ..stages.discover.node import run_stage as discover_stage
from ..stages.validate.environment.node import run_environment
from ..stages.validate.node import run_validate
from ..stages.report.node import run_report
from .graph import build_graph
from .state import RunContext, RunState


def run(
    repository: Path,
    output_dir: Path | None = None,
    audit_mode: str | None = None,
) -> RunState:
    if audit_mode is not None and audit_mode not in AUDIT_MODES:
        raise ValueError(f"audit mode must be one of {', '.join(AUDIT_MODES)}")
    settings = load_settings()
    state = create_run(repository, output_dir, settings, audit_mode)
    session = start_run_logging(Path(state["run_file"]))
    session.progress.start("workflow", run_id=state["run_id"])
    try:
        result = build_graph().invoke(
            state,
            context=RunContext(settings=settings, progress=session.progress),
        )
        session.progress.finish("workflow", status=str(result.get("status", "complete")))
        return result
    except Exception as error:
        session.progress.finish("workflow", status="failed", error_type=type(error).__name__)
        try:
            persisted = load_state(Path(state["run_file"]))
            mark_failed(persisted, error)
        except (OSError, TypeError, ValueError):
            pass
        raise
    finally:
        session.close()


def run_discover(run_file: Path) -> RunState:
    """Run only discover from an existing run created after init.

    The discover subgraph owns its checkpoint under the run's discover artifact
    directory, so invoking this again resumes pending work instead of creating
    a second run record.
    """
    state = load_state(run_file.expanduser().resolve())
    repository = Path(state["repository"])
    if not repository.is_dir():
        raise ValueError(f"repository is not a directory: {repository}")
    init_records = [item for item in state.get("stages", []) if item.get("name") == "init"]
    if not init_records or init_records[-1].get("status") not in {"complete", "partial"}:
        raise ValueError("discover requires an existing run with a completed or partial init stage")
    session = start_run_logging(run_file.expanduser().resolve())
    session.progress.start("workflow.discover_resume", run_file=str(run_file))
    try:
        update = discover_stage(
            state,
            runtime=Runtime(
                context=RunContext(settings=load_settings(), progress=session.progress)
            ),
        )
        session.progress.finish(
            "workflow.discover_resume",
            status=str(update.get("status", "complete")),
        )
        return {**state, **update}
    except Exception as error:
        session.progress.finish(
            "workflow.discover_resume",
            status="failed",
            error_type=type(error).__name__,
        )
        try:
            persisted = load_state(Path(state["run_file"]))
            mark_failed(persisted, error)
        except (OSError, TypeError, ValueError):
            pass
        raise
    finally:
        session.close()


def run_audit(run_file: Path, mode: str | None = None) -> RunState:
    """Run the audit stage from an existing run created after init and discover."""
    if mode is not None and mode not in AUDIT_MODES:
        raise ValueError(f"audit mode must be one of {', '.join(AUDIT_MODES)}")
    state = load_state(run_file.expanduser().resolve())
    repository = Path(state["repository"])
    if not repository.is_dir():
        raise ValueError(f"repository is not a directory: {repository}")
    for name in ("init", "discover"):
        records = [item for item in state.get("stages", []) if item.get("name") == name]
        if not records or records[-1].get("status") not in {"complete", "partial"}:
            raise ValueError(
                f"audit requires an existing run with a completed or partial {name} stage"
            )
    audit_records = [item for item in state.get("stages", []) if item.get("name") == "audit"]
    if (
        mode is not None
        and audit_records
        and str(state.get("audit_mode") or "") != mode
    ):
        raise ValueError("audit mode cannot be changed after the audit stage has started")

    settings = load_settings()
    selected_mode = mode or str(state.get("audit_mode") or settings.audit_mode)
    if selected_mode not in AUDIT_MODES:
        raise ValueError(f"audit mode must be one of {', '.join(AUDIT_MODES)}")
    state = {**state, "audit_mode": selected_mode}
    save_state(state)
    resolved = run_file.expanduser().resolve()
    session = start_run_logging(resolved)
    session.progress.start("workflow.audit_resume", run_file=str(run_file))
    try:
        update = audit_stage(
            state,
            runtime=Runtime(
                context=RunContext(settings=settings, progress=session.progress)
            ),
        )
        session.progress.finish(
            "workflow.audit_resume",
            status=str(update.get("audit", {}).get("status", "partial")),
        )
        return {**state, **update}
    except Exception as error:
        session.progress.finish(
            "workflow.audit_resume",
            status="failed",
            error_type=type(error).__name__,
        )
        try:
            persisted = load_state(Path(state["run_file"]))
            mark_failed(persisted, error)
        except (OSError, TypeError, ValueError):
            pass
        raise
    finally:
        session.close()

