from __future__ import annotations

import subprocess
import logging
from pathlib import Path
from typing import Any

from langgraph.runtime import Runtime

from ....storage import utc_now
from ....observability import trace_node
from ....workflow.state import RunContext
from ..schema import DiscoverState
from ..ledger import DiscoverLedger
from ..storage import load_json, load_previous, persist, unique, write_json
from .inventory import build_inventory


logger = logging.getLogger(__name__)


@trace_node("discover.prepare")
def prepare(
    state: DiscoverState,
    runtime: Runtime[RunContext] | None = None,
) -> dict[str, object]:
    """Build a deterministic inventory and recover the discover work ledger."""
    del runtime
    previous = load_previous(state)
    repository = Path(previous.get("repository", state["repository"])).expanduser().resolve()
    _validate_base(previous, repository)
    init_reference = _enriched_init_reference(previous)
    init_resources, resource_gaps = _index_init_resources(previous, init_reference)

    current_files, excluded, inventory_gaps, inventory_source = build_inventory(repository)
    logger.info(
        "discover prepare inventory source=%s files=%s excluded=%s",
        inventory_source,
        len(current_files),
        len(excluded),
    )

    ledger_file = Path(previous.get("ledger_file", "")) if previous.get("ledger_file") else Path(previous["artifact_dir"]) / "ledger.sqlite"
    with DiscoverLedger.open(ledger_file) as ledger:
        inventory_counts = ledger.replace_inventory(current_files, excluded)
        requeued_task_count = ledger.recover_running_tasks()
        warnings = unique(list(previous.get("warnings", [])))
        gaps = unique([*previous.get("gaps", []), *resource_gaps, *inventory_gaps])
        ledger.add_messages(gaps=gaps, warnings=warnings)
        file_counts = ledger.file_counts()
        candidate_count = file_counts.get("production_text", 0)
        task_count = ledger.task_count()
    if not candidate_count:
        gaps.append("no text source or configuration candidates were found")
        with DiscoverLedger.open(ledger_file) as ledger:
            ledger.add_messages(gaps=[gaps[-1]])

    compact_gaps = unique(gaps)
    prepare_result = {
        "status": "partial" if gaps else "complete",
        "inventory_source": inventory_source,
        "file_count": inventory_counts["file_count"],
        "excluded_count": inventory_counts["excluded_count"],
        "candidate_count": candidate_count,
        "requeued_task_count": requeued_task_count,
        "task_count": task_count,
        "init_resource_count": sum(len(items) for items in init_resources.values()),
        "gaps": compact_gaps[-20:],
        "gap_count": len(compact_gaps),
        "warnings": unique(warnings)[-20:],
    }
    with DiscoverLedger.open(ledger_file) as ledger:
        file_counts = ledger.file_counts()
        update: DiscoverState = {
            **previous,
            "repository": str(repository),
            "ledger_file": str(ledger_file),
            "init_reference": init_reference,
            "init_resources": init_resources,
            "source_revision": _source_revision(repository),
            "file_count": file_counts.get("total", 0),
            "screened_file_count": file_counts.get("screened", 0),
            "covered_file_count": file_counts.get("covered", 0),
            "excluded_file_count": ledger.excluded_count(),
            "task_count": ledger.task_count(),
            "pending_task_count": ledger.pending_task_count(),
            "entry_count": ledger.count_entries(),
            "evidence_count": ledger.count_evidence(),
            "gap_count": ledger.message_count("gaps"),
            "warning_count": ledger.message_count("warnings"),
            "prepare": prepare_result,
            "warnings": ledger.messages("warnings"),
            "gaps": ledger.messages("gaps"),
            "current_node": "prepare",
            "status": "running",
            "stop_reason": "",
            "updated_at": utc_now(),
        }
        ledger.export_inventory(Path(update["artifact_dir"]))
    persist(update)
    artifact_dir = Path(update["artifact_dir"])
    write_json(artifact_dir / "init-resources.json", init_resources)
    write_json(artifact_dir / "prepare.json", prepare_result)
    logger.info(
        "discover prepare work items candidates=%s files=%s gaps=%s",
        candidate_count,
        prepare_result["file_count"],
        len(prepare_result["gaps"]),
    )
    return update


def _validate_base(state: DiscoverState, repository: Path) -> None:
    if not repository.is_dir():
        raise ValueError(f"discover prepare requires a repository directory: {repository}")
    reference = state.get("init_reference", {})
    status = reference.get("status") if isinstance(reference, dict) else None
    if status not in {"complete", "partial"}:
        raise ValueError(
            "discover prepare requires an existing run with a completed or partial init stage"
        )
    state_file = Path(state["state_file"])
    if state_file.exists() and not state_file.is_file():
        raise ValueError(f"discover state path is not a file: {state_file}")


def _enriched_init_reference(state: DiscoverState) -> dict[str, Any]:
    reference = dict(state.get("init_reference", {}))
    artifact_file = reference.get("artifact_file")
    if not artifact_file:
        return reference
    path = Path(str(artifact_file))
    if not path.is_absolute():
        path = _run_root(state) / path
    if not path.is_file():
        return reference
    try:
        record = load_json(path)
    except ValueError:
        return reference
    details = record.get("details")
    if isinstance(details, dict):
        reference["details"] = details
        for key in ("checks", "documents", "security_history", "gaps"):
            if key in details and key not in reference:
                reference[key] = details[key]
    return reference


def _index_init_resources(
    state: DiscoverState,
    reference: dict[str, Any],
) -> tuple[dict[str, list[dict[str, Any]]], list[str]]:
    run_root = _run_root(state)
    resources: dict[str, list[dict[str, Any]]] = {
        "checks": [],
        "documents": [],
        "security_history": [],
    }
    gaps: list[str] = []
    gaps.extend(
        f"init: {item}"
        for item in reference.get("gaps", [])
        if isinstance(item, str) and item
    )
    checks = reference.get("checks", {})
    if isinstance(checks, dict):
        for name in ("yasa", "cwe"):
            check = checks.get(name, {})
            status = str(check.get("status", "missing")) if isinstance(check, dict) else "missing"
            resources["checks"].append(
                {
                    "kind": f"{name}-check",
                    "status": status,
                    "available": status == "complete",
                    "required": True,
                }
            )
            if status in {"missing", "unavailable", "partial", "failed", "timeout"}:
                gaps.append(f"init {name} check is {status}")
    else:
        gaps.append("init checks index is missing")

    documents = reference.get("documents")
    document_paths = (
        ("inventory", "inventory_file", True),
        ("overview", "overview_file", True),
        ("notes", "notes_dir", False),
        ("sources", "sources_dir", False),
    )
    _append_artifacts(
        resources["documents"],
        gaps,
        run_root,
        "documents",
        documents if isinstance(documents, dict) else {},
        document_paths,
    )

    history = reference.get("security_history")
    history_values = history if isinstance(history, dict) else {}
    history_paths = (
        ("summary", "summary_file", True),
        ("report", "report_file", True),
        ("patch-graphs", "patch_graphs_file", True),
        ("artifact-dir", "artifact_dir", False),
    )
    if history_values.get("artifact_dir") and not history_values.get("patch_graphs_file"):
        history_values = {
            **history_values,
            "patch_graphs_file": str(
                Path(str(history_values["artifact_dir"])) / "patch_graphs.json"
            ),
        }
    _append_artifacts(
        resources["security_history"],
        gaps,
        run_root,
        "security_history",
        history_values,
        history_paths,
    )
    return resources, unique(gaps)


def _append_artifacts(
    target: list[dict[str, Any]],
    gaps: list[str],
    run_root: Path,
    group: str,
    values: dict[str, Any],
    paths: tuple[tuple[str, str, bool], ...],
) -> None:
    for kind, field, is_file in paths:
        raw_path = values.get(field)
        if not raw_path:
            target.append(
                {
                    "kind": kind,
                    "status": "missing",
                    "available": False,
                    "required": False,
                }
            )
            gaps.append(f"init {group} artifact {kind} is missing")
            continue
        path = Path(str(raw_path))
        if not path.is_absolute():
            path = run_root / path
        available = path.is_file() if is_file else path.is_dir()
        relative = _relative_or_absolute(path, run_root)
        target.append(
            {
                "kind": kind,
                "status": "available" if available else "unavailable",
                "path": relative,
                "available": available,
                "required": False,
            }
        )
        if not available:
            gaps.append(f"init {group} artifact {kind} is unavailable: {relative}")


def _run_root(state: DiscoverState) -> Path:
    artifact_dir = Path(state["artifact_dir"]).resolve()
    if artifact_dir.name == "discover" and artifact_dir.parent.name == "stages":
        return artifact_dir.parent.parent
    return artifact_dir.parent


def _relative_or_absolute(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _source_revision(repository: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repository,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError):
        return "working-tree"
    return result.stdout.strip() or "working-tree"
