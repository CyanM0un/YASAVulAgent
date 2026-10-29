from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Sequence

from . import __version__
from .config import AUDIT_MODES
from .workflow.runner import (
    run,
    run_audit,
    run_discover,
    run_environment,
    run_report,
    run_validate,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evidence-backed YASA vulnerability analysis workflow.")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)

    run_parser = commands.add_parser("run", help="Run the five-stage workflow.")
    run_parser.add_argument("repository", type=Path, help="Repository to associate with this run.")
    run_parser.add_argument(
        "--output-dir",
        type=Path,
        help="Parent directory for run records; defaults to REPOSITORY/.yasa-vulnagent/runs.",
    )
    run_parser.add_argument(
        "--audit-mode",
        choices=AUDIT_MODES,
        help="Audit input route; defaults to AUDIT_MODE.",
    )
    discover_parser = commands.add_parser(
        "discover", help="Run or resume discover from an existing run record."
    )
    discover_parser.add_argument("--run-file", required=True, type=Path, help="Existing run.json.")
    audit_parser = commands.add_parser(
        "audit", help="Run the audit stage from an existing run record."
    )
    audit_parser.add_argument("--run-file", required=True, type=Path, help="Existing run.json.")
    audit_parser.add_argument(
        "--mode",
        choices=AUDIT_MODES,
        help="Audit input route; cannot change after audit starts.",
    )
    environment_parser = commands.add_parser(
        "environment", help="Run or resume Docker environment construction for an existing run."
    )
    environment_parser.add_argument("--run-file", required=True, type=Path, help="Existing run.json.")
    environment_parser.add_argument(
        "--rebuild",
        action="store_true",
        help="Ignore a ready environment and build a new image.",
    )
    validate_parser = commands.add_parser(
        "validate", help="Run runtime validation from an existing run record."
    )
    validate_parser.add_argument("--run-file", required=True, type=Path, help="Existing run.json.")
    validate_parser.add_argument(
        "--finding",
        action="append",
        dest="findings",
        help="Explicit finding id; may be repeated.",
    )
    validate_parser.add_argument(
        "--environment",
        choices=("auto", "reuse", "build"),
        default="auto",
        help="Environment handling; defaults to auto.",
    )
    validate_parser.add_argument(
        "--rerun",
        action="store_true",
        help="Discard previous validation findings before running.",
    )
    report_parser = commands.add_parser(
        "report", help="Generate local report materials from an existing run record."
    )
    report_parser.add_argument("--run-file", required=True, type=Path, help="Existing run.json.")
    report_parser.add_argument(
        "--finding",
        action="append",
        dest="findings",
        help="Explicit confirmed finding id; may be repeated.",
    )
    report_parser.add_argument(
        "--rerun",
        action="store_true",
        help="Discard previous report findings and submissions before running.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        if args.command == "run":
            state = run(args.repository, args.output_dir, args.audit_mode)
        elif args.command == "discover":
            state = run_discover(args.run_file)
        elif args.command == "audit":
            state = run_audit(args.run_file, args.mode)
        elif args.command == "environment":
            state = run_environment(args.run_file, rebuild=args.rebuild)
        elif args.command == "validate":
            state = run_validate(
                args.run_file,
                finding_ids=args.findings,
                environment_mode=args.environment,
                rerun=args.rerun,
            )
        elif args.command == "report":
            state = run_report(
                args.run_file,
                finding_ids=args.findings,
                rerun=args.rerun,
            )
        else:
            return 2
    except Exception as error:
        print(json.dumps({"status": "failed", "error": str(error)}, ensure_ascii=False))
        return 1

    print(json.dumps(state, ensure_ascii=False, indent=2))
    if args.command == "environment" and state.get("environment", {}).get("status") != "ready":
        return 1
    if args.command == "validate" and state.get("validation", {}).get("status") not in {
        "complete",
        "partial",
    }:
        return 1
    if args.command == "report" and state.get("report", {}).get("status") not in {
        "complete",
        "partial",
    }:
        return 1
    return 0
