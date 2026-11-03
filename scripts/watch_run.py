#!/usr/bin/env python3
"""Read-only status view of one YASAVulAgent run.

Built for a 25-minute reporting cadence: one command gives stage progress,
live counters, token spend, log health and a RUNNING/STUCK/DONE/FAILED verdict.

Usage:
    python3 scripts/watch_run.py healthchecks
    python3 scripts/watch_run.py healthchecks --json
    python3 scripts/watch_run.py --run-dir /path/to/run
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STAGE_NAMES = ("init", "discover", "audit", "validate", "report")
STUCK_AFTER_S = 600.0
TAIL_LINES = 400


def log(message: str) -> None:
    print(message, flush=True)


def parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def human_duration(seconds: float) -> str:
    seconds = max(0.0, seconds)
    hours, rest = divmod(int(seconds), 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours}h{minutes:02d}m"
    if minutes:
        return f"{minutes}m{secs:02d}s"
    return f"{secs}s"


def load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def pick_numbers(value: dict, prefix: str = "") -> list[str]:
    """Turn a state/index object into compact ``key=n`` facts."""
    facts: list[str] = []
    for key, item in value.items():
        if key in {"schema_version", "version"}:
            continue
        label = f"{prefix}{key}"
        if isinstance(item, list):
            facts.append(f"{label}={len(item)}")
        elif isinstance(item, dict):
            facts.append(f"{label}={len(item)}")
        elif isinstance(item, bool):
            facts.append(f"{label}={'true' if item else 'false'}")
        elif isinstance(item, (int, float)):
            facts.append(f"{label}={item}")
        elif isinstance(item, str) and len(item) <= 60:
            facts.append(f"{label}={item!r}")
    return facts


def run_dir_for(target: str) -> Path | None:
    root = ROOT / "targets" / target / ".yasa-vulnagent" / "runs"
    if not root.is_dir():
        return None
    candidates = [item for item in root.iterdir() if item.is_dir()]
    if not candidates:
        return None
    return max(candidates, key=lambda item: item.stat().st_mtime)


def stage_rows(run_state: dict, run_dir: Path) -> list[dict]:
    recorded: dict[str, dict] = {}
    for item in run_state.get("stages", []) or []:
        if isinstance(item, dict) and item.get("name"):
            recorded[str(item["name"])] = item
    rows = []
    for name in STAGE_NAMES:
        record = recorded.get(name, {})
        stage_file = run_dir / "stages" / name / "stage.json"
        if stage_file.is_file():
            fresh = load_json(stage_file)
            if fresh:
                record = fresh
        started = parse_time(record.get("started_at"))
        finished = parse_time(record.get("finished_at"))
        duration = None
        if started:
            duration = ((finished or datetime.now(timezone.utc)) - started).total_seconds()
        rows.append(
            {
                "name": name,
                "status": record.get("status") or "pending",
                "duration_s": round(duration, 1) if duration is not None else None,
                "message": str(record.get("message") or "")[:160],
                "started_at": record.get("started_at"),
                "finished_at": record.get("finished_at"),
            }
        )
    return rows


def usage_totals(run_dir: Path) -> list[dict]:
    rows = []
    for path in sorted((run_dir / "stages").glob("*/usage.json")):
        data = load_json(path)
        if not data:
            continue
        # schema: {"totals": {...}, "limits": {...}, "by_stage": {...}, "records": [...]}
        totals = data.get("totals") if isinstance(data.get("totals"), dict) else data
        rows.append(
            {
                "stage": path.parent.name,
                "calls": totals.get("calls", 0),
                "prompt_tokens": totals.get("prompt_tokens", 0),
                "completion_tokens": totals.get("completion_tokens", 0),
                "total_tokens": totals.get("total_tokens", 0),
                "retries": totals.get("retries", 0),
                "cost": totals.get("cost", 0),
            }
        )
    return rows


def log_health(run_dir: Path) -> dict:
    path = run_dir / "run.log"
    if not path.is_file():
        return {"exists": False}
    stat = path.stat()
    age = time.time() - stat.st_mtime
    tracebacks = 0
    errors: list[str] = []
    warnings = 0
    model_calls = 0
    last_heartbeat = ""
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if "chat/completions" in line:
                model_calls += 1
        handle.seek(0)
        lines = handle.readlines()[-TAIL_LINES:]
    for line in lines:
        if "Traceback (most recent call last)" in line:
            tracebacks += 1
        if " ERROR " in line:
            errors.append(line.strip()[:200])
        if " WARNING " in line:
            warnings += 1
        if "progress heartbeat" in line:
            last_heartbeat = line.strip()[:200]
    return {
        "exists": True,
        "path": str(path),
        "bytes": stat.st_size,
        "age_s": round(age, 1),
        "tracebacks": tracebacks,
        "model_calls": model_calls,
        "errors": errors[-3:],
        "warnings": warnings,
        "last_heartbeat": last_heartbeat,
    }


def verdict(run_state: dict, log_info: dict) -> str:
    """Liveness comes from the heartbeat writes, not from pgrep.

    Each shell call here runs in its own PID namespace (bwrap --unshare-pid), so
    a process started by another call is invisible to pgrep. run.log is appended
    every ~30s by the heartbeat thread, which is the reliable signal.
    """
    status = str(run_state.get("status") or "unknown")
    if status == "failed" or run_state.get("error"):
        return "FAILED"
    if status in {"complete", "partial", "blocked"}:
        return f"DONE:{status}"
    age = log_info.get("age_s")
    if not log_info.get("exists"):
        return "NO_LOG"
    if age is None:
        return "RUNNING"
    if age > STUCK_AFTER_S:
        return "STUCK"
    if age > 120:
        return "STALLING"
    return "RUNNING"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", nargs="?", help="target id, e.g. healthchecks")
    parser.add_argument("--run-dir", help="explicit run directory")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    if args.run_dir:
        run_dir = Path(args.run_dir).expanduser().resolve()
        target = run_dir.parent.parent.parent.parent.name if run_dir else ""
    elif args.target:
        run_dir = run_dir_for(args.target)
        target = args.target
    else:
        parser.error("provide a target id or --run-dir")
        return 2

    if run_dir is None or not (run_dir / "run.json").is_file():
        payload = {"target": target, "run_dir": str(run_dir) if run_dir else None, "verdict": "NO_RUN"}
        print(json.dumps(payload, ensure_ascii=False) if args.json else f"[{target}] NO_RUN")
        return 1

    run_state = load_json(run_dir / "run.json")
    stages = stage_rows(run_state, run_dir)
    started = parse_time(run_state.get("started_at"))
    finished = parse_time(run_state.get("finished_at"))
    elapsed = ((finished or datetime.now(timezone.utc)) - started).total_seconds() if started else None
    usage = usage_totals(run_dir)
    log_info = log_health(run_dir)
    state_label = verdict(run_state, log_info)

    current = str(run_state.get("current_stage") or "")
    live_facts: list[str] = []
    for name in [current, *STAGE_NAMES]:
        if not name:
            continue
        stage_dir = run_dir / "stages" / name
        for candidate in ("state.json", "index.json"):
            path = stage_dir / candidate
            if path.is_file():
                live_facts = pick_numbers(load_json(path))[:14]
                if live_facts:
                    break
        if live_facts:
            break

    totals = {
        "calls": sum(int(row["calls"] or 0) for row in usage),
        "prompt_tokens": sum(int(row["prompt_tokens"] or 0) for row in usage),
        "completion_tokens": sum(int(row["completion_tokens"] or 0) for row in usage),
        "total_tokens": sum(int(row["total_tokens"] or 0) for row in usage),
        "retries": sum(int(row["retries"] or 0) for row in usage),
    }

    payload = {
        "target": target,
        "run_id": run_state.get("run_id"),
        "run_dir": str(run_dir),
        "status": run_state.get("status"),
        "current_stage": current,
        "elapsed_s": round(elapsed, 1) if elapsed is not None else None,
        "stages": stages,
        "live": live_facts,
        "usage": usage,
        "usage_totals": totals,
        "log": log_info,
        "verdict": state_label,
        "error": run_state.get("error"),
    }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False))
        return 0

    log(f"[{target}] {state_label} | run {run_state.get('run_id')} | 已用 {human_duration(elapsed or 0)}")
    log(f"  stage: {current or '-'}")
    for row in stages:
        duration = human_duration(row["duration_s"]) if row["duration_s"] is not None else "-"
        log(f"  - {row['name']:9} {row['status']:9} {duration:>7}  {row['message'][:90]}")
    if live_facts:
        log("  实况: " + ", ".join(live_facts))
    log(
        f"  tokens: total={totals['total_tokens']} (in {totals['prompt_tokens']} / out "
        f"{totals['completion_tokens']}) calls={totals['calls']} retries={totals['retries']}"
    )
    if log_info.get("exists"):
        log(
            f"  log: {log_info['bytes']}B, 心跳 {human_duration(log_info['age_s'])} 前, "
            f"model_calls={log_info['model_calls']}, traceback={log_info['tracebacks']}, "
            f"warn={log_info['warnings']}"
        )
        for line in log_info["errors"]:
            log(f"    ERROR {line}")
    if run_state.get("error"):
        log(f"  error: {str(run_state['error'])[:400]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
