#!/usr/bin/env python3
"""G1 preflight: prove YASA works on each analysis target.

This runs exactly what the init stage's `yasa` node runs (see
src/yasa_vulnagent/stages/init/yasa/runner.py): `yasa_mcp init`, `yasa_mcp
status`, and a `get_function(name="main")` MCP probe. An empty probe result is
fine — the probe only proves the service answers, not that `main` exists.

It deliberately does not create a run record or execute documents/cwe/
security_history, so it is cheap enough to iterate on.

Run inside the project venv:
    .venv/bin/python scripts/preflight_yasa.py
    .venv/bin/python scripts/preflight_yasa.py --only healthchecks
    .venv/bin/python scripts/preflight_yasa.py --skip-mcp
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from yasa_vulnagent.config import load_settings, resolve_project_path  # noqa: E402
from yasa_vulnagent.stages.init.yasa.runner import YasaError, YasaRunner  # noqa: E402

REGISTRY_PATH = ROOT / "targets" / "registry.json"


def log(message: str) -> None:
    print(f"[preflight] {message}", flush=True)


def ensure_writable_home() -> None:
    """yasa_mcp writes ~/.yasamcp/{logs,config.json}; fall back to a repo-local HOME.

    The sandbox here mounts $HOME read-only, which makes yasa_mcp abort before it
    even looks at the binary tree. Only redirect when the real HOME cannot be used.
    """
    home = os.environ.get("HOME")
    if home:
        try:
            (Path(home) / ".yasamcp").mkdir(parents=True, exist_ok=True)
            return
        except OSError:
            pass
    local = ROOT / ".yasa-home"
    local.mkdir(parents=True, exist_ok=True)
    os.environ["HOME"] = str(local)
    log(f"HOME is not writable; using {local}")


def seed_binary_config(bin_path: Path) -> None:
    """Point yasa_mcp's persisted binary path at this checkout.

    The CLI group callback calls ``BinaryManager.load_from_persisted()`` before it
    parses ``--bin``, so a missing or stale ``~/.yasamcp/config.json`` aborts init
    with "Path .../<platform> does not exist".
    """
    config = Path(os.environ.get("HOME", "")) / ".yasamcp" / "config.json"
    config.parent.mkdir(parents=True, exist_ok=True)
    try:
        current = json.loads(config.read_text(encoding="utf-8")).get("binary_path", "")
    except (OSError, json.JSONDecodeError, AttributeError):
        current = ""
    usable = any((p / "yasa" / "yasa").is_file() for p in bin_path.glob("*"))
    if current and usable and Path(current) == bin_path:
        return
    config.write_text(json.dumps({"binary_path": str(bin_path)}), encoding="utf-8")
    log(f"seeded {config} -> {bin_path}")


def binary_hint(bin_path: Path) -> str | None:
    """Return the resolved YASA executable, or None if the layout is incomplete."""
    for platform_root in sorted(bin_path.glob("*")):
        candidate = platform_root / "yasa" / "yasa"
        if candidate.is_file():
            return str(candidate.relative_to(ROOT)) if candidate.is_relative_to(ROOT) else str(candidate)
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", action="append", dest="only", help="limit to specific target id")
    parser.add_argument("--skip-mcp", action="store_true", help="run init+status only, skip the MCP probe")
    args = parser.parse_args()
    ensure_writable_home()

    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    targets = registry["targets"]
    if args.only:
        wanted = set(args.only)
        targets = [item for item in targets if item["id"] in wanted]
        missing = wanted - {item["id"] for item in targets}
        if missing:
            log(f"unknown target id(s): {', '.join(sorted(missing))}")
            return 2

    settings = load_settings(ROOT / ".env")
    source_path = resolve_project_path(settings.yasa_source_path)
    bin_path = resolve_project_path(settings.yasa_bin_path)

    log(f"yasa source : {source_path}")
    log(f"yasa bin    : {bin_path}")
    executable = binary_hint(bin_path)
    if executable is None:
        log(f"ERROR: no <platform>/yasa/yasa under {bin_path}; run scripts/bootstrap_env.sh first")
        print("[preflight-json] " + json.dumps({"targets": [], "failures": len(targets)}, ensure_ascii=False))
        return 1
    log(f"yasa binary : {executable}")
    seed_binary_config(bin_path)

    runner = YasaRunner(
        source_path=source_path,
        bin_path=bin_path,
        init_timeout=settings.yasa_init_timeout,
        status_timeout=settings.yasa_status_timeout,
        mcp_timeout=settings.yasa_mcp_timeout,
    )

    results = []
    failures = 0
    for target in targets:
        local = ROOT / target["local_dir"]
        record: dict[str, object] = {"id": target["id"], "path": target["local_dir"]}
        started = time.monotonic()
        if not (local / ".git").is_dir():
            record.update({"ok": False, "error": "target clone missing; run scripts/fetch_targets.py"})
            failures += 1
            results.append(record)
            log(f"{target['id']}: FAILED missing clone")
            continue
        try:
            if args.skip_mcp:
                runner.initialize(local)
                status = runner.status(local)
                record.update(
                    {"ok": True, "status_valid": bool(status.get("valid")), "mcp": "skipped"}
                )
            else:
                outcome = runner.run(local)
                record.update(
                    {
                        "ok": bool(outcome.get("status_valid")),
                        "status_valid": bool(outcome.get("status_valid")),
                        "mcp_tool": outcome.get("mcp_tool"),
                        "mcp_result_count": outcome.get("mcp_result_count"),
                    }
                )
                if not record["ok"]:
                    failures += 1
                    log(f"{target['id']}: FAILED cache reported invalid")
                else:
                    log(
                        f"{target['id']}: OK mcp_result_count={record['mcp_result_count']}"
                    )
        except YasaError as error:
            failures += 1
            record.update({"ok": False, "error": str(error)[:4000]})
            log(f"{target['id']}: FAILED {str(error)[:400]}")
        except Exception as error:  # noqa: BLE001 - report anything, never abort the sweep
            failures += 1
            record.update({"ok": False, "error": f"{type(error).__name__}: {error}"[:4000]})
            log(f"{target['id']}: FAILED {type(error).__name__}: {str(error)[:400]}")
        finally:
            record["elapsed_s"] = round(time.monotonic() - started, 1)
        results.append(record)

    print("[preflight-json] " + json.dumps({"targets": results, "failures": failures}, ensure_ascii=False))
    log(f"done: {len(results) - failures}/{len(results)} targets OK")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
