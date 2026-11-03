#!/usr/bin/env python3
"""Clone, pin, and verify the analysis targets listed in targets/registry.json.

Each target is cloned with full history (the init stage's security-history
subgraph reviews commits and builds patch graphs, so a shallow clone would
cripple it) and then detached at the pinned SHA recorded in the registry.

Usage:
    python3 scripts/fetch_targets.py            # clone/fetch + checkout + refresh source_profile
    python3 scripts/fetch_targets.py --check    # verify only, clone nothing
    python3 scripts/fetch_targets.py --only halo
    python3 scripts/fetch_targets.py --refresh-pins   # move pins to upstream default-branch HEAD

Exit code is 0 only when every target ends up at its pinned SHA.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = ROOT / "targets" / "registry.json"

# Directories that never contain first-party source worth counting.
EXCLUDED_DIRS = {
    ".codegraph",
    ".git",
    ".yasa",
    ".yasa-vulnagent",
    ".venv",
    ".uv-cache",
    ".uv-python",
    "node_modules",
    "vendor",
    "third_party",
    "dist",
    "build",
}

SOURCE_EXTS = (".java", ".py", ".js", ".ts", ".go", ".php")


def log(message: str) -> None:
    print(f"[targets] {message}", flush=True)


def git(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
    )


def git_ok(args: list[str], cwd: Path | None = None) -> str:
    result = git(args, cwd)
    if result.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed ({result.returncode}): {result.stderr.strip()}"
        )
    return result.stdout.strip()


def gh_json(args: list[str]) -> object | None:
    if shutil.which("gh") is None:
        return None
    result = subprocess.run(["gh", "api", *args], capture_output=True, text=True)
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def load_registry() -> dict:
    return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))


def save_registry(registry: dict) -> bool:
    text = json.dumps(registry, indent=2, ensure_ascii=False) + "\n"
    if REGISTRY_PATH.read_text(encoding="utf-8") == text:
        return False
    REGISTRY_PATH.write_text(text, encoding="utf-8")
    return True


def ensure_clone(target: dict) -> Path:
    local = ROOT / target["local_dir"]
    url = target["url"]
    if local.is_dir():
        if not (local / ".git").is_dir():
            raise RuntimeError(f"{local} exists but is not a git repository")
        origin = git_ok(["remote", "get-url", "origin"], cwd=local)
        if origin.rstrip("/") != url.rstrip("/"):
            raise RuntimeError(
                f"{local} points at {origin}, expected {url} (refusing to change the remote)"
            )
        log(f"{target['id']}: reusing existing clone")
        return local
    log(f"{target['id']}: cloning {url} (full history)")
    result = git(["clone", "--no-checkout", url, str(local)])
    if result.returncode != 0:
        raise RuntimeError(f"git clone failed for {url}: {result.stderr.strip()}")
    return local


def pin(local: Path, sha: str) -> str:
    git_ok(["fetch", "--all", "--tags", "--prune"], cwd=local)
    exists = git(["cat-file", "-e", f"{sha}^{{commit}}"], cwd=local)
    if exists.returncode != 0:
        # The pin may be newer than anything the default fetch brought down.
        git(["fetch", "origin", sha], cwd=local)
    git_ok(["checkout", "--force", "--detach", sha], cwd=local)
    head = git_ok(["rev-parse", "HEAD"], cwd=local)
    if head != sha:
        raise RuntimeError(f"checked-out HEAD {head} != pinned sha {sha}")
    return head


def source_profile(local: Path) -> dict:
    by_ext = {ext: 0 for ext in SOURCE_EXTS}
    for path in local.rglob("*"):
        if not path.is_file():
            continue
        if any(part in EXCLUDED_DIRS for part in path.relative_to(local).parts):
            continue
        suffix = path.suffix.lower()
        if suffix in by_ext:
            by_ext[suffix] += 1
    by_ext = {ext: count for ext, count in by_ext.items() if count}
    return {"yasa_files": sum(by_ext.values()), "by_ext": by_ext}


def tree_size(local: Path, include_git: bool = False) -> int:
    """Size of the working tree (default) or of .git only.

    Runtime caches the analyzer writes into a target (.yasa/, .yasa-vulnagent/)
    are excluded, so this reports the checkout size rather than cache growth.
    """
    total = 0
    for path in local.rglob("*"):
        rel = path.relative_to(local).parts
        if not rel:
            continue
        in_git = rel[0] == ".git"
        if in_git != include_git:
            continue
        if not in_git and rel[0] in EXCLUDED_DIRS:
            continue
        if path.is_file() and not path.is_symlink():
            try:
                total += path.stat().st_size
            except OSError:
                pass
    return total


def human(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.1f}{unit}"
        value /= 1024
    return f"{value:.1f}GB"


def refresh_pins(registry: dict) -> None:
    for target in registry["targets"]:
        repo = target["repo"]
        info = gh_json([f"repos/{repo}"])
        commit = gh_json([f"repos/{repo}/commits/{target['default_branch']}"])
        if not isinstance(info, dict) or not isinstance(commit, dict):
            log(f"{target['id']}: could not refresh pin (gh unavailable or rate limited), keeping {target['pinned_sha'][:12]}")
            continue
        target["default_branch"] = info.get("default_branch") or target["default_branch"]
        target["pinned_sha"] = commit.get("sha") or target["pinned_sha"]
        committed = (commit.get("commit") or {}).get("committer") or {}
        target["pinned_at"] = committed.get("date") or target.get("pinned_at")

        metrics = target["selection"].setdefault("metrics", {})
        if info.get("pushed_at"):
            metrics["pushed_at"] = info["pushed_at"]
        if isinstance(info.get("stargazers_count"), int):
            metrics["stars"] = info["stargazers_count"]
        if isinstance(info.get("open_issues_count"), int):
            metrics["open_issues"] = info["open_issues_count"]

        advisories = gh_json([f"repos/{repo}/security-advisories?per_page=100"])
        if isinstance(advisories, list):
            published = sorted(
                item["published_at"] for item in advisories if item.get("published_at")
            )
            metrics["advisories"] = len(advisories)
            if published:
                metrics["last_advisory"] = published[-1][:10]
        log(f"{target['id']}: pin -> {target['pinned_sha'][:12]} ({target['pinned_at']})")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify clones and pins, change nothing")
    parser.add_argument("--only", action="append", dest="only", help="limit to specific target id")
    parser.add_argument(
        "--refresh-pins",
        action="store_true",
        help="move pinned SHAs (and metrics) to upstream default-branch HEAD",
    )
    args = parser.parse_args()

    registry = load_registry()
    targets = registry["targets"]
    if args.only:
        wanted = set(args.only)
        targets = [item for item in targets if item["id"] in wanted]
        missing = wanted - {item["id"] for item in targets}
        if missing:
            log(f"unknown target id(s): {', '.join(sorted(missing))}")
            return 2

    if args.refresh_pins:
        refresh_pins(registry)
        if save_registry(registry):
            log(f"registry updated: {REGISTRY_PATH.relative_to(ROOT)}")

    failures = 0
    summaries = []
    for target in targets:
        local = ROOT / target["local_dir"]
        try:
            if args.check:
                if not (local / ".git").is_dir():
                    raise RuntimeError(f"missing clone at {target['local_dir']}; run without --check first")
            else:
                local = ensure_clone(target)
                pin(local, target["pinned_sha"])

            head = git_ok(["rev-parse", "HEAD"], cwd=local)
            if head != target["pinned_sha"]:
                raise RuntimeError(f"HEAD {head} != pinned {target['pinned_sha']}")

            profile = source_profile(local)
            if not args.check:
                target["selection"]["source_profile"] = profile

            summary = {
                "id": target["id"],
                "sha": head[:12],
                "pinned": True,
                "yasa_files": profile["yasa_files"],
                "by_ext": profile["by_ext"],
                "worktree": human(tree_size(local)),
                "git_dir": human(tree_size(local, include_git=True)),
            }
            summaries.append(summary)
            log(
                f"{target['id']}: pinned {head[:12]} | yasa_files={profile['yasa_files']} "
                f"| worktree={summary['worktree']} | .git={summary['git_dir']}"
            )
        except RuntimeError as error:
            failures += 1
            summaries.append({"id": target["id"], "pinned": False, "error": str(error)})
            log(f"{target['id']}: FAILED {error}")

    if not args.check and save_registry(registry):
        log(f"registry updated: {REGISTRY_PATH.relative_to(ROOT)}")

    print(json.dumps({"targets": summaries, "failures": failures}, ensure_ascii=False, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
