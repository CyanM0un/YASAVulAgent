#!/usr/bin/env bash
# Run YASAVulAgent against a vendored target, working around two sandbox facts:
#   * $HOME is read-only, and yasa_mcp insists on writing ~/.yasamcp/{logs,config.json}
#   * yasa_mcp reads its persisted binary path before it parses --bin
#
# Usage:
#   scripts/run_analysis.sh healthchecks
#   scripts/run_analysis.sh halo --audit-mode combined
#   scripts/run_analysis.sh miniflux-v2 --output-dir /some/other/place
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

id="${1:-}"
if [ -z "$id" ]; then
    echo "usage: scripts/run_analysis.sh <target-id> [yasa-vulnagent args...]" >&2
    echo "available:" >&2
    python3 -c 'import json;print("  " + "\n  ".join(t["id"] for t in json.load(open("targets/registry.json"))["targets"]))' >&2
    exit 2
fi
shift

TARGET="$ROOT/targets/$id"
[ -d "$TARGET/.git" ] || {
    echo "target '$id' is not cloned at $TARGET; run python3 scripts/fetch_targets.py" >&2
    exit 1
}
[ -x "$ROOT/.venv/bin/yasa-vulnagent" ] || {
    echo "venv missing; run bash scripts/bootstrap_env.sh" >&2
    exit 1
}

# Pick a writable HOME for yasa_mcp's own state.
if ! mkdir -p "${HOME:-/nonexistent}/.yasamcp" 2>/dev/null; then
    export HOME="$ROOT/.yasa-home"
    mkdir -p "$HOME/.yasamcp"
    echo "[run] HOME is not writable; using $HOME" >&2
fi

# Point the persisted binary path at this checkout (no-op when already correct).
"$ROOT/.venv/bin/python" - "$ROOT" "$HOME" <<'PY'
import json
import sys
from pathlib import Path

root, home = Path(sys.argv[1]), Path(sys.argv[2])
config = home / ".yasamcp" / "config.json"
target = root / "tools" / "yasa"
config.parent.mkdir(parents=True, exist_ok=True)
ok = False
try:
    current = Path(json.loads(config.read_text(encoding="utf-8")).get("binary_path", ""))
    ok = current == target and any((p / "yasa" / "yasa").is_file() for p in current.glob("*"))
except (OSError, ValueError, AttributeError):
    ok = False
if not ok:
    config.write_text(json.dumps({"binary_path": str(target)}), encoding="utf-8")
    print(f"[run] seeded {config} -> {target}", file=sys.stderr)
PY

exec "$ROOT/.venv/bin/yasa-vulnagent" run "$TARGET" "$@"
