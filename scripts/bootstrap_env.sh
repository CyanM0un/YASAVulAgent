#!/usr/bin/env bash
# Bootstrap the local runtime for YASAVulAgent:
#   1. uv-managed Python >= 3.10 virtualenv (system python3 is 3.8 here)
#   2. editable install of the project (provides yasa-vulnagent + yasa_mcp deps)
#   3. YASA native tool tree under tools/yasa/<platform>/
#   4. smoke checks
#
# Idempotent: re-running skips work that is already in place.
# All writable state stays inside the repository (the sandbox only allows that).
#
# The native tree needs four tools (see yasa_mcp/layout/binary_layout.py):
#
#   <platform>/yasa/yasa              antgroup/YASA-Engine   (engine + uast deps)
#   <platform>/ripgrep/rg             BurntSushi/ripgrep
#   <platform>/scc/scc                boyter/scc
#   <platform>/codegraph/bin/codegraph colbymchenry/codegraph
#
# YASA-Engine's own releases ship the engine only, so the other three are pulled
# from their upstream release pages (all public, listed in tools/yasa-mcp/NOTICE.md).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON_VERSION="${PYTHON_VERSION:-3.12}"
YASA_PLATFORM="${YASA_PLATFORM:-linux-x86-64}"
ENGINE_VERSION="${ENGINE_VERSION:-v0.3.3}"
CODEGRAPH_VERSION="${CODEGRAPH_VERSION:-v1.6.2}"
RIPGREP_VERSION="${RIPGREP_VERSION:-15.2.0}"
SCC_VERSION="${SCC_VERSION:-v4.1.0}"
YASA_SOURCE_PATH="${YASA_SOURCE_PATH:-tools/yasa-mcp}"
YASA_BIN_PATH="${YASA_BIN_PATH:-tools/yasa}"

# HOME is read-only in this sandbox, so uv's cache and managed interpreters must
# live inside the repository (both are gitignored).
export UV_CACHE_DIR="${UV_CACHE_DIR:-$ROOT/.uv-cache}"
export UV_PYTHON_INSTALL_DIR="${UV_PYTHON_INSTALL_DIR:-$ROOT/.uv-python}"
export ROOT YASA_PLATFORM YASA_BIN_PATH

mkdir -p "$UV_CACHE_DIR" "$UV_PYTHON_INSTALL_DIR"

log() { printf '[bootstrap] %s\n' "$*"; }
die() { printf '[bootstrap] ERROR: %s\n' "$*" >&2; exit 1; }

# git may be configured with an HTTP proxy that curl does not inherit; without
# this the release-asset download hangs even though `git clone` works.
GIT_PROXY="$(git config --global --get http.proxy || true)"
if [ -n "${GIT_PROXY:-}" ] && [ -z "${https_proxy:-}" ]; then
    export http_proxy="$GIT_PROXY" https_proxy="$GIT_PROXY"
    log "using git proxy $GIT_PROXY for release downloads"
fi

# ---------------------------------------------------------------- 1. venv
log "1/4 virtualenv (.venv, python $PYTHON_VERSION)"
if [ ! -x "$ROOT/.venv/bin/python" ]; then
    uv venv --python "$PYTHON_VERSION" .venv \
        || die "uv venv failed (need network for a managed CPython $PYTHON_VERSION)"
fi
"$ROOT/.venv/bin/python" -V

# ------------------------------------------------------- 2. project install
log "2/4 editable install"
uv pip install --python "$ROOT/.venv/bin/python" -e . \
    || die "dependency installation failed (PyPI unreachable?)"

# ------------------------------------------------- 3. YASA native binaries
log "3/4 YASA native binaries -> $YASA_BIN_PATH/$YASA_PLATFORM"
PLATFORM_DIR="$ROOT/$YASA_BIN_PATH/$YASA_PLATFORM"
if [ -f "$PLATFORM_DIR/yasa/yasa" ] \
   && [ -f "$PLATFORM_DIR/ripgrep/rg" ] \
   && [ -f "$PLATFORM_DIR/scc/scc" ] \
   && [ -f "$PLATFORM_DIR/codegraph/bin/codegraph" ]; then
    log "    already complete, skipping download"
else
    DL_DIR="$ROOT/.yasa-dl"
    mkdir -p "$DL_DIR"
    fetch() { # fetch <url> <dest-name>
        local url="$1" name="$2"
        if [ -s "$DL_DIR/$name" ]; then
            log "    reusing $name"
            return 0
        fi
        log "    fetching $url"
        if curl -fSL --retry 3 --retry-delay 2 --connect-timeout 20 \
                -o "$DL_DIR/$name.part" "$url"; then
            mv "$DL_DIR/$name.part" "$DL_DIR/$name"
            return 0
        fi
        rm -f "$DL_DIR/$name.part"
        log "    FAILED: $url"
        return 1
    }

    fetch "https://github.com/antgroup/YASA-Engine/releases/download/$ENGINE_VERSION/yasa-linux-x64.zip" "yasa-linux-x64.zip" \
        || die "could not download the YASA engine archive"
    fetch "https://github.com/BurntSushi/ripgrep/releases/download/$RIPGREP_VERSION/ripgrep-$RIPGREP_VERSION-x86_64-unknown-linux-musl.tar.gz" "ripgrep.tar.gz" \
        || die "could not download ripgrep"
    fetch "https://github.com/boyter/scc/releases/download/$SCC_VERSION/scc_Linux_x86_64.tar.gz" "scc.tar.gz" \
        || die "could not download scc"
    fetch "https://github.com/colbymchenry/codegraph/releases/download/$CODEGRAPH_VERSION/codegraph-linux-x64.tar.gz" "codegraph-linux-x64.tar.gz" \
        || die "could not download codegraph"

    "$ROOT/.venv/bin/python" - "$ROOT" <<'PY'
"""Assemble the native tool tree that YASA-MCP expects.

Layout contract (yasa_mcp/layout/binary_layout.py + each tool's *_bin_layout.py):
    <platform>/yasa/yasa                 + <platform>/yasa/deps/uast4go|uast4py
    <platform>/ripgrep/rg
    <platform>/scc/scc
    <platform>/codegraph/bin/codegraph
"""
import os
import shutil
import stat
import sys
import tarfile
import zipfile
from pathlib import Path

root = Path(sys.argv[1])
platform = os.environ["YASA_PLATFORM"]
bin_root = root / os.environ["YASA_BIN_PATH"]
dl = root / ".yasa-dl"
work = dl / "extract"


def die(msg):
    print(f"[bootstrap] ERROR: {msg}", file=sys.stderr)
    raise SystemExit(1)


def extract(archive: Path, dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(dest)
    else:
        with tarfile.open(archive) as tf:
            tf.extractall(dest)
    return dest


def only_file(base: Path, name: str) -> Path:
    matches = [p for p in base.rglob(name) if p.is_file()]
    if not matches:
        die(f"'{name}' not found inside {base.relative_to(root)}")
    return matches[0]


if work.exists():
    shutil.rmtree(work)
work.mkdir(parents=True)

target = bin_root / platform
if target.exists():
    shutil.rmtree(target)
target.mkdir(parents=True)

# --- yasa engine + uast deps -------------------------------------------
engine = extract(dl / "yasa-linux-x64.zip", work / "engine")
yasa_dir = target / "yasa"
yasa_dir.mkdir()
engine_bin = engine / "yasa-engine-linux-x64"
if not engine_bin.is_file():
    engine_bin = only_file(engine, "yasa")
shutil.copy2(engine_bin, yasa_dir / "yasa")

deps = yasa_dir / "deps"
deps.mkdir()
for source, name in (("uast4go*", "uast4go"), ("uast4py*", "uast4py")):
    shutil.copy2(only_file(engine, source), deps / name)

for extra in ("node_modules", "example-rule-config"):
    if (engine / extra).is_dir():
        shutil.copytree(engine / extra, yasa_dir / extra, symlinks=True)

# --- ripgrep ------------------------------------------------------------
rg_root = extract(dl / "ripgrep.tar.gz", work / "ripgrep")
(target / "ripgrep").mkdir()
shutil.copy2(only_file(rg_root, "rg"), target / "ripgrep" / "rg")

# --- scc ----------------------------------------------------------------
scc_root = extract(dl / "scc.tar.gz", work / "scc")
(target / "scc").mkdir()
shutil.copy2(only_file(scc_root, "scc"), target / "scc" / "scc")

# --- codegraph (node runtime + bundle) ----------------------------------
cg_root = extract(dl / "codegraph-linux-x64.tar.gz", work / "codegraph")
launcher = only_file(cg_root, "codegraph")
bundle = launcher.parent.parent  # .../<bundle>/bin/codegraph
if bundle == cg_root or not (bundle / "lib").is_dir():
    candidates = [p for p in cg_root.rglob("bin") if (p / "codegraph").is_file()]
    if not candidates:
        die("codegraph bundle with bin/codegraph was not found")
    bundle = candidates[0].parent
shutil.copytree(bundle, target / "codegraph", symlinks=True)

# --- permissions --------------------------------------------------------
executables = [
    target / "yasa" / "yasa",
    deps / "uast4go",
    deps / "uast4py",
    target / "ripgrep" / "rg",
    target / "scc" / "scc",
    target / "codegraph" / "bin" / "codegraph",
    target / "codegraph" / "node",
]
for path in executables:
    if path.is_file():
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    else:
        print(f"[bootstrap]     WARNING: missing {path.relative_to(root)}", file=sys.stderr)

print(f"[bootstrap]     installed -> {target.relative_to(root)}")
PY

    rm -rf "$ROOT/.yasa-dl"
fi

# ------------------------------------------------------------ 4. smoke test
log "4/4 smoke checks"
for required in "yasa/yasa" "ripgrep/rg" "scc/scc" "codegraph/bin/codegraph"; do
    [ -e "$PLATFORM_DIR/$required" ] || die "missing native tool: $PLATFORM_DIR/$required"
done

"$PLATFORM_DIR/yasa/yasa" --version >/dev/null 2>&1 \
    || log "    note: 'yasa --version' did not exit 0"
"$PLATFORM_DIR/ripgrep/rg" --version >/dev/null || die "ripgrep does not run"
"$PLATFORM_DIR/scc/scc" --version >/dev/null || die "scc does not run"
"$PLATFORM_DIR/codegraph/bin/codegraph" --version >/dev/null 2>&1 \
    || log "    note: 'codegraph --version' did not exit 0"

PYTHONPATH="$ROOT/$YASA_SOURCE_PATH/src${PYTHONPATH:+:$PYTHONPATH}" \
    "$ROOT/.venv/bin/python" -m yasa_mcp --help >/dev/null \
    || die "yasa_mcp is not importable; check PYTHONPATH=$YASA_SOURCE_PATH/src"

log "OK"
log "  venv     : $ROOT/.venv"
log "  yasa bin : $PLATFORM_DIR"
log "  next     : python3 scripts/fetch_targets.py && .venv/bin/python scripts/preflight_yasa.py"
