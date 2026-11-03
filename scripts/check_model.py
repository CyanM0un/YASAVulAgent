#!/usr/bin/env python3
"""Probe the configured LLM endpoint with one structured-JSON call.

Reads .env exactly like the CLI does, so a green result means the whole model
path works: base_url + api_key + model id + ChatOpenAI plumbing + JSON shaping.

Usage:
    .venv/bin/python scripts/check_model.py [--model NAME] [--timeout SEC]

Exit codes: 0 ok, 1 model call failed, 2 configuration missing.
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

from yasa_vulnagent.config import load_settings  # noqa: E402

PROMPT = (
    "You are a security auditor. Reply with ONLY a JSON object, no prose, with keys "
    'task_id (string), verdict ("vulnerable"|"clean"), and cwe (string). '
    "Evidence: a Django view passes request.GET['next'] to redirect() without validation."
)


def log(message: str) -> None:
    print(f"[model] {message}", flush=True)


def parse_json(content: str) -> dict | None:
    text = content.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[-1]
    text = text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    try:
        value = json.loads(text)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", help="override LLM_MODEL for this probe")
    parser.add_argument("--timeout", type=float, default=120.0)
    args = parser.parse_args()

    settings = load_settings(ROOT / ".env")
    model = args.model or settings.model
    if not settings.api_key:
        log("ERROR: LLM_API_KEY is empty")
        return 2
    if not settings.base_url:
        log("ERROR: LLM_BASE_URL is empty")
        return 2

    try:
        from langchain_openai import ChatOpenAI
    except ImportError:
        log("ERROR: langchain-openai is missing; run scripts/bootstrap_env.sh")
        return 2

    log(f"base_url : {settings.base_url}")
    log(f"model    : {model}")
    client = ChatOpenAI(
        model=model,
        api_key=settings.api_key,
        base_url=settings.base_url,
        timeout=args.timeout,
        max_retries=0,
    )

    started = time.time()
    try:
        message = client.invoke(PROMPT)
    except Exception as exc:  # noqa: BLE001 - probe must report any failure
        log(f"FAILED after {time.time() - started:.1f}s: {type(exc).__name__}: {str(exc)[:400]}")
        return 1

    elapsed = time.time() - started
    content = message.content if isinstance(message.content, str) else str(message.content)
    usage = message.usage_metadata or {}
    parsed = parse_json(content)

    log(f"latency  : {elapsed:.1f}s")
    log(f"tokens   : in={usage.get('input_tokens')} out={usage.get('output_tokens')}")
    if parsed is None:
        log(f"FAILED: response is not a JSON object: {content[:300]!r}")
        return 1
    log(f"OK       : json keys={sorted(parsed)}")
    print(
        json.dumps(
            {
                "ok": True,
                "model": model,
                "latency_s": round(elapsed, 2),
                "input_tokens": usage.get("input_tokens"),
                "output_tokens": usage.get("output_tokens"),
                "parsed": parsed,
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
