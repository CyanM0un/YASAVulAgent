You are planning a reproducible Docker environment for a security validation run.

Use only the provided read-only tools. Inspect the repository yourself:
- list the root and important directories;
- read README, CI, Makefile, build scripts, manifests, lockfiles, and entrypoints;
- decide the build system and a smoke command that proves the environment starts.

Do not run shell commands. Do not edit files. Do not guess file contents.
Every inspection evidence item must point to a file range you actually read with `read_file`.

Return one JSON object only, with this shape:

{
  "status": "ready" | "blocked",
  "base_image": "python:3.12-slim",
  "dockerfile": [
    {"instruction": "FROM", "arguments": "python:3.12-slim"},
    {"instruction": "WORKDIR", "arguments": "/workspace"},
    {"instruction": "COPY", "arguments": ". /workspace"},
    {"instruction": "RUN", "arguments": "python -m pip install --no-cache-dir -r requirements.txt"}
  ],
  "smoke_commands": [["python", "-m", "pytest", "--collect-only", "-q"]],
  "inspection": {
    "languages": ["python"],
    "build_system": "pip",
    "evidence": [
      {"path": "pyproject.toml", "start_line": 1, "end_line": 20, "reason": "project metadata"}
    ],
    "unknowns": []
  },
  "assumptions": [],
  "gaps": [],
  "confidence": "low" | "medium" | "high",
  "why": "short rationale"
}

Rules:
- If no Dockerfile exists, generate one from the repository evidence.
- Use a single final runtime stage; multi-stage builds are allowed only when the evidence requires them.
- `COPY` and `ADD` sources must be relative to the repository and must not name `.env`, keys, credentials, or the Docker socket.
- `smoke_commands` are argv arrays, never shell strings. They must run inside the image without services.
- Do not use `sudo`, `nsenter`, `mount`, `pivot_root`, host paths, Docker sockets, or privileged flags.
- Build-time network access is allowed for dependency installation; smoke has no network.
- If the repository cannot be built safely or the stack is unknowable, return `status: "blocked"` and explain the gap. Do not invent a command.
- When revising a plan, include `changes` and `based_on`, and change only what the diagnosis or gate feedback requires.
- Keep the context small: use paginated reads and cite only the ranges you need.
