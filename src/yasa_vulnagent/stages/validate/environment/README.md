# environment build

Builds a Docker base environment from the live repository and records a reusable
image handle. It is an environment stage only; it does not run application
services or decide whether a vulnerability is valid.

## Flow

```text
preflight -> plan -> plan_gate -> build -> smoke -> snapshot -> finalize
                         |          |        |
                         +-> plan   +-> diagnose -> plan
```

- `preflight` checks the Docker CLI, daemon, socket and current groups.
- `plan` runs a read-only repository agent and returns one JSON plan.
- `plan_gate` rejects unsafe plans and warns about quality risks.
- `build` copies a filtered context and runs `docker build` with fixed flags.
- `smoke` runs argv commands with network disabled, capabilities dropped,
  `no-new-privileges`, pid/memory/cpu limits, and `--rm`.
- `diagnose` only runs after build or smoke failure and may request one plan
  revision.
- `snapshot` writes `environment.json` and `handle.json`; `classify` writes a
  terminal blocked/failed manifest. `finalize` writes state, index, usage and
  stage records.

## Artifacts

Under `stages/validate/environment/`:

```text
environment.json  handle.json  state.json  index.json  usage.json  stage.json
Dockerfile        dockerignore
preflight.json
plans/0001.json   plans/0001.receipts.json   plans/0001.effective.json
gates/0001.json
attempts/0001/build.log   build.json   smoke.log   smoke.json   diagnosis.json
```

`handle.json` exists only for a ready environment. A failed or blocked run
removes it so later stages cannot consume a stale image.

## Plan shape

```json
{
  "status": "ready",
  "base_image": "python:3.12-slim",
  "dockerfile": [{"instruction": "FROM", "arguments": "python:3.12-slim"}],
  "smoke_commands": [["python", "-m", "compileall", "-q", "."]],
  "inspection": {
    "languages": ["python"],
    "build_system": "pip",
    "evidence": [{"path": "pyproject.toml", "start_line": 1, "end_line": 20}],
    "unknowns": []
  },
  "assumptions": [],
  "gaps": [],
  "confidence": "high",
  "why": "..."
}
```

The gate requires evidence to match a successful, non-truncated `read_file`
receipt. It rejects unsafe context paths, host escape commands, Docker socket
references, missing `FROM`, and plans with no smoke command or fallback.

Quality issues such as an unknown base image, `latest`, remote `ADD`, `sudo`,
root user, or `curl | sh` are warnings. `strict` mode also rejects base images
outside the configured allowlist.

## Stop conditions and limits

Limits come from `Settings` (`VALIDATE_ENV_*`, `VALIDATE_DOCKER_*`). The graph
stops on plan/diagnosis call limits, build-attempt limits, plan-revision limits,
gate stagnation, repeated failure signatures, budget exhaustion, or node visit
limits. Internal model or context errors are recorded as failed/blocked
artifacts rather than silently retried.

Docker preflight distinguishes `docker_cli_missing`, `docker_group_not_active`,
`docker_socket_permission`, `sandbox_hides_docker_socket`, and
`docker_unavailable`. The code never runs `sudo`, `sg`, `chmod 666`, or a shell
to work around host permissions.

## Scope boundary

The build context is live: the repository is not snapshotted. `source_revision`
is recorded as metadata; there is no source-drift comparison or warning. Build
steps may access the network and run repository-provided scripts. Runtime
application isolation, secrets, external services and vulnerability validation
belong to later validate work, not this graph.
