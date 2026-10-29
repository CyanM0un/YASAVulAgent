# validate stage

Validates audit findings at runtime. Docker is a hard dependency when there are
selected findings: the stage does not fall back to running the target on the host.
With no selected findings it writes a valid empty artifact without starting Docker.

## Flow

```text
intake -> (plan -> execute -> verify) per finding -> finalize
```

- `intake` is deterministic: select `confirmed` and `needs_validation` findings,
  preflight Docker, resolve or build the environment image, and record the
  repository commit.
- `plan` asks one agent for a claim and a bounded harness. The agent may choose
  HTTP, CLI, test_case, library_api, or service reproduction and may choose the
  container topology.
- `execute` runs the agent's baseline, PoC, negative controls and debug commands
  through `ShellRunner`. The agent controls Docker; the harness logs every command
  and applies a best-effort deny list. Debugging happens here, not in a separate
  node.
- `verify` is a separate agent instructed to reset state, use fresh containers, and save its own evidence.
- `finalize` validates the raw results with the result contract and writes the
  canonical `validation.json`.

This is a sequential loop inside one node, not a LangGraph subgraph. Without
`--rerun`, a valid `plan.json`, `result.json`, or verifier `result.json` is
reused, so a crashed or partial run resumes where it stopped. A malformed
artifact is ignored and that phase runs again. Before a finding starts, at least
120 seconds must remain; otherwise it is recorded as `unresolved` with
`agent_stop_reason=time_budget`.

## Results and artifacts

```text
stages/validate/
  validation.json
  state.json
  selection.json
  index.json
  usage.json
  stage.json
  findings/<finding-id>/
    plan.json
    result.json
    agent.json
    notes.jsonl
    attempts/0001/commands.jsonl
    evidence files
  verifier/<finding-id>/
    result.json
    agent.json
    notes.jsonl
    attempts/0001/commands.jsonl
  environment/...
```

`confirmed` and `rejected` require `execution_status=completed`, saved runtime
evidence, `security_boundary_crossed=yes|no`, a non-auxiliary reproduction level,
`environment`, `reproduction`, and a fresh verifier with its own evidence.
Everything else remains `unresolved`. The artifact records `repo_commit` once at
the top level; there is no per-finding source comparison. Each finding records
`agent_stop_reason` (`complete`, `round_limit`, `time_budget`, `model_request`,
`token_budget`, `cost_budget`; empty means another failure) and `agent.json` keeps
the final text, timings and per-call token counts.

## Agent notes

`save_note` writes short finding-scoped notes to `notes.jsonl`. Notes survive
context compaction (they are re-injected as a compaction hint) and resume (they
are prepended to the prompt of the next execute/verify run). The source remains
the authority; a note is a pointer, not evidence.

## Docker boundary

The agent uses host bash and Docker, so the code does not provide a hard sandbox.
`commands.py` rejects obvious host escapes: privileged mode, host network/pid/
ipc/uts/user namespaces, devices, Docker socket references, unconfined security
options, and host mounts outside the validation workspace. `SYS_PTRACE` is allowed
for debugging. Compose files and commands encoded inside scripts can bypass the
audit; this is a best-effort guardrail, not an isolation guarantee.

Do not run this stage against untrusted repositories. Validation does not check
whether the repository was modified during the run and does not limit or record
network access. Results must not claim repository immutability or network
isolation.

## Verifier limits

The verifier runs in a separate directory with its own evidence and rerun, but it
uses the same model, tools, and image, and its prompt includes the primary result
(including the conclusion). `independent`/`rerun` are partly self-reported.
`confirmed` means two agent runs agreed with saved evidence, not that a
cross-model adversarial audit passed.

## Failure semantics

A model configuration failure (HTTP 401/403, missing key) blocks the stage. A
request that still fails after retries marks that finding `unresolved` with
`agent_stop_reason=model_request`; the stage becomes `partial`. Round/time/usage
exhaustion triggers one tool-free finalize call; if that still returns no usable
object, the finding records its stop reason. Usage caps are checked after a call
completes, so an exceeded cap prevents the next call rather than truncating one.
