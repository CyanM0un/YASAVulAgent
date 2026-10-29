# validate flow

`validate` turns audit findings into runtime evidence. It is separate from the
environment builder: the environment stage produces a reusable image handle, and
validation uses that image to exercise the target.

## State flow

```text
intake -> (plan -> execute -> verify) per finding -> finalize
```

`intake` selects `confirmed` and `needs_validation` findings by default,
preflights Docker, and resolves the environment handle. `plan` produces a claim
and harness; `execute` runs the baseline, PoC, negative controls and bounded
debug steps; `verify` independently reruns the decisive step; `finalize` applies
the result contract.

This is a sequential loop inside one workflow node, not a LangGraph subgraph.
There is no checkpoint between phases: resume works from the artifact files
written by `plan`, `execute`, and `verify`.

## Debugging

Debugging happens inside `execute`, performed by the agent with the tools it
has: `docker logs`, `docker exec`, saved command output, `read_artifact`,
`read_file`, coverage, verbosity, strace, or a temporary source copy. The prompt
requires the decisive run to use original logic and controls. There is no
separate debug node, no automatic diagnosis pass, and no harness-driven retry
after an `unresolved` result; the agent must use its round, call, and time
budget within the single execute invocation.

## Reproduction choices

The agent, not the code, chooses the strongest available form:

- `http`: start the target and run a client in a container.
- `cli`: invoke a command with argv/stdin/files.
- `test_case`: run pytest, JUnit, Go test, Node test or another test harness.
- `library_api`: exercise a public library boundary.
- `service`: use additional local services when the agent needs them.

A direct internal method call is auxiliary and cannot by itself produce a
terminal `confirmed` or `rejected`. Build failures, missing dependencies,
timeouts and single non-triggers are `unresolved`, not `rejected`.

## Resume

`--rerun` deletes `findings/` and `verifier/`, then runs everything again.
Without it, each phase reuses a valid artifact:

- `plan.json` passes `check_plan` -> skip `plan`.
- `result.json` has `execution_status=completed` and a disposition -> skip `execute`.
- `verifier/<id>/result.json` has `execution_status=completed` -> skip `verify`.

Malformed or failed artifacts are ignored and the phase runs again. Notes are
stored inside the finding directory, so a resumed run sees the notes from the
previous attempt. Command numbering continues after the highest recorded index
in `attempts/0001/commands.jsonl` instead of restarting at 1.

The time budget is shared by all findings. Before a finding starts, the stage
checks that at least 120 seconds remain; if not, the finding is recorded as
`unresolved` with `agent_stop_reason=time_budget` instead of being started and
cut off mid-phase.

## Result contract

The canonical artifact is `stages/validate/validation.json`. Agent raw results
live under `findings/<finding-id>/`, and the verifier writes under
`verifier/<finding-id>/`. The code canonicalizes the artifact and does not trust
an agent-written final status.

A terminal result requires runtime evidence with saved artifacts, a completed
execution, the expected `security_boundary_crossed` value, a non-auxiliary
reproduction level, `environment`, `reproduction`, and a fresh verifier with its
own evidence and rerun. Missing pieces downgrade the result to `unresolved`.

`validation.json` records the repository commit once at the top level as
`repo_commit`. There is no per-finding source comparison and no drift check; the
run assumes the source does not change between intake and finalize. Each finding
records `agent_stop_reason` so a non-terminal result can be attributed to
`round_limit`, `step_budget`, `time_budget`, `model_request`, `token_budget`,
`cost_budget`, or a normal `complete`; an empty value means the phase failed for
another reason.

## Failure semantics

- Model configuration or authentication failure (`ModelFatal`, e.g. HTTP 401/403,
  missing API key) aborts the stage: status is `blocked` with
  `stop_reason=model_configuration`.
- A model request that still fails after retries (`ModelRequest`, timeouts) is
  recorded against that finding: `agent_stop_reason=model_request`, stage
  `partial`.
- Budget exhaustion triggers one tool-free finalize call. If the agent still
  cannot return a usable object, the finding is `unresolved` with its stop
  reason.
- Usage caps are soft: a call is recorded after it completes. When the cap is
  already exceeded, the next model call is not made, so no finalize output is
  produced; the finding records `token_budget` or `cost_budget`.

## Agent-controlled Docker

The agent has host bash and Docker. It chooses single-container or multi-container
topology and controls target startup, test files and cleanup. `ShellRunner` logs
each command and rejects obvious host escapes (privileged mode, host namespaces,
devices, Docker socket references, unconfined security options, and host mounts
outside the validation workspace). This deny list is best-effort: script content
and compose configuration can bypass text matching. It is not a hard sandbox.

Do not run this stage against untrusted repositories. Use it only in a trusted or
otherwise isolated host. The stage does not check whether the repository was
modified during the run, and it does not limit or record network access; results
must not claim repository immutability or network isolation.

Docker is a hard dependency when there is at least one selected finding. If Docker
or the environment image is unavailable, the stage becomes `blocked`; it never
falls back to host execution. With no selected findings the stage writes a valid
empty artifact and completes without starting Docker.

## Verifier independence

The verifier runs in a separate directory and must save its own evidence and
rerun. It is not identity-independent: it uses the same model, the same tools,
and the same image, and its prompt includes the primary result, including the
conclusion. `independent` and `rerun` are partly self-reported (the contract
recomputes only the evidence-based parts). Treat `confirmed` as "two agent runs
agreed with saved evidence", not as a cross-model or adversarial audit.

## Wiring debt

Known gaps, intentionally left out of the current scope:

- `parallel_tools` is not enabled for validate; read-only tools run sequentially.
- The shared `TokenCounter`/`ContextManager`/`RetryPolicy` wiring is hand-written
  in each stage; there is no common factory.
- `discover`, `audit`, and `init` still configure the loop independently.
- Execution is not sandboxed beyond the deny list; there is no command whitelist
  or containerized agent.
- Evidence artifacts are checked for existence, not bound to a command index or
  content hash.
