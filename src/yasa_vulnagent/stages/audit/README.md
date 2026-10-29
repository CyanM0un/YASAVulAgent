# Audit stage

All audit nodes are implemented; see
[`docs/audit-framework.md`](../../../../docs/audit-framework.md).

```text
prepare → plan → trace → recon → trace → verify → gate → finalize
```

`prepare` reads init/discover artifacts, projects the discover ledger into the
audit scope, normalizes confirmed entries and patch graphs, and writes
`prepare.json` plus the `audit.json` checkpoint. It does not call a model and
does not write `business-logic.json`.

`plan` builds one seed task per prepared entry and patch, splits seed tasks into
path-bounded batches, and requires one model consolidation call per batch. The
model only groups and orders seed IDs; final paths, entries, patches, repair
units, and priorities stay deterministic. Plan output adds tasks, category
checks, and patch mechanism checks to `audit.json`. A patch without repair units
is blocked and recorded as a plan gap, except a patch already marked
`not_applicable`. There is no semantic fallback when the model is missing or
returns invalid output. Transient 429/5xx failures are retried with the shared
`RetryPolicy`; auth and other fatal failures are not.

Plan-facing category metadata lives in `categories.json`. Detailed CWE and
checklist content lives in `category_details.json`; `plan` does not load it.
`plan` never writes `business-logic.json` and has no separate `plan.json`.

`trace` runs a per-task `prepare_task → path_scout → triage → expand/triage →
specialists → lead → validate_persist` graph. Path scouting uses YASA call
graphs plus current-source excerpts; triage is bounded to two rounds and twelve
units per round; specialists are selected from a registry with `identity`,
`boundary`, `dynamic`, and `patch` lenses. The lead records candidate
source-to-sink flows and closes category or mechanism checks with current-source
evidence. Gate trace debts are injected as a bounded `repair` block, and
independently reviewed rejections are injected as `known_rejections`. Trace
writes compact records to `audit.json`, full task traces under `traces/`, and
never writes `findings`. `AUDIT_TIMEOUT` bounds the whole stage;
`AGENT_HARD_TASK_CAP` bounds each task; `AUDIT_MODEL_CONCURRENCY` bounds
concurrent model calls. Optional `AUDIT_MAX_TOTAL_TOKENS` and
`AUDIT_MAX_TOTAL_COST` soft caps are checked before the next model call.

`recon` runs after the first trace and before the second trace. It consumes
the prepared scope, entries, patches, tasks, first-trace summaries, project
overview, and any complete sidecar; it uses one bounded agent with source,
YASA, and read-only Git tools. It writes cross-task business constraints,
operations, investigations, and concrete `logic` follow-up tasks to
`business-logic.json`. A missing model, failed request, invalid output, invalid
reference, invalid evidence, or empty business model is a hard error: recon
writes no sidecar, does not set `recon_done`, and does not route to trace. An
empty business scope is a deterministic no-op that writes an empty complete
sidecar without a model. A valid result may be `partial` for real `unknown` or
`deferred` investigations.

Recon does not create category or mechanism checks; `state_workflow_business_logic`
remains trace-owned. It skips duplicate logic questions, and the second trace
processes only pending tasks. Trace reads only the business records referenced
by a logic task and still does not create findings.

`verify` reads full candidate flows from `traces/`, materializes deterministic
candidate findings, and verifies each candidate with a fresh source-backed
agent. A confirmed or rejected result requires a complete independent finding
review whose verdict matches the finding; a material disagreement is
adjudicated by a second fresh verifier. A rejected finding without a complete
review is reviewed directly, without re-running the verifier. Invalid output,
missing current-source reads, and budget exhaustion keep candidates or pending
reviews visible instead of fabricating findings. Verify writes `findings`,
`reviews`, and its summary; it does not own audit closure or the final stage
status.

`gate` is deterministic and calls no model or tools. It evaluates inputs,
task/check/trace coverage, finding materialization, confirmed/rejected finding
reviews, and business gaps; closed static work can leave `needs_validation`
findings for later dynamic validation. Missing coverage reopens a task and
routes to `trace`; an unresolved candidate or a missing/mismatched review routes
to `verify`; blocking debt or a debt fingerprint/visit/budget stop routes to
`finalize` with `partial`. `complete`
means the recorded static audit scope is closed, not that the repository has no
vulnerabilities.

`finalize` uses the gate status for `audit.json`, `index.json`, `stage.json`,
and the report, while preserving the business sidecar's own status. It writes
no coverage review. `validation.json` remains `not_run` with a warning that
dynamic and external contract validation are pending.

To replace a node, keep its `(state, runtime)` signature and return a JSON
compatible update with `next_action`. Canonical writes should go through
`storage.py`; node-specific helpers stay inside that node's directory.
