# Audit recon

`recon` recovers business constraints, operations, investigations, and targeted
follow-up questions from the prepared audit inputs and the first trace pass.

## Inputs

- `audit.json`: scope, entries, patches, tasks, category/mechanism checks,
  compact traces, and summaries.
- `prepare.inputs.overview_file` when available.
- Existing `business-logic.json`, reused only when it is complete and valid.

## Outputs

`business-logic.json` is canonical:

```text
run_id
repo
mode
status              complete | partial
scope
constraints[]
operations[]
investigations[]
gaps[]
warnings[]
limitations[]
model
written_at
```

`audit.json` receives only a `recon` summary, the `business_artifact` path, and
any generated `logic` tasks. Trace, category checks, mechanism checks,
findings, and reviews are preserved.

`recon` does not create a business graph. Relationships are ID references, not
nodes and edges.

## Model dependency

When the audit has business tasks, recon is a hard model dependency:

- missing model or API key -> `ReconConfigurationError`;
- expired budget -> `ReconBudgetError`;
- request failure, invalid JSON, invalid record/reference/evidence, or an empty
  business model -> `ReconModelError`.

These failures do not write a sidecar, do not set `recon_done`, and do not
route to the second trace. Only a complete validation result is persisted.

When no entry, patch, or runnable task exists, recon is a deterministic no-op:
it writes an empty `complete` sidecar and does not call a model. A valid result
with real `unknown`/`deferred` investigations may be `partial`; that is a
business uncertainty, not a model-failure fallback.

## Boundary with trace

- Trace owns the baseline category checks, including
  `state_workflow_business_logic`.
- Recon does not write category or mechanism checks and does not re-run
  completed entry/patch tasks.
- A logic task is created only for a concrete cross-task, cross-operation, or
  business-context question. Duplicate questions are skipped.
- The second trace reads only the business records referenced by a logic task.
  It skips complete entry/patch tasks and does not create findings.
