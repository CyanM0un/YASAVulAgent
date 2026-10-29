# Audit plan

`plan` converts the prepared audit inputs into durable tasks and coverage
obligations. It is deterministic except for the required model consolidation
step. It does not trace code, load CWE checklists, write findings, or touch
`business-logic.json`.

```text
prepared entries/patches
  → seed tasks
  → deterministic path batches
  → required model consolidation per batch
  → final tasks, category obligations, mechanism checks
  → audit.json checkpoint
  → next_action = trace
```

## Seed tasks

Every prepared entry and patch produces exactly one seed task, so the seed count
is `entries + patches`.

- An entry seed task has `kind=entry`, one `entry_ids` value, no `patch_ids`,
  in-scope paths from its entry location/evidence, and `priority=normal`.
- A patch seed task has `kind=patch`, one `patch_ids` value, every repair unit
  reference, and `paths=changed_paths` intersected with the audit scope.
- A patch with no repair units becomes `status=blocked`; it receives no
  mechanism checks and adds a plan gap.
- Category obligations are records added after grouping, not extra seed tasks.

Seed task IDs are deterministic: entry tasks use an entry slug plus a SHA-256
prefix, and patch tasks use the commit.

## Batching

`AUDIT_PLAN_BATCH_SIZE` (default `100`, positive integer) bounds each model
batch. Tasks are bucketed by their primary in-scope path and split into
`batch-0001`, `batch-0002`, ... batches. Entry and patch batches are separate.

Batching is intentionally conservative:

- batches are deterministic;
- a batch never exceeds the configured size;
- cross-batch merging is disabled;
- the model sees a compact task view, not source code, CWE details, or
  category checklists;
- one model call is made per batch.

The model may only partition and order the seed IDs it receives. It cannot add
or drop task IDs, paths, entries, patches, repair units, or findings.

## Model protocol

The model must return one JSON object:

```json
{
  "groups": [
    {
      "seed_task_ids": ["task-entry-example-12345678"],
      "priority": "high",
      "reason": "same controller and sink"
    }
  ],
  "order": [0]
}
```

Validation rejects unknown or repeated IDs, missing IDs, cross-batch IDs, mixed
entry/patch groups, groups larger than four, groups without a common path,
blocked tasks in a merged group, invalid priorities, missing reasons, and an
incomplete `order` permutation. A failure raises `PlanModelError` before any
task is written. There is no semantic fallback and no repair call. Transient
429/5xx model failures are retried with `RetryPolicy` and `AGENT_MODEL_RETRIES`;
400/401/403 failures are fatal and are not retried. Provider-level retries stay
disabled to avoid double retries.

When seed tasks exist, the model is mandatory. Missing `LLM_API_KEY` or model
configuration raises `PlanConfigurationError`. An existing plan is reused
without a model call.

After validation, each group becomes one final task. A singleton keeps its seed
ID; a merged group gets a deterministic `task-<kind>-group-<hash>` ID and the
union of its seed fields. The final order is:

```text
priority_rank(high=0, normal=1, low=2)
  → batch index
  → model-local order
```

## Obligations

- Each entry task receives one category check per baseline category. A merged
  entry task still receives one set, not one set per seed.
- Category checks contain only category metadata: `task_id`, category,
  applicability, status, source, required, and profile version. Detailed CWE
  and checklist content stays in `category_details.json`, which is
  execution-facing and is not loaded by `plan`.
- Each patch task with repair units receives the three patch mechanism checks:
  `original_path`, `bypass`, and `same_mechanism`.
- Blocked patch tasks receive no mechanism checks.

## Persistence and idempotency

`plan` writes only the `audit.json` checkpoint; there is no `plan.json`. It
preserves prepare-sourced gaps and appends plan-sourced gaps. It does not write
`business-logic.json`.

A repeated run hydrates existing tasks/checks when `audit.tasks` exists or
`framework.plan_done=true`. It does not call the model and does not rewrite the
audit checkpoint. `plan.status` is `complete` only when tasks exist, no plan gap
remains, and prepare is complete; otherwise it is `partial`.

The model usage record uses `stage=audit.plan` and `task_id=<batch id>`.
