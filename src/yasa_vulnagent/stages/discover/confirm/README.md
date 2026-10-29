# confirm

Runs bounded, file-scoped confirmation tasks for candidate entries and review handoffs. A candidate is only a lead. Confirm reads the candidate location and the same file for sibling handlers, wrappers, registration points, and activation branches; directly related callers/callees may be read, but broad cross-file work must become a new screen task.

A `confirmed` entry needs five source-backed fields: `input_origin`, `registration`, `activation`, `input_binding`, and `trust_boundary`. Each field contains a summary and evidence references that resolve to the current inventory and source. A claim with a missing or invalid field/evidence is downgraded to `unknown`; a failed model or tool call leaves the candidate pending instead of fabricating a terminal result.

Allowed outcomes:

- `confirmed`: all five fields and evidence passed validation.
- `not_applicable`: the lead is explicitly not an entry, with reason and evidence.
- `unknown`: the source cannot establish the claim, with reason, owner, attempts, reopen condition, and evidence.
- `deferred`: bounded work cannot settle it now, with reason, owner, attempts, reopen condition, and evidence.

`unknown` and `deferred` are terminal for that candidate and do not mean absence has been proved. Every result is persisted with the candidate status, same-file review flag, evidence, and task result.

A task may also return `same_file_targets` for another bounded check of the same file, or `screen_scope` for broad production scope that exceeds the confirm task limits. The runtime deduplicates these tasks and excludes the current confirm task when creating same-file expansion. Confirm also accepts structured `feature_observations`, using the same bounded query/materialization path as screen; query hits are leads, not verified entries. Confirm reads never create screen coverage receipts.

If a confirm run is interrupted after its task commit but before feature processing, the next confirm pass replays the task's unprocessed `feature_observations`. A runtime/model configuration failure keeps the task pending and writes the reason to the ledger gaps, so a missing key is visible in the final partial result rather than silently stalling the queue.
