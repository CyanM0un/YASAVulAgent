# finalize

`finalize` is the deterministic close-out node. It does not call a model or tools. It reads the run-local ledger, computes the final status, and writes a compact handoff. It does not mirror every ledger table as JSON.

Completion requires:

- the initial screen wave to be complete;
- zero open debt, including unresolved files, candidates, tasks, follow-ups, and feature work;
- zero open handoffs;
- review status `complete` with route `finalize`;
- no blocking review gaps;
- `force_partial` to be false.

A recursion-limit stop is routed through `finalize` with `force_partial=True`, so it always reports `partial` while still writing the normal handoff artifacts.

Artifacts written by `finalize`:

- `files.json` and `excluded-files.json`: inventory snapshot;
- `confirmed-entries.json`: all confirmed entries;
- `index.json`: compact summary;
- `state.json`: full `DiscoverState`.

Tasks, entries, evidence, dispositions, mechanisms, feature queries, hits, and the full gap list remain in `ledger.sqlite`; `finalize` does not duplicate them as separate JSON files.

`confirmed`, `unknown`, `deferred`, and `not_applicable` are terminal dispositions. A run with zero confirmed entries can complete if every candidate is terminal and no other debt or handoff remains. `unknown` and `deferred` remain visible in the ledger and handoff summary and are not treated as proof of absence. Open handoffs block completion until confirm consumes them; consumed handoffs remain in history. Budget exhaustion, missing runtime context, and no-progress stops produce `partial`, with the stop reason and gaps preserved.
