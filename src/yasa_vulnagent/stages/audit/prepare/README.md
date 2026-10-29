# Audit prepare

`prepare` is the deterministic input adapter for the audit graph. It has no
inner LangGraph: the steps are sequential I/O, with no model/tool loop.

```text
resolve stage inputs
  → project discover ledger into audit scope
  → normalize confirmed entries / patch graphs
  → write prepare.json + audit.json
  → next_action = plan
```

## Files

| File | Purpose |
| --- | --- |
| `inputs.py` | Resolve stage references, input paths, source revisions, and the input signature. |
| `inventory.py` | Read-only projection of `discover/ledger.sqlite`; no repository walk or reclassification. |
| `normalize.py` | Convert confirmed entries and patch graphs into audit records with current-source evidence. |
| `node.py` | Orchestrate the steps and return the state update. |

## Rules

- All audit modes require discover; its full inventory is `ledger.sqlite`, not
  the capped `files.json` export.
- `scope.files` is projected from the ledger; evidence paths must be in scope.
- Evidence is re-read from current source. A changed file fingerprint or a
  changed discover revision invalidates the affected reference.
- `business-logic.json` is owned by `recon`; prepare does not write it.
- A matching input signature is idempotent. Changed inputs fail before writes.
- Empty or unusable inputs produce `status=partial` and an explicit gap, not a
  fabricated complete snapshot.
