# Audit trace

`trace` runs one per-task state graph:

```text
prepare_task -> path_scout -> triage -> expand/triage -> specialists -> lead -> validate_persist
```

Inputs are the planned entry or patch task, current-source scope, category and
mechanism checks, and valid behavior summaries from the audit state. The output
is a set of candidate source-to-sink flows, category and mechanism checks,
repair-unit results, summaries, and gaps. Trace does not create findings.

- `path_scout` uses YASA call graphs and bounded source excerpts. YASA is
  structural navigation, not taint analysis; missing or truncated graphs are
  marked as dynamic.
- Triage is tool-free, judges only units reached from the entry or patch unit,
  and runs for at most two rounds.
- Specialists are selected from `specialists/registry.json`; adding a lens needs
  a registry entry and a prompt file, not graph or triage-parser changes.
- The lead owns required checks and candidate flows. Missing checks remain
  pending, and unproven paths stay unknown.
- When gate reopens a task with trace debt, triage and lead receive a bounded
  `repair` block. The lead returns one `repair_responses` item per debt; this is
  validated and recorded, but gate still decides closure from actual coverage.
- Rejected findings with a complete independent review are injected as
  `known_rejections`; a new current-source fact can still justify re-reporting
  the flow.
- Full task traces are written under `stages/audit/traces/`; the outer
  checkpoint stores compact records and preserves verify-owned findings.
- `AUDIT_TIMEOUT` bounds the stage and `AGENT_HARD_TASK_CAP` bounds each task.
  `AUDIT_MODEL_CONCURRENCY` caps concurrent model calls across task and
  specialist loops; `AUDIT_MAX_TOTAL_TOKENS`/`AUDIT_MAX_TOTAL_COST` are optional
  soft caps checked before the next model call.
