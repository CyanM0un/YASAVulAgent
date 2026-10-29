# Audit schemas

No standalone JSON Schema files are shipped; `audit.json` and
`business-logic.json` are validated structurally by their writers.

`audit.json` is populated by `prepare`, `plan`, `trace`, `recon`, `verify`, and
`gate`, then closed by `finalize`. Trace compact records live in `audit.json`;
full task traces are written under `stages/audit/traces/`. `business-logic.json`
is written by `recon` and carries business constraints, operations,
investigations, and gaps.
