# audit gate

`gate` is the deterministic closure controller for the audit stage. It has no
model, prompt, tool, or subagent, and it writes no separate artifact: its
decision is stored in `audit.json.gate`.

It reads the canonical audit records, compact traces and full trace artifacts,
findings and reviews, and the business sidecar. Debt is stable and typed:
inputs without tasks, incomplete or blocked tasks, incomplete category or
mechanism obligations, traces that are not coverage-complete, flows without a
materialized finding, candidates, confirmed findings without a complete
review, and business or audit gaps.

A task with `patch.status=not_applicable` and no repair units is the only
accepted blocked task. `needs_validation` is terminal for verify and does not
block closure; it is reported in `validation_pending` for later dynamic
validation. No coverage review is generated or required.

Routing is `trace` before `verify` before `recon` before `finalize`. A complete
task with missing obligations or trace coverage is reopened to `partial` and
routed to `trace`; a candidate or missing finding is routed to `verify`; a
missing business sidecar may be routed to `recon` while recon is incomplete.
Blocking debt that no route can repair, a repeated debt fingerprint, the gate
visit cap, or an exhausted stage budget closes to `finalize` as `partial`.

`complete` requires no blocking debt and an empty canonical `audit.gaps` list.
It means the recorded static audit scope is closed, not that the repository has
no vulnerabilities.
