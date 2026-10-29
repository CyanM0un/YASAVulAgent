# audit verify

`verify` turns trace candidate flows into evidence-backed findings. It does
not modify source, create trace tasks, or claim coverage; the deterministic
`gate` owns closure debt and the final audit status.

## Candidate materialization

Full candidate flows live in `traces/<trace-id>.json`; the compact trace
records in `audit.json` do not contain them. Verify reads each full artifact,
creates one deterministic `candidate` finding per unique flow, and checkpoints
before calling a model. Candidate keys include category, kind, source/sink
anchors, reachability, triggerability, and prerequisites. Flows that differ on
one of those dimensions remain separate findings.

## Verification flow

1. A fresh verifier receives one candidate plus its task, entry/patch, and
   business references. It re-reads current source with read-only source tools
   and optional YASA tools.
2. The verifier returns `confirmed`, `rejected`, or `needs_validation`.
   `confirmed` requires complete fields and current-source evidence. Missing
   fields or missing reads downgrade the result to `needs_validation`.
3. A `confirmed` or `rejected` result goes to an independent finding review.
   The review does not see the verifier's private reasoning; it checks the
   finding, its verdict, its reason, and the evidence. A rejected finding that
   predates the review policy is reviewed directly, without re-running the
   verifier.
4. If the review materially disagrees with either verdict, a fresh second
   verifier adjudicates. If that verifier cannot complete, the finding stays
   unconfirmed with a deferred review.
5. `needs_validation` findings are terminal for verify but are not a security
   conclusion; `gate` decides whether unresolved findings block completion.
   A rejected finding with a complete review is terminal; one without a
   complete review remains open for review and routes back through `verify`.

## Evidence

Evidence is repository-relative with positive line ranges, current source
`code`, and a non-empty explanation. The runtime hydrates `code` from the
current checkout. A confirmed finding or complete review requires a successful
`read_file` receipt from that verifier/reviewer for each evidence path.

## Failure behavior

- Missing model or audit budget: candidates remain candidates; verify is
  `partial`.
- Invalid verifier JSON or evidence: candidate remains, with a gap.
- Confirmed verifier without a complete independent review: not confirmed.
- Rejected finding without a complete independent review: retained as
  `rejected` with a pending review; gate routes `verify`.
- Source revision changed since prepare: configuration error; start a new run.
- Re-running is safe: terminal findings and complete reviews are reused;
  candidates continue verification, and rejected findings without a complete
  review continue review.

## Output

`audit.json` receives `findings`, `reviews`, and the `verify` summary;
`state.json` receives the same state. Verify writes no separate artifact.
Evidence uses `path`, `start_line`, `end_line`, `code`, and `explanation`.
