# review

Audits open discover debt in a fresh context and writes `review.json`. Debt includes unread production files, candidates, pending or partial tasks, completed-screen follow-ups and deferred items, mechanisms without queries, incomplete feature queries, query hits without tasks, and open handoffs.

Before the model call, review automatically:

- consumes open handoffs by creating or merging a confirm task;
- runs a bounded query for every stored mechanism that has no query row;
- resumes incomplete feature-query cursors within the configured query limits.

The review model then receives a compact debt snapshot, may read only debt-related source, and returns dispositions and optional bounded screen tasks. Accepted dispositions are `not_applicable`, `deferred`, and `handoff_to_confirm`; `covered` is never accepted because file coverage comes only from screen read receipts. Every disposition requires a reason, owner, and evidence reference that resolves in the current inventory/source; a rejected or unsupported disposition leaves debt open.

`handoff_to_confirm` is candidate-only, requires reason `downstream_confirm`, creates a confirm task immediately, and is marked consumed. A consumed handoff no longer blocks completion; the candidate remains until confirm records a terminal result. New screen tasks are validated; rejected proposals become warnings rather than blocking gaps.

Routing is deterministic after dispositions: candidate, handoff, and confirm-task debt routes to `confirm`; file, mechanism, query, hit, and completed-task debt routes to `screen`; no debt routes to `finalize`. Malformed review JSON is retried once in the same context, and a second failure records a blocking gap. Review never marks a file or candidate `covered`.
