# report flow

`report` is the final outer stage. It consumes the canonical validation artifact
and the audit artifact it references, and writes local submission materials for
confirmed runtime findings. It never sends mail, opens a GitHub advisory, calls
a submission API, or edits the repository.

```text
intake -> route investigation -> per finding: draft -> contract -> repair(<=1)
       -> independent review -> finalize
```

## Intake

The stage reads `stages/validate/validation.json` and requires a `complete` or
`partial` validation status plus a non-empty top-level `repo_commit`. It selects
only findings whose `disposition` is `confirmed`; `--finding ID` may narrow the
selection but cannot add a non-confirmed result.

Each selected finding is joined with its audit finding by `finding_id`. The
material bundle contains the validation result, the audit fields that the
report needs (`title`, `cwe_ids`, `severity`, entry point, impact,
prerequisites, source-to-sink, evidence), and bounded text excerpts from saved
validation evidence artifacts. A missing audit finding, missing CWE, incomplete
environment/reproduction/verifier record, or non-completed execution blocks that
finding with a gap. If nothing is confirmed, the stage completes with an empty
report and calls no model.

The report records both the validation commit and the current checkout commit.
A difference is a warning, not a blocker: the advisory must state the tested
revision, and the reproduction remains tied to that revision.

## Route investigation

Deterministic code scans a bounded set of repository policy files:
`SECURITY.md`, `SECURITY.txt`, `.github/SECURITY.md`, `.github/SECURITY.txt`,
`docs/SECURITY.md`, `docs/security.md`, `security/SECURITY.md`, `security.txt`,
`.well-known/security.txt`, `.github/ISSUE_TEMPLATE/config.yml`, `README.md`,
`CONTRIBUTING.md`, and `SUPPORT.md`. It extracts email addresses, URLs, security
contract fields, GitHub remote information, and candidate routes.

One model call interprets the scanned text. The code then validates the result:

- A `confirmed` route requires at least one exact quote that occurs in the cited
  source.
- A confirmed email must match an address found in the scanned policy.
- A confirmed URL must match a scanned candidate.
- A GitHub advisory URL derived from the remote is only a `candidate`; private
  reporting enablement is not proven offline.
- If no route is confirmed, the default GitHub-advisory-shaped route is used and
  marked `default`. This does not prove the project accepts private reports.
- A conflicting or unresolved route is retained as `unknown`; the body is still
  drafted locally, but the item stays `pending` until a human resolves it.

The stage does not make network requests for route discovery.

## Draft

Each finding gets one draft call and at most one repair call. The model returns a
title, CWE list, CVSS vector and justification, a complete body, and an optional
email subject. The body must use exactly these top-level headings in order. Keep the headings
and structural labels in English when the report language is not English; only
the prose is translated:

```markdown
# Title
# Summary
# Details
# Proof of concept
# Impact
```

The deterministic contract enforces:

- affected component, tested revision, root cause, attack preconditions,
  expected versus observed behavior, impact, remediation, and a regression test;
- at least one CWE, restricted to the audit finding's CWE list;
- a CVSS 3.1 or 4.0 vector whose base score is recalculated by code, with a
  matching severity;
- no placeholders, internal workflow names, run identifiers, stage paths,
  machine-specific absolute paths, or credential-like values;
- a bounded body length (800 to 30,000 characters).

Secrets are redacted before the body contract runs. If the contract fails, the
model gets the violation list and the previous draft once; a second failure
blocks that finding.

## Independent review

A fresh model call reviews the material, draft, and route requirements. It
returns `approved` or `blocked` plus eight fixed checks:

- `evidence_supports_claim`
- `source_identity_matches`
- `no_fabricated_range_or_fix`
- `cvss_justified`
- `body_self_contained`
- `route_requirements_satisfied`
- `no_sensitive_data`
- `cwe_and_severity_consistent`

The code requires `approved`, all checks true, and no blocking issues. A blocked
review marks the finding `blocked`; it never rewrites the validation conclusion.
The review is independent in context, though it uses the same configured model.

## Artifacts

```text
stages/report/
├── stage.json
├── state.json
├── report.json
├── routes.json
├── routes.agent.json
├── summary.md
├── index.json
├── usage.json
├── findings/
│   └── <finding-id>/
│       ├── material.json
│       ├── draft.json
│       ├── draft.agent.json
│       ├── draft-repair.agent.json   # only when a repair was needed
│       ├── review.json
│       └── review.agent.json
└── submissions/
    ├── <finding-id>.md               # complete self-contained body
    └── <finding-id>.json             # local envelope and form fields
```

`report.json` has no `schema_version`. Its top-level fields are `run_id`,
`repo`, `repo_commit`, `current_commit`, `source_validation`, `source_audit`,
`validation_status`, `status`, `execution_status`, `stop_reason`, `language`,
`selected_finding_ids`, `routes`, `findings`, `gaps`, and
`direct_submit_ready`.

Each finding records `id`, `finding_id`, `title`, `status`, `body_status`,
`route_status`, `format`, `language`, `cwe`, `severity`, `audit_severity`,
`cvss`, `route`, `subject`, `form_fields`, `body`, `review`, `gaps`, and
`artifacts`. The CVSS object stores the version, vector, recalculated
`base_score`, severity, and metric justification.

For email routes, the envelope carries the recipient and subject; the body stays
pure. For advisory and form routes, `form_fields` is derived deterministically
from the five body sections: `title`, `summary`, `description`, `impact`, and
`steps_to_reproduce`.

## Status and resume

Report statuses are `complete`, `partial`, `blocked`, and `failed`. A finding is
`ready` only when the body contract passes, the independent review is approved,
the route is `confirmed` or the default `default`, and there are no blocking
gaps. A report is `partial` when at least one full local body exists but some
finding is still `blocked` or `pending`; it is `blocked` only when no body could
be produced. `direct_submit_ready` is true only when every ready item has a confirmed
route; it is always a local marker and never triggers submission.

An empty confirmed selection completes with no findings. Missing validation,
missing audit, or a model configuration failure blocks the report. A per-call
request failure blocks only that finding and leaves the report `partial`; a
time/token/cost cap leaves remaining findings `pending`.

Without `--rerun`, valid route, draft, and approved review artifacts are reused.
A review is reused only when its `body_sha256` matches the current body. `--rerun`
removes report findings, submissions, and the report files before rebuilding.

## Limits

`REPORT_MODEL` falls back to `LLM_MODEL`. `REPORT_LANGUAGE` defaults to `en` and
can be overridden by a confirmed policy requirement. `REPORT_LLM_TIMEOUT`,
`REPORT_TOTAL_TIMEOUT`, `REPORT_MAX_TOTAL_TOKENS`, `REPORT_MAX_TOTAL_COST`, and
`REPORT_MAX_FINDINGS` bound the stage. CVSS 4.0 support uses the `cvss` package;
3.1 is calculated natively.

This stage does not implement sending, GitHub API enablement checks, attachment
packaging, PGP encryption, disclosure-deadline tracking, duplicate-root-cause
merging, or a human approval UI. Those remain manual operations outside the run.
