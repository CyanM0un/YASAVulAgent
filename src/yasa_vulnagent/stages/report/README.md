# report stage

Generates local, submission-ready vulnerability advisories from confirmed
validation results. The stage consumes `stages/validate/validation.json` and the
audit artifact it references. It never sends mail, opens an advisory, calls a
submission API, or edits the target repository.

```text
intake -> route investigation -> draft -> deterministic contract -> optional repair
       -> independent review -> report.json + submissions/
```

- Intake selects only `confirmed` findings with complete material and joins each
  one to its audit finding for CWE, entry point, severity, and evidence.
- Route investigation scans local security policy files and the Git remote. A
  GitHub advisory URL derived from the remote is only a candidate; when no route
  is confirmed, the stage uses a default advisory-shaped route.
- Draft and review are separate model calls. The body must use the fixed
  five-section advisory shape and is checked by code for CVSS, CWE, placeholders,
  internal text, secrets, and absolute paths.
- A fresh review must approve every fixed check before an item is ready. Report
  generation never rewrites a validation conclusion.
- `submissions/<finding-id>.md` contains the body; the matching `.json` contains
  the local envelope and form fields. `report.json` and `summary.md` describe the
  run.

See [`docs/report-flow.md`](../../../../docs/report-flow.md) for the full
contract, status semantics, resume behavior, and configuration. The stage writes
no `schema_version` field.
