# yasa-vulnagent

An evidence-backed vulnerability analysis workflow for repository code. It uses YASA for structural context, LangGraph for staged orchestration, and writes validation and local report artifacts.

The current entry connects five stages:

```text
init → discover → audit → validate → report
```

All five outer stages execute and write run records. `init`, `discover`, and `audit` have their own subgraphs; `validate` runs its plan/execute/verify pipeline and exposes `environment` as a separate subgraph; `report` is a single report node.

```text
init: START → yasa → documents → cwe → security_history → END
```

`yasa` performs deterministic initialization, cache-status validation, and one MCP `get_function(name="main")` connectivity check; an empty result is allowed. `documents` is an independent LangGraph subgraph that discovers, reads, and summarizes project documentation. `cwe` validates only the local offline CWE Top 25 ZIP/XML archive. `security_history` is a read-only Git-history subgraph bound to a fixed HEAD; it reviews commits and builds patch graphs whose historical source references are checked for consistency. `discover` has a loopable `prepare → screen → confirm → review → finalize` outer subgraph. Screen runs three initial views, bounded waves, and structured feature queries; confirm runs file-scoped five-field verification and expansion; review repairs feature queues and routes remaining debt. The stage reports `complete` only when every candidate is terminal, no task/debt/open handoff remains, and review converges; otherwise it reports `partial` with explicit gaps. `init` and `discover` write checks, indexes, and gaps to their stage directories; core configuration or YASA failures are marked `failed`. `audit` now has its outer `prepare → plan → trace → recon → trace → verify → gate → finalize` graph. `prepare` resolves init/discover inputs, projects the discover inventory into audit scope, and normalizes confirmed entries and patch graphs without calling a model. `plan` then builds one seed task per prepared entry/patch, batches by path, and requires one model consolidation call per batch; the model can only group and order seed IDs. Plan adds tasks, category checks, and patch mechanism checks to the audit checkpoint. `trace` runs per-task path scouting, bounded triage, registry-driven specialists, and a lead; it writes candidate source-to-sink flows and traces, not findings. `recon` recovers cross-task business constraints, operations, investigations, and logic follow-up tasks; it requires a configured model whenever business tasks exist and does not fall back to an empty sidecar on model failure. `verify` independently verifies candidate flows and writes findings/reviews. The deterministic `gate` evaluates closure debt, reopens repairable tasks, and emits a stable `complete`/`partial` decision; `finalize` writes that status into the audit, index, stage, and report artifacts while preserving the business sidecar status. The audit stage's own `validation.json` remains `not_run` because runtime validation is a separate stage. The top-level `validate` stage selects `confirmed` and `needs_validation` findings, asks an agent to build and run a Docker-backed PoC, sends terminal results to a fresh verifier, and writes the canonical validation artifact. It records the repository commit once, resumes completed plan/execute/verify phases, and keeps finding-scoped notes that survive compaction and resume. The top-level `report` stage selects only confirmed validation results, investigates the repository's submission route from local policy text and the Git remote, drafts a self-contained five-section advisory, recalculates CVSS, and requires a fresh independent review before an item is ready. It writes `report.json` plus per-finding `submissions/` materials under `stages/report/`; it never sends mail, opens an advisory, or calls a submission API. The environment subgraph remains available through the `environment` command. See [`docs/audit-framework.md`](docs/audit-framework.md), [`docs/validate-flow.md`](docs/validate-flow.md), and [`docs/report-flow.md`](docs/report-flow.md). This version does not depend on OpenCode.

## Installation and usage

```bash
cd yasa-vulnagent
python -m pip install -e .
cp .env.example .env
# Fill in LLM_API_KEY, LLM_BASE_URL, and LLM_MODEL in .env
# Optional: set CWE_ARCHIVE_PATH to override the local CWE archive
# Optional: set YASA_SOURCE_PATH, YASA_BIN_PATH, YASA timeouts, DOCUMENTS_*, SECURITY_HISTORY_*, DISCOVER_SCREEN_* (wave budgets and task rounds), DISCOVER_RECURSION_LIMIT, AUDIT_MODE, AUDIT_TIMEOUT, AUDIT_RECURSION_LIMIT, AUDIT_MAX_AGENTS, AUDIT_PLAN_BATCH_SIZE, AUDIT_MAX_TOTAL_TOKENS, AUDIT_MAX_TOTAL_COST, AUDIT_MODEL_CONCURRENCY, VALIDATE_ENV_*, VALIDATE_DOCKER_*, VALIDATE_*, REPORT_*, AGENT_*, and TOOLS_* settings
# Optional: set USAGE_PRICE_TABLE to a JSON price table for cost accounting
yasa-vulnagent run /absolute/path/to/repository
```

Discover can also be resumed directly from an existing run record without triggering the later audit stage:

```bash
yasa-vulnagent discover --run-file /path/to/run.json
```

Audit can be run or resumed from an existing run record:

```bash
yasa-vulnagent audit --run-file /path/to/run.json
```

Choose the audit input route on a new run with `--audit-mode entries|patches|combined` (default `combined`). All routes require init and discover. `prepare` consumes the selected inputs; `plan`, `trace`, and `recon` require a configured model whenever business tasks exist; `verify` requires one whenever candidate flows exist. `gate` is deterministic and calls no model; `finalize` writes the gate status.

The validate environment builder can be run or resumed from an existing run record:

```bash
yasa-vulnagent environment --run-file /path/to/run.json
```

Add `--rebuild` to ignore a ready image and plan/build again. The subgraph is `preflight → plan → plan_gate → build → smoke → snapshot → finalize`; `plan` and `diagnose` use an agent, while Docker flags and smoke isolation are code-controlled. A ready run writes `stages/validate/environment/handle.json`; blocked or failed runs remove it. This command builds the environment only; it does not execute application services or validate findings.

Runtime validation can be run or resumed from a run with a complete or partial audit:

```bash
yasa-vulnagent validate --run-file /path/to/run.json
```

Use `--finding ID` to select explicit findings, `--environment auto|reuse|build` to control environment reuse, and `--rerun` to discard previous validation findings. Docker is a hard dependency when findings are selected: without a reachable Docker daemon the stage is `blocked` and does not fall back to host execution; an empty selection completes with a valid empty artifact. The agent controls container topology and chooses HTTP, CLI, test_case, or library_api reproduction; the code logs commands, applies a best-effort Docker deny list, and canonicalizes the result. `confirmed` and `rejected` require saved runtime evidence and a fresh verifier rerun. Without `--rerun`, valid plan/execute/verify artifacts are reused; a model configuration failure blocks the stage, while a retry-exhausted request marks that finding `unresolved` with `agent_stop_reason=model_request`. See [`docs/validate-flow.md`](docs/validate-flow.md).

Report generation can be run or resumed from a run with a complete or partial validate stage:

```bash
yasa-vulnagent report --run-file /path/to/run.json
```

Use `--finding ID` to select confirmed findings and `--rerun` to discard previous report findings and submissions. Only `confirmed` validation results are eligible. The stage scans local security policy files and the Git remote, uses a default GitHub-advisory-shaped route when no private route is confirmed, recalculates CVSS, and gates every ready item on a fresh independent review. It writes `report.json`, `summary.md`, per-finding `submissions/<id>.md`, and a local envelope JSON. It never sends or submits anything. See [`docs/report-flow.md`](docs/report-flow.md).

The module entry point can be used directly:

```bash
python -m yasa_vulnagent run /absolute/path/to/repository
```

The default record location is:

```text
<repository>/.yasa-vulnagent/runs/<run-id>/
├── run.log
├── run.json
└── stages/
```

Use `--output-dir` to choose the parent directory for run records. API keys are never written to run records or command output.

The init stage defaults to `yasa-vulnagent/.knowledge/cwe-top25-1435.xml.zip`. Relative `CWE_ARCHIVE_PATH` values are resolved from the project root; an absolute path overrides the default. Missing, corrupt, or incomplete CWE entries are recorded as `init_checks.cwe.status=unavailable` and as an init gap, and a warning is logged without blocking later init nodes.

YASA-MCP source is located at `tools/yasa-mcp/`, and native tools are located at `tools/yasa/`. Relative paths are resolved from the `yasa-vulnagent/` project root, so tools can be found even when the command starts from another working directory. Absolute paths can override external tool directories. A YASA initialization or MCP-check failure terminates the current run; a successful MCP query proves only that the service is reachable and returned a valid response, not that the repository contains a `main` function.

The documents stage reads only project-owned documentation and build/deployment configuration. It excludes third-party dependencies, generated material, runtime output, and real secret files. Each run stores `inventory.json`, source segments, per-material reading notes, an English `overview.md`, and a `chunks/` manifest directory plus `coverage.json` under `stages/init/documents/`. External pages may be opened only from HTTP(S) links found in local documents, with at most one same-host link followed. The default total budget is 30 minutes and can be adjusted through `DOCUMENTS_TIMEOUT` and related settings. A failure to read or parse one item remains `partial`/`unavailable` and the run continues; model authentication failures, missing dependencies, or globally unavailable configuration terminate the current run.

Documents and security-history model calls now use the shared agent loop under `src/yasa_vulnagent/agent/`: per-task time/model budgets, retry classification, token-aware context compaction, bounded tool-result rendering with artifact references, and usage accounting. Small and medium local documents can be read through explicit chunk tools (`DOCUMENTS_READ_MODE=auto`); larger documents keep the bounded map/reduce reader. Oversized text/PDF/DOCX reads and HTTP responses are rejected or truncated according to tool limits instead of being loaded wholesale. `init` also builds `index.sqlite`, an FTS5 index over document notes, historical commits, and patch units, for later on-demand retrieval.

Each discover screen wave shares time and model-call budgets (`DISCOVER_SCREEN_*`) and automatically runs three views in parallel on the initial wave. Screen, confirm, planner, and review run through one async task loop with token-aware compaction at whole tool-exchange boundaries, artifact-backed oversized tool results (`read_tool_result`), per-wave read caching, bounded text search, and usage accounting. A task may call `save_note` to keep scratch facts across compaction; notes and prior-findings from tasks sharing the same scope are read back from the ledger and injected as leads, not facts. When a budget is exhausted the loop makes one final tool-free call and records `stop_reason` plus `partial_summary`, so partial work is preserved instead of discarded. Token, attempt, retry, compaction, tool-call, and cost totals are written to `stages/discover/usage.json`. The run-local SQLite ledger owns the inventory, scopes, tasks, read receipts, notes, candidates, evidence, and full gaps; `state.json` keeps only counters, routing, and bounded summaries. Directory, glob, and text-search tools paginate through ledger-backed scopes, so a task prompt never contains the full repository path list. Without an API key, tasks remain pending and can be resumed later; files whose source was not read are never marked closed.

## Directory conventions

The init flowcharts, drawn from LangGraph node registrations, are in [`docs/init-flowcharts.md`](docs/init-flowcharts.md). They cover the outer graph, documents, security history, and patch graph.

The discover outer nodes and persistence boundary are in [`docs/discover-flowcharts.md`](docs/discover-flowcharts.md).

The audit graph, artifact paths, and node contracts are in [`docs/audit-framework.md`](docs/audit-framework.md).

The validate environment builder's state graph and node responsibilities are in [`docs/validate-environment-flow.md`](docs/validate-environment-flow.md).

The report contract, route statuses, fixed advisory shape, artifacts, and resume behavior are in [`docs/report-flow.md`](docs/report-flow.md).

Shared orchestration lives under `src/yasa_vulnagent/workflow/`; configuration and persistence live at the package root. The five stages live under `src/yasa_vulnagent/stages/<stage>/`. Discover is further split into `prepare/screen/confirm/review/finalize` node directories; audit is split into `prepare/plan/trace/recon/verify/gate/finalize` node directories. Future prompts, tools, or schemas should be added inside the directory for the relevant stage.

Each run uses this artifact structure:

```text
<repository>/.yasa-vulnagent/runs/<run-id>/
├── run.log
├── run.json
└── stages/
    ├── init/
    │   ├── stage.json
    │   ├── usage.json
    │   ├── index.sqlite
    │   ├── documents/
    │   │   ├── inventory.json
    │   │   ├── chunks/
    │   │   ├── coverage.json
    │   │   ├── sources/
    │   │   ├── notes/
    │   │   ├── tool-results/
    │   │   ├── overview.md
    │   │   └── usage.json
    │   └── security_history/
    │       ├── snapshot.json
    │       ├── candidates.json
    │       ├── reviews/
    │       ├── patches/
    │       ├── patch_graphs.json
    │       ├── summary.json
    │       ├── report.md
    │       └── usage.json
    ├── discover/
    │   ├── stage.json
    │   ├── state.json
    │   ├── ledger.sqlite
    │   ├── files.json
    │   ├── excluded-files.json
    │   ├── init-resources.json
    │   ├── prepare.json
    │   ├── screen/
    │   │   ├── tasks/
    │   │   └── waves/
    │   ├── review.json
    │   ├── confirmed-entries.json
    │   ├── index.json
    │   ├── usage.json
    │   └── tool-results/
    ├── audit/
    │   ├── stage.json
    │   ├── state.json
    │   ├── framework.json
    │   ├── prepare.json
    │   ├── audit.json
    │   ├── traces/
    │   │   └── <trace-id>.json
    │   ├── business-logic.json
    │   ├── report.md
    │   ├── index.json
    │   ├── validation.json
    │   └── usage.json
    ├── validate/
    │   ├── stage.json
    │   ├── validation.json
    │   ├── state.json
    │   ├── selection.json
    │   ├── index.json
    │   ├── usage.json
    │   ├── findings/
    │   │   └── <finding-id>/
    │   │       ├── plan.json
    │   │       ├── result.json
    │   │       ├── attempts/0001/commands.jsonl
    │   │       └── evidence files
    │   ├── verifier/
    │   │   └── <finding-id>/
    │   └── environment/
    │       ├── environment.json
    │       ├── handle.json
    │       ├── state.json
    │       ├── index.json
    │       ├── stage.json
    │       ├── Dockerfile
    │       ├── dockerignore
    │       ├── plans/
    │       ├── gates/
    │       └── attempts/
    └── report/
        ├── stage.json
        ├── state.json
        ├── report.json
        ├── routes.json
        ├── summary.md
        ├── index.json
        ├── usage.json
        ├── findings/
        │   └── <finding-id>/
        │       ├── material.json
        │       ├── draft.json
        │       ├── review.json
        │       └── *.agent.json
        └── submissions/
            ├── <finding-id>.md
            └── <finding-id>.json
```

`run.json` is the top-level summary, and each stage's `stage.json` stores that stage's record. Documents and security-history indexes are referenced by their corresponding fields in `run.json`. API keys are passed only through the LangGraph runtime context and are not written to these files.

Audit prepare, plan, trace, recon, and verify are implemented: `prepare.json` records the resolved inputs and route status; `audit.json` contains the projected scope, normalized entries/patches, planned tasks, category checks, patch mechanism checks, compact traces, behavior summaries, a recon summary, and logic tasks; full task traces live under `traces/`; and `business-logic.json` contains recon constraints, operations, and investigations. Plan has no separate `plan.json`. Trace produces candidate source-to-sink flows, not findings; recon produces business records and follow-up questions, not findings. Verify materializes candidate findings, runs fresh source-backed verification and independent reviews, and writes `findings`/`reviews`. Gate is deterministic and writes `audit.json.gate` plus gate-sourced gaps only for blocked finalization. Finalize uses the gate status for `audit.json`, `index.json`, `stage.json`, and `report.md` and preserves the business sidecar status. The audit stage's `validation.json` is `not_run` because dynamic validation is the later `validate` stage. Do not treat unverified candidates as audit findings.

Runtime progress is written both to the terminal and to `run.log` in the run directory. INFO records stages, LangGraph nodes, work-item counts, statuses, and elapsed time; long waits emit a heartbeat every 30 seconds. More detailed model or tool diagnostics use DEBUG. Logs do not contain API keys, prompts, or source text. Standard output still returns JSON only for script consumption.
