# init stage

Prepares the analysis foundations for the target repository. The current first-level subgraph runs in this order:

```text
START → yasa → documents → cwe → security_history → END
```

The LangGraph flowchart for this stage is available at [`yasa-vulnagent/docs/init-flowcharts.md`](../../../../docs/init-flowcharts.md).

`yasa` has been migrated as a deterministic node that performs YASA initialization, checks cache status, and issues one MCP `get_function(name="main")` query. An empty query result still means that the MCP call succeeded. Initialization, status-check, or MCP-call failures terminate the current run.

`documents` has been migrated as an independent subgraph. It discovers project-owned documentation and build/deployment configuration, reads each item in bounded ranges, writes attributed reading notes, and finally produces an English project overview. Small and medium local documents use explicit chunk tools (`list_chunks`, `read_chunk`, `search_document`) with a chunk manifest and coverage ledger; larger documents use the bounded map/reduce reader. Read-only tools handle text files, text-based PDFs, and DOCX files with byte/page/block limits; external links may only be discovered from local documents and may follow at most one same-host link. A failure to read, parse, or produce model output for one item is recorded as a warning and the run continues; overall model unavailability terminates the current run.

`cwe` has been migrated as an offline ZIP/XML check. Missing, corrupt, or incomplete entries produce a warning and are recorded as `unavailable` in `init_checks.cwe`, while later nodes continue. `security_history` binds to one captured Git HEAD, uses only structured read-only Git tools to discover candidate repairs and review commits, and extracts a patch graph for `security_fix` commits with consistency checks against the supplied historical source references. A single commit failure or timeout is recorded in that commit's result and its gap is preserved; authentication errors, missing dependencies, or globally unavailable model configuration terminate the current run.

This stage does not define a `persist` node. Internal nodes do not write separate outer-stage records; the outer `init` stage writes `stages/init/stage.json` according to the shared stage contract, including `running`, `complete`/`partial`/`failed`, the four check results, and gaps.

## Node directories

- `yasa/`: YASA initialization, cache status, and MCP connectivity checks.
- `documents/`: document discovery, segmented reading, notes, and the project overview.
- `cwe/`: offline CWE Top 25 archive validation.
- `security_history/`: Git snapshot, candidate repairs, per-commit review, patch graph extraction, and evidence validation.

The CWE archive defaults to `yasa-vulnagent/.knowledge/cwe-top25-1435.xml.zip`. Relative `CWE_ARCHIVE_PATH` values are resolved from the `yasa-vulnagent/` project root; an absolute path overrides this default. YASA source and native tools default to `tools/yasa-mcp/` and `tools/yasa/`, respectively. These relative paths are also resolved from the project root and can be overridden with absolute `YASA_SOURCE_PATH` and `YASA_BIN_PATH` values.

The default security-history budget is 60 minutes, with at most 10 minutes for candidate discovery, at most 10 minutes per commit, and at most three commits processed in parallel. `SECURITY_HISTORY_*` settings can adjust these values. Artifacts are written under `stages/init/security_history/`: `snapshot.json` fixes the captured HEAD, `candidates.json` stores discovery results, `reviews/` stores per-commit decisions, and `patches/<commit>/` stores the diff source, validated `graph.json`, and `result.json`. `patch_graphs.json`, `summary.json`, and `report.md` provide the final summary.

## Harness capabilities and remaining work

The shared agent loop under `src/yasa_vulnagent/agent/` provides:

- **Task budgets and retries**: per-invocation model rounds, per-task caps, deadline checks, fatal/transient model-error classification, `Retry-After`, and one JSON repair call.
- **Context management**: token-aware compaction that preserves recent tool exchanges, converts older ones into receipt summaries, and keeps source locations.
- **Bounded tool results**: large results are written under `tool-results/` and replaced by a bounded excerpt plus an artifact reference; `read_tool_result` reads a window on demand.
- **Usage accounting**: prompt/completion/total tokens, attempts, retries, compactions, and optional cost from `USAGE_PRICE_TABLE`; written to `usage.json`.
- **Local retrieval index**: `stages/init/index.sqlite` contains FTS5 tables over document notes, historical commits, and patch units. It is rebuilt at the end of init, and history discovery can query document notes through the read-only `search_notes`, `search_commits`, and `search_units` tools.

The following capabilities remain intentionally deferred: checkpoint/resume between model and tool calls, task-local memory, grouped patch-graph synthesis, and vector retrieval. YASA and CWE continue to use deterministic flows.
