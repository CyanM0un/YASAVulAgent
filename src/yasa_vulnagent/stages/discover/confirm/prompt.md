You are executing one bounded discover.confirm task.

A candidate is only a lead. Confirm it against source; do not confirm from a search hit, a filename, or another model's summary. Read the candidate location and inspect the whole same file for sibling handlers, wrappers, registration, callbacks, and activation branches. You may read directly related callers/callees in other files, but broad new scope must be returned as `screen_scope` instead of explored without bound.

A confirmed entry needs all five source-backed fields:
1. input_origin: where the value enters from an external or low-trust source.
2. registration: the registration/call point that makes the path reachable.
3. activation: the condition or lifecycle that activates it.
4. input_binding: how the input reaches parameters or sinks.
5. trust_boundary: where trust changes and what constrains it.

Each field must contain `summary` and `evidence_refs`. Evidence refs must be `source:path:start-end`, `evidence:id`, or `entry:id` and must resolve in the current repository. Missing or invalid evidence downgrades a claimed confirmation to `unknown`; it is not permission to guess.

Return JSON only:
{
  "same_file_reviewed": true,
  "entry_results": [
    {
      "entry_id": "entry-...",
      "status": "confirmed|not_applicable|unknown|deferred",
      "role": "source|registration|activation|binding|boundary|unknown",
      "summary": "short source-backed conclusion",
      "location": {"path": "src/File.java", "line_start": 10, "line_end": 20},
      "input_origin": {"summary": "...", "evidence_refs": ["source:src/File.java:10-12"]},
      "registration": {"summary": "...", "evidence_refs": ["source:src/File.java:13-14"]},
      "activation": {"summary": "...", "evidence_refs": ["source:src/File.java:15-16"]},
      "input_binding": {"summary": "...", "evidence_refs": ["source:src/File.java:17-18"]},
      "trust_boundary": {"summary": "...", "evidence_refs": ["source:src/File.java:19-20"]},
      "reason": "required for non-confirmed outcomes",
      "owner": "required for unknown/deferred",
      "attempts": ["what was checked for unknown"],
      "reopen_condition": "required for deferred/unknown",
      "evidence_refs": ["source:src/File.java:10-20"]
    }
  ],
  "same_file_targets": [
    {"path": "src/File.java", "line_start": 1, "line_end": 1, "question": "Inspect an uncovered sibling entry."}
  ],
  "screen_scope": [
    {"paths": ["src/Other.java"], "question": "Inspect broad related scope.", "reason": "Requires a separate screen task."}
  ],
  "feature_observations": []
}

Use `not_applicable` only when source shows the candidate is not an external entry and explain why. Use `unknown` when evidence is insufficient after real attempts; use `deferred` only when a runtime or environment condition remains, with a reopen condition. `same_file_targets` is for remaining same-file scope; `screen_scope` is for broad cross-file scope. Feature observations use the same shape as screen: kind, name, role, definition, evidence_refs, and query.
