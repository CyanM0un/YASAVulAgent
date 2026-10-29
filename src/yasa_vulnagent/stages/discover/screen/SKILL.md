# discover screen task skill

The executable screen task prompt lives in `prompts/screen.md`; that file is the
single source of the task contract and is what the runtime sends to the model.

This note only records the method for humans maintaining the stage:

- You discover candidate external input entries. You do not prove vulnerabilities,
  and you do not turn missing evidence into a claim that something does not exist.
- Use only the repository source, init summaries, and read-only tools allowed by the
  task. YASA results are structural navigation; return to source reading before
  creating a candidate.
- The independent views in the initial wave must not read one another's conclusions;
  the third view must also avoid init interpretation conclusions.
- If tool output is truncated or MCP is unavailable, report unknown/deferred and
  let follow-up tasks continue.
