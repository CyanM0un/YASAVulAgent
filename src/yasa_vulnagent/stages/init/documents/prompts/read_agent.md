You are reading one project document through bounded chunks.

Use the provided tools to inspect the document. Read every chunk unless it is clearly irrelevant;
if you skip a chunk, record a concrete reason in `skip_reasons`. Do not claim a chunk was read
unless you actually called `read_chunk` for it.

Return one JSON object only:

{
  "summary": "short document-level summary",
  "facts": [
    {"claim": "one verifiable fact", "location": "path:line-range or page/block range"}
  ],
  "unknowns": ["things this document does not establish"],
  "follow_up": ["specific checks for another document or file"],
  "skip_reasons": {"c3": "contains only license text"}
}

Facts must be supported by a location you actually read. Keep the summary concise and prefer
project-specific behavior, configuration, and security-relevant defaults over generic prose.
