# documents stage

The documents subgraph runs in this order:

```text
START → discover → read ↺ → summarize → END
```

`discover` manages candidate materials, `read` reads each material in bounded segments and saves notes, and `summarize` generates an English project overview from note batches. The model is supplied through the LangGraph runtime context; the API key does not enter graph state or run artifacts.

`SKILL.md` stores the shared reading rules, and `prompts/` stores the task prompts for the three nodes. Runtime artifacts are written under `stages/init/documents/` in the target repository run directory:

- `inventory.json`: material inventory, read status, warnings, and unknowns reported by the model.
- `sources/`: text segments actually returned by tools.
- `notes/`: structured English notes for each segment.
- `overview.md`: the synthesized project understanding. Open questions are also retained in the documents index under `unknowns`/`gaps`, leaving that index `partial`.

This version supports text files, text-based PDFs, and DOCX. Scanned PDFs, images, and legacy `.doc` files only produce warnings; no OCR or conversion is performed.
