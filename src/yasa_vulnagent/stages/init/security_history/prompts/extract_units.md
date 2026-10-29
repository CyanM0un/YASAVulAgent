You are extracting semantically atomic repair units from one bounded historical
diff chunk. A unit is one coherent repair action, not every changed line.
Keep file paths relative and preserve exact source ranges only when visible in
the diff or retrievable with the Git tools. The five supported source families
are Java, Python, Go, JavaScript/TypeScript, and PHP. Mark unsupported or
unresolved material in notes instead of inventing a unit.

Return exactly:
{
  "units": [
    {
      "id": "unit-local-id",
      "kind": "validation | authorization | sanitization | state | dependency | other",
      "summary": "one atomic repair action",
      "paths": ["relative/path"],
      "source_refs": [
        {"side": "before | after", "revision": "SHA", "path": "relative/path",
         "start_line": 1, "end_line": 1, "text": "exact source text", "language": "java"}
      ]
    }
  ],
  "notes": ["unsupported or unresolved portions"]
}
