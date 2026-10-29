# Self-contained vulnerability advisory draft

Write one submission-ready advisory for exactly one confirmed vulnerability.
The body must stand alone: a maintainer who has not seen the audit or validation
artifacts must be able to understand, reproduce, and fix the issue.

## Fixed body shape

Use exactly these five top-level headings, in this order, each on its own line:

```markdown
# Title
# Summary
# Details
# Proof of concept
# Impact
```

Use `##` subsections inside them. Do not add or remove top-level headings.
Keep the five top-level headings and the structural subsection labels in
English even when the requested report language is not English; translate the
prose, not the headings. Keep labels such as `Tested revision`, `Base score`,
`Affected component`, `CWE`, and `CVSS` in English for machine checks.
Do not put `#` comments at the start of lines inside fenced code blocks in a way
that could be mistaken for a top-level heading; use `##` or another comment
style there.

## Required content

- `# Title`: a specific vulnerability title naming the affected component.
- `# Summary`: affected component, tested revision or commit, the security
  boundary that is crossed, and one sentence on impact.
- `# Details`: root cause, source-to-sink path, affected component and revision,
  attack preconditions, expected versus observed behavior. Include relevant
  code or configuration inline. Explain why the observed behavior violates the
  intended security boundary.
- `# Proof of concept`: exact setup, inputs, commands, and expected versus
  observed result. Use the verified validation reproduction; do not invent a
  different exploit. Include the minimum decisive steps and any cleanup.
- `# Impact`: realistic impact, who can trigger it, prerequisites, CWE, severity,
  and a CVSS vector with metric-by-metric justification. Include remediation and
  a regression test suggestion.

Every factual claim must come from the supplied audit and validation material.
Do not invent version ranges, exploit reliability, deployment exposure, or a
fix that was not verified. State the tested revision exactly as supplied. If a
fact is unknown, say it is unknown instead of guessing.

## CVSS and CWE

- Use CVSS 3.1 unless the supplied route explicitly requires 4.0.
- Write the complete vector, for example `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`.
- Write the base score with one decimal and the matching severity word, for
  example `Base score: 9.8 (critical)`.
- The harness recalculates the base score from the vector. If your score does
  not match, the draft will be returned for repair.
- Choose only from the supplied audit CWE identifiers. Do not add a CWE that is
  not in that list.
- Justify each CVSS metric from the verified test scene.

## Safety and hygiene

- Redact secrets, tokens, passwords, private keys, and personal data.
- Do not mention internal workflows, run identifiers, stage directories, agent
  names, `validation.json`, `audit.json`, or host-specific absolute paths.
- Do not claim the report was submitted or that the project accepted it.
- Keep the body under 30,000 characters.

## Output

Return one JSON object only:

```json
{
  "title": "specific title",
  "cwe": ["CWE-78"],
  "severity": "critical",
  "cvss": {
    "version": "3.1",
    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "justification": "metric-by-metric justification tied to the verified scene"
  },
  "body": "# Title\n...\n# Impact\n...",
  "subject": "optional email subject"
}
```
