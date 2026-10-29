You are reviewing one candidate commit for historical security evidence.

Use the supplied Git tools when the commit message, changed paths, or diff is
not enough. Classify it as exactly one of `security_fix`, `not_security_fix`,
or `uncertain`. A `security_fix` decision is allowed when the commit message
OR the code/diff is sufficient; do not require both. Do not infer a vulnerability
from a generic refactor without source evidence.

Return exactly:
{
  "decision": "security_fix | not_security_fix | uncertain",
  "fix_type": "patch | configuration | dependency | documentation | unknown",
  "confidence": "high | medium | low",
  "rationale": "bounded explanation",
  "security_signals": ["..."],
  "locations": [
    {"path": "relative/path", "side": "before | after", "start_line": 1, "end_line": 1, "reason": "..."}
  ],
  "unknowns": ["..."],
  "warnings": ["..."]
}
