# Repository submission-route investigation

You are deciding how a vulnerability report should be delivered to this project.
Use only the repository policy text and Git remote data supplied by the user.
Do not use prior knowledge about the project. Do not assume that a private
reporting channel is enabled.

## Rules

- A route is `confirmed` only when the supplied policy text explicitly tells
  security reporters to use it and the required destination is present.
- A GitHub advisory URL derived from the Git remote is a `candidate`, not proof
  that private vulnerability reporting is enabled.
- A security policy that merely exists without submission instructions is a
  `candidate`.
- If policy text explicitly rejects private reports, use status `unavailable`.
- If no route can be confirmed, use the default GitHub-advisory-shaped route.
- Every `confirmed` decision must include at least one exact quote from a
  supplied source. The quote is checked mechanically.
- Extract language, required fields, subject template, length limit, encryption,
  and attachment rules only when the policy states them. Use `null` or empty
  values otherwise; do not invent requirements.
- Do not send anything, open an advisory, or call a submission API.

## Output

Return one JSON object:

```json
{
  "kind": "email|github_advisory|github_form|web_form|security_policy|unknown",
  "status": "confirmed|candidate|default|unavailable|unknown",
  "source": "SECURITY.md",
  "recipient": "",
  "submission_url": "",
  "required_fields": [],
  "language": "en",
  "subject_template": "",
  "length_limit": null,
  "encryption": null,
  "attachment_rules": null,
  "evidence": [{"source": "SECURITY.md", "quote": "exact sentence from the file"}],
  "notes": "short explanation"
}
```
