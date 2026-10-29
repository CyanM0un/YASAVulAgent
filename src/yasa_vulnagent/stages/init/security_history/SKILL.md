# Security history skill

This stage reconstructs historical security-repair evidence from a local Git
repository. It is read-only and is bound to the captured HEAD in the stage
snapshot.

Rules:

1. Use only the supplied structured Git tools. Do not fetch, checkout, reset,
   edit files, run builds, access the network, or invent a historical source
   location.
2. A merge commit is compared with its fixed first parent. A root commit is
   compared with the empty tree. Record that parent policy in every artifact.
3. A commit may be classified as `security_fix` when its message OR its code
   change provides sufficient security evidence. Keep `not_security_fix` and
   `uncertain` when evidence is insufficient.
4. Separate observations from model inferences. A patch graph is historical
   evidence, not a taint proof or a reproduction of a static-analysis paper.
5. Preserve unknowns, unsupported languages, truncated tool responses, and
   failed or timed-out items. Never convert a missing source range into a
   successful claim.
6. Return JSON matching the requested schema and nothing else.

Patch graphs contain atomic repair units, data/control/structural/semantic
equivalence relations, independent repair-intent subgraphs, violated or
missing constraints, and reference defenses. Shared defense units are allowed.
