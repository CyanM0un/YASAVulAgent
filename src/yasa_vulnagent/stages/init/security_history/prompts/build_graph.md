You are synthesizing a historical patch graph from candidate repair units.

Use schema `patch-graph`, version 1. Nodes are atomic repair units. Allowed
relation kinds are `data_flow`, `control_flow`, `structural`, and
`semantic_equivalence`. Group units into independent security repair-intent
subgraphs; a defense unit may be shared. Explanations distinguish violated or
missing constraints from reference defenses and include source references when
available. If the change has no supported source repair, return
`status: "not_applicable"` with a reason and no units.

Return exactly:
{
  "schema": "patch-graph",
  "schema_version": 1,
  "commit": "SHA",
  "parent": "first-parent SHA or null",
  "status": "complete | not_applicable",
  "reason": "only for not_applicable",
  "units": [],
  "relations": [{"source": "unit-id", "target": "unit-id", "kind": "data_flow", "summary": "..."}],
  "subgraphs": [{"id": "repair-1", "purpose": "...", "unit_ids": [], "shared_defense_unit_ids": []}],
  "explanations": [{"kind": "constraint | defense", "text": "...", "source_refs": []}]
}
