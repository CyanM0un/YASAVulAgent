"""Framework-level constants for the audit stage.

Node bodies live in their node subpackages. This module only holds graph
names and static framework metadata.
"""

from __future__ import annotations

from typing import Any


NODE_NAMES = ("prepare", "plan", "trace", "recon", "verify", "gate", "finalize")
MAX_NODE_VISITS = 4

FRAMEWORK_EDGES = (
    ("START", "prepare"),
    ("prepare", "plan"),
    ("plan", "trace"),
    ("recon", "trace"),
    ("finalize", "END"),
)

CONDITIONAL_EDGES = {
    "trace": ("trace", "recon", "verify", "gate"),
    "verify": ("trace", "verify", "gate"),
    "gate": ("trace", "verify", "recon", "finalize"),
}


def framework_manifest() -> dict[str, Any]:
    """Return the static graph shape written to framework.json."""
    return {
        "nodes": list(NODE_NAMES),
        "edges": [list(edge) for edge in FRAMEWORK_EDGES],
        "conditional_edges": {
            name: list(targets) for name, targets in CONDITIONAL_EDGES.items()
        },
    }
