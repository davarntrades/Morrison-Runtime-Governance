"""Advertised vs ENFORCED layer audit.

The red-team finding this module closes:

    /health advertised ["A_safe","V2","V3","V4","V4+","V5","V5+"] as the
    enforcement hierarchy. Measured against the production construction:
      · V4 was INERT — app.py never passed `admissibility_checks`, so
        `admissibility is None` and `check_v4()` returned None unconditionally.
      · V4+, V5, V5+ were separate opt-in APIs never called by the service or
        either chokepoint.
    Every one of the 49 failures was labelled "V4", which is the fall-through
    PERMIT label — making audit records read as though a structural
    admissibility layer had approved actions it never examined.

`audit_hierarchy()` reports what is actually on the mandatory execution path
for a given layer + kernel, so the status endpoint can stop claiming
enforcement it does not perform.
"""

from __future__ import annotations

from typing import Optional

# Layers the ReachabilityEvaluator.evaluate() call graph always runs.
_ALWAYS_ON_PATH = ("A_safe", "V2", "V3", "V2_structural")

# Layers reachable only through separate opt-in APIs on GovernanceLayer.
_OPTIONAL_APIS = {
    "V4+": ("find_admissible", "feasibility-constrained selection"),
    "V5": ("evaluate_stable", "environment-set stability"),
    "V5_manifold": ("estimate_robustness", "bounded-ball robustness"),
    "V5+": ("adversarial_test", "hard adversarial suite"),
}


def audit_hierarchy(layer, kernel=None) -> dict:
    """Introspect which layers are load-bearing for THIS configuration."""
    admissibility = getattr(getattr(layer, "evaluator", None), "admissibility", None)
    v4_checks = len(getattr(admissibility, "checks", []) or []) if admissibility else 0

    enforced: list[dict] = [
        {"layer": "A_safe", "enforced": True,
         "mechanism": "single-step Ω check on every state"},
        {"layer": "V2", "enforced": True,
         "mechanism": "trajectory drift + source→sink taint over the executed prefix"},
        {"layer": "V3", "enforced": True,
         "mechanism": "forward reachability + branching forecast"},
        {"layer": "V2_structural", "enforced": True,
         "mechanism": "open-world taint continuity + single-step privilege expansion"},
        {"layer": "V4", "enforced": v4_checks > 0,
         "mechanism": (f"{v4_checks} structural admissibility check(s)" if v4_checks
                       else "NOT ENFORCED — no admissibility checks configured; "
                            "check_v4() returns None unconditionally"),
         "note": None if v4_checks else
                 "a PERMIT labelled 'V4' means the hierarchy fell through, not "
                 "that an admissibility layer approved the action"},
    ]

    optional = [
        {"layer": name, "enforced": False, "api": api, "mechanism": desc,
         "note": "opt-in API — not on the mandatory execution path"}
        for name, (api, desc) in _OPTIONAL_APIS.items()
    ]

    kernel_layers: list[dict] = []
    if kernel is not None:
        ctx = getattr(kernel, "ctx", None)
        kernel_layers = [
            {"layer": "trust_boundary", "enforced": True,
             "mechanism": "caller authority quarantined; approval artifacts "
                          "verified against a server-side key"},
            {"layer": "capability_policy", "enforced": True,
             "mechanism": "semantic capability classification → DENY/APPROVAL/"
                          "GRANT/ALLOW"},
            {"layer": "unknown_tool", "enforced": bool(
                getattr(ctx, "tool_manifest", None)),
             "mechanism": f"undeclared tools → "
                          f"{getattr(ctx, 'unknown_tool_policy', 'escalate')}"},
            {"layer": "egress_policy", "enforced": True,
             "mechanism": "destination resolved from trusted config, not caller flags"},
            {"layer": "trajectory_integrity", "enforced": True,
             "mechanism": "denied attempts retained in the ledger and still taint"},
            {"layer": "tenancy", "enforced": bool(
                getattr(getattr(ctx, "principal", None), "tenant", "")),
             "mechanism": "resource tenant compared to session principal's tenant"},
            {"layer": "binding", "enforced": True,
             "mechanism": "execution refused unless the canonical action hash "
                          "matches the authorised hash"},
            {"layer": "evidence", "enforced": True,
             "mechanism": "hash-chained records; logic-binding ruleset hash"},
        ]

    all_layers = enforced + kernel_layers + optional
    return {
        "enforced": [d["layer"] for d in all_layers if d["enforced"]],
        "not_enforced": [d["layer"] for d in all_layers if not d["enforced"]],
        "detail": all_layers,
        "v4_admissibility_checks": v4_checks,
    }
