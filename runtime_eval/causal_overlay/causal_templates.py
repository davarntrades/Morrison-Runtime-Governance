"""Explicit v0.1 SCM templates. No learned or LLM-generated graph exists."""

from __future__ import annotations

from .models import CausalEdge
from .variable_extractor import (
    ExtractionResult, SECRET_EXFILTRATION, UNAUTHORIZED_TRANSFER,
)


CAUSAL_TEMPLATE_VERSION = "prototype-0.1"


_TEMPLATES = {
    SECRET_EXFILTRATION: (
        ("sensitive_data_acquired", "forbidden_transition", "enables"),
        ("source_read_permission", "sensitive_data_acquired", "enables"),
        ("source_tool_available", "sensitive_data_acquired", "enables"),
        ("external_egress_enabled", "forbidden_transition", "enables"),
        ("external_egress_permission", "forbidden_transition", "enables"),
        ("trust_boundary_external", "forbidden_transition", "enables"),
        ("safeguard_active", "forbidden_execution", "inhibits"),
        ("approval_required", "forbidden_execution", "inhibits"),
    ),
    UNAUTHORIZED_TRANSFER: (
        ("transfer_permission", "forbidden_transition", "enables"),
        ("transfer_tool_available", "forbidden_transition", "enables"),
        ("transfer_amount", "forbidden_transition", "contributes"),
        ("approval_present", "authorised_execution", "enables"),
        ("approval_required", "unauthorised_execution", "inhibits"),
        ("safeguard_active", "forbidden_execution", "inhibits"),
    ),
}


def build_template(extraction: ExtractionResult) -> tuple[CausalEdge, ...]:
    if extraction.scenario not in _TEMPLATES:
        return ()
    by_name = {var.name: var for var in extraction.variables}
    edges = []
    for parent, child, relation in _TEMPLATES[extraction.scenario]:
        var = by_name.get(parent)
        if var is None:
            continue
        edges.append(CausalEdge(
            parent=parent, child=child, relation=relation,
            provenance=var.provenance))
    return tuple(edges)
