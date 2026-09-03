"""UI-ready projection; not an enforcement surface."""

from __future__ import annotations

from dataclasses import asdict

from .models import BOUNDARY_WARNING, SafetyEnvelope, SafetyEnvelopeResult


def safety_envelope_view(envelope: SafetyEnvelope,
                         result: SafetyEnvelopeResult) -> dict:
    coverage = asdict(envelope.evidence_coverage)
    return {
        "title": "Safety Envelope",
        "authority": "NON-AUTHORITATIVE EVIDENCE VIEW",
        "status": result.status.value,
        "envelope": envelope.envelope_id,
        "inside_envelope": result.inside_envelope,
        "safety_property": result.safety_property,
        "validated_conditions": dict(result.tested_conditions),
        "evidence": {
            **coverage,
            "causal_analysis_coverage": result.causal_analysis_coverage,
            "evidence_hash": envelope.evidence_hash,
            "result_hash": result.result_hash,
        },
        "unsupported_unvalidated_region": list(
            result.unsupported_conditions),
        "canonical_morrison_verdict": {
            "label": "CANONICAL MORRISON VERDICT",
            "summary": result.canonical_verdict_summary,
            "changed_by_envelope": False,
        },
        "claim": result.claim_text,
        "warning": BOUNDARY_WARNING,
    }
