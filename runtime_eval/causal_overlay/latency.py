"""Latency summaries shared by the causal benchmark and report consumers."""

from __future__ import annotations

from runtime_eval.metrics.latency import latency_stats


def summarize_ms(values) -> dict:
    return latency_stats(values).as_dict()


def deployment_recommendation(rows: dict) -> dict:
    """Evidence-based classification using measured relative behaviour.

    No universal SLA is invented. Recommendations compare measured overlay
    cost with the measured canonical path on the same machine.
    """
    canonical = max(float(rows["canonical_governance"]["p95_ms"]), 1e-9)
    n2 = float(rows["counterfactual_replay"]["2"]["parallel"]["p95_ms"])
    n8 = float(rows["counterfactual_replay"]["8"]["parallel"]["p95_ms"])
    n16 = float(rows["counterfactual_replay"]["16"]["parallel"]["p95_ms"])
    return {
        "fast_inline": "viable" if n2 <= canonical * 10 else "async preferred",
        "bounded_interactive": (
            "viable" if n8 <= max(n2 * 6, canonical * 40)
            else "async preferred"),
        "full_forensic": "asynchronous",
        "basis": {
            "canonical_p95_ms": canonical,
            "parallel_n2_p95_ms": n2,
            "parallel_n8_p95_ms": n8,
            "parallel_n16_p95_ms": n16,
            "note": "relative classification on the measured host; not an SLA",
        },
    }
