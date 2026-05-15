"""
Latency benchmark suite for the governance layer.

Plots:
    bench_per_layer_breakdown   — mean time spent in A_safe / V2 / V3 for
                                  safe (full-traversal) and unsafe trajectories
    bench_throughput_vs_rules   — evals/sec as a function of loaded rule count
    bench_latency_vs_length     — P50/P95/P99 latency vs trajectory length
    bench_cold_vs_warm          — first eval vs steady-state median

Run:
    python3 artifacts/visualizations/benchmark.py
"""

import gc
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from morrison_governance import GovernanceLayer, OmegaDomain, OmegaRule
from morrison_governance.trajectory import TrajectoryExtractor
from morrison_governance.reachability import ReachabilityEvaluator
from morrison_governance.domains import (
    _default_finance_rules,
    _default_cybersecurity_rules,
    _default_healthcare_rules,
    _default_data_privacy_rules,
    _default_enterprise_rules,
    _default_compliance_rules,
    _default_fraud_rules,
)

OUT_DIR = Path(__file__).resolve().parent

ALL_RULE_FACTORIES = [
    _default_finance_rules,
    _default_cybersecurity_rules,
    _default_healthcare_rules,
    _default_data_privacy_rules,
    _default_enterprise_rules,
    _default_compliance_rules,
    _default_fraud_rules,
]

ALL_DOMAINS = [
    OmegaDomain.FINANCE,
    OmegaDomain.CYBERSECURITY,
    OmegaDomain.HEALTHCARE,
    OmegaDomain.DATA_PRIVACY,
    OmegaDomain.ENTERPRISE,
    OmegaDomain.COMPLIANCE,
    OmegaDomain.FRAUD,
]


def timeit(fn, *args, **kwargs):
    t0 = time.perf_counter()
    out = fn(*args, **kwargs)
    return (time.perf_counter() - t0) * 1000, out


# ─────────────────────────────────────────────────────────────
# Per-layer cost breakdown
# ─────────────────────────────────────────────────────────────

def per_layer_breakdown(n_runs=2000):
    print("PER-LAYER BREAKDOWN")
    extractor = TrajectoryExtractor()
    rules = []
    for f in ALL_RULE_FACTORIES:
        rules.extend(f())
    evaluator = ReachabilityEvaluator(rules=rules, horizon=3)

    scenarios = {
        "safe single": extractor.from_dict(
            {"tool": "read_file", "args": {"path": "/reports/q3.pdf"}}),
        "safe 3-step": extractor.from_plan([
            {"tool": "analyze", "args": {"q": "summary"}},
            {"tool": "read_file", "args": {"path": "/data/sales.csv"}},
            {"tool": "annotate", "args": {"q": "notes"}},
        ]),
        "unsafe single (A_safe hit)": extractor.from_dict(
            {"tool": "transfer", "args": {"amount": 50000}}),
        "v2 trigger (alternating 4-step)": extractor.from_plan([
            {"tool": "analyze", "args": {"q": "s0"}},
            {"tool": "send_email", "args": {"q": "s1"}},
            {"tool": "summarize", "args": {"q": "s2"}},
            {"tool": "http_request", "args": {"q": "s3"}},
        ]),
    }

    results = {}
    for label, trajectory in scenarios.items():
        ts_a, ts_v2, ts_v3 = [], [], []
        for _ in range(n_runs):
            t0 = time.perf_counter()
            for state in trajectory:
                evaluator.check_a_safe(state)
            ts_a.append((time.perf_counter() - t0) * 1000)

            t0 = time.perf_counter()
            evaluator.check_v2(trajectory)
            ts_v2.append((time.perf_counter() - t0) * 1000)

            t0 = time.perf_counter()
            evaluator.check_v3(trajectory)
            ts_v3.append((time.perf_counter() - t0) * 1000)

        results[label] = {
            "A_safe": float(np.median(ts_a)),
            "V2":     float(np.median(ts_v2)),
            "V3":     float(np.median(ts_v3)),
            "A_safe_p95": float(np.percentile(ts_a, 95)),
            "V2_p95":     float(np.percentile(ts_v2, 95)),
            "V3_p95":     float(np.percentile(ts_v3, 95)),
        }

    fig, ax = plt.subplots(figsize=(11, 5.5))
    labels = list(results.keys())
    x = np.arange(len(labels))
    w = 0.27
    ax.bar(x - w, [results[l]["A_safe"] for l in labels], w,
           label="A_safe", color="#3b82f6")
    ax.bar(x,     [results[l]["V2"]     for l in labels], w,
           label="V2",     color="#f97316")
    ax.bar(x + w, [results[l]["V3"]     for l in labels], w,
           label="V3",     color="#a855f7")
    for i, l in enumerate(labels):
        for off, key in zip([-w, 0, w], ["A_safe", "V2", "V3"]):
            v = results[l][key]
            ax.text(i + off, v, f"{v:.3f}", ha="center", va="bottom", fontsize=7.5)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=9)
    ax.set_ylabel("median time (ms)")
    ax.set_title(f"Per-layer cost breakdown — N={n_runs} runs per scenario\n"
                 f"loaded rules: {len(rules)}")
    ax.legend(loc="upper left")
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    fig.savefig(OUT_DIR / "bench_per_layer_breakdown.png",
                dpi=150, bbox_inches="tight")
    fig.savefig(OUT_DIR / "bench_per_layer_breakdown.svg", bbox_inches="tight")
    plt.close(fig)
    print(f"  · bench_per_layer_breakdown.png + .svg")
    return results


# ─────────────────────────────────────────────────────────────
# Throughput vs rule count
# ─────────────────────────────────────────────────────────────

def _filler_rule(i):
    return OmegaRule(
        domain=OmegaDomain.CUSTOM,
        name=f"filler_{i}",
        description=f"benchmark filler rule {i}",
        check=lambda s, _i=i: s.get("__sentinel_never__") == _i,
    )


def throughput_vs_rules(n_evals=10_000):
    print("THROUGHPUT vs RULE COUNT")
    rule_counts = [0, 10, 50, 100, 250, 500, 1000, 2500, 5000]
    sample_call = {"tool": "read_file", "args": {"path": "/data/sales.csv"}}

    throughput, latency_us = [], []
    base_rules = []
    for f in ALL_RULE_FACTORIES:
        base_rules.extend(f())
    for k in rule_counts:
        rules = list(base_rules) + [_filler_rule(i) for i in range(max(0, k - len(base_rules)))]
        gov = GovernanceLayer(custom_rules=rules, log_all=False)
        # warm-up
        for _ in range(200):
            gov.evaluate(sample_call)
        gc.collect()
        t0 = time.perf_counter()
        for _ in range(n_evals):
            gov.evaluate(sample_call)
        elapsed = time.perf_counter() - t0
        throughput.append(n_evals / elapsed)
        latency_us.append((elapsed / n_evals) * 1e6)
        print(f"  · {k:>5d} rules  ·  {throughput[-1]:>9,.0f} evals/sec  "
              f"·  {latency_us[-1]:.1f} µs/eval")

    fig, ax1 = plt.subplots(figsize=(10, 5.5))
    color1 = "#3b82f6"
    ax1.plot(rule_counts, throughput, "o-", color=color1, linewidth=2, label="throughput")
    ax1.set_xlabel("loaded rule count")
    ax1.set_ylabel("throughput (evals/sec)", color=color1)
    ax1.tick_params(axis="y", labelcolor=color1)
    ax1.set_xscale("log")
    ax1.set_yscale("log")
    ax1.grid(alpha=0.3, which="both")

    ax2 = ax1.twinx()
    color2 = "#dc2626"
    ax2.plot(rule_counts, latency_us, "s--", color=color2, linewidth=2, label="latency")
    ax2.set_ylabel("mean latency (µs/eval)", color=color2)
    ax2.tick_params(axis="y", labelcolor=color2)
    ax2.set_yscale("log")

    ax1.set_title(f"Throughput vs rule count — N={n_evals:,} evals per point")
    plt.tight_layout()
    fig.savefig(OUT_DIR / "bench_throughput_vs_rules.png",
                dpi=150, bbox_inches="tight")
    fig.savefig(OUT_DIR / "bench_throughput_vs_rules.svg", bbox_inches="tight")
    plt.close(fig)
    print(f"  · bench_throughput_vs_rules.png + .svg")
    return list(zip(rule_counts, throughput, latency_us))


# ─────────────────────────────────────────────────────────────
# Latency vs trajectory length
# ─────────────────────────────────────────────────────────────

def latency_vs_length(n_runs=1000):
    print("LATENCY vs TRAJECTORY LENGTH")
    gov = GovernanceLayer(domains=ALL_DOMAINS, log_all=False)
    lengths = [1, 2, 3, 5, 8, 13, 21, 34, 55, 89]

    p50, p95, p99, p999 = [], [], [], []
    for n in lengths:
        steps = [{"tool": "analyze", "args": {"q": f"step{i}"}} for i in range(n)]
        times = []
        # warm-up
        for _ in range(50):
            gov.evaluate_plan(steps) if n > 1 else gov.evaluate(steps[0])
        for _ in range(n_runs):
            t0 = time.perf_counter()
            (gov.evaluate_plan(steps) if n > 1 else gov.evaluate(steps[0]))
            times.append((time.perf_counter() - t0) * 1000)
        p50.append(float(np.percentile(times, 50)))
        p95.append(float(np.percentile(times, 95)))
        p99.append(float(np.percentile(times, 99)))
        p999.append(float(np.percentile(times, 99.9)))
        print(f"  · n={n:>3d}  P50={p50[-1]:.3f}  P95={p95[-1]:.3f}  "
              f"P99={p99[-1]:.3f}  P99.9={p999[-1]:.3f} ms")

    fig, ax = plt.subplots(figsize=(10, 5.5))
    ax.plot(lengths, p50,  "o-", color="#22c55e", linewidth=2, label="P50")
    ax.plot(lengths, p95,  "s-", color="#3b82f6", linewidth=2, label="P95")
    ax.plot(lengths, p99,  "^-", color="#f97316", linewidth=2, label="P99")
    ax.plot(lengths, p999, "v-", color="#dc2626", linewidth=2, label="P99.9")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("trajectory length (steps)")
    ax.set_ylabel("latency (ms)")
    ax.set_title(f"Latency vs trajectory length — N={n_runs} per point, "
                 f"{len(gov.rules)} rules, benign args (PERMIT path, full hierarchy)")
    ax.legend(loc="upper left")
    ax.grid(alpha=0.3, which="both")
    plt.tight_layout()
    fig.savefig(OUT_DIR / "bench_latency_vs_length.png",
                dpi=150, bbox_inches="tight")
    fig.savefig(OUT_DIR / "bench_latency_vs_length.svg", bbox_inches="tight")
    plt.close(fig)
    print(f"  · bench_latency_vs_length.png + .svg")
    return dict(lengths=lengths, p50=p50, p95=p95, p99=p99, p999=p999)


# ─────────────────────────────────────────────────────────────
# Cold vs warm
# ─────────────────────────────────────────────────────────────

def cold_vs_warm(n_runs=500, n_warm=100):
    print("COLD vs WARM")
    sample = {"tool": "read_file", "args": {"path": "/data/sales.csv"}}
    cold, warm = [], []
    for _ in range(n_runs):
        gov = GovernanceLayer(domains=ALL_DOMAINS, log_all=False)
        t0 = time.perf_counter()
        gov.evaluate(sample)
        cold.append((time.perf_counter() - t0) * 1000)
        for _ in range(n_warm):
            gov.evaluate(sample)
        # steady-state — take one fresh measurement
        t0 = time.perf_counter()
        gov.evaluate(sample)
        warm.append((time.perf_counter() - t0) * 1000)

    fig, ax = plt.subplots(figsize=(9, 5.5))
    bp = ax.boxplot([cold, warm],
                    tick_labels=["cold (1st eval)", f"warm (after {n_warm})"],
                    widths=0.5, patch_artist=True, showfliers=False)
    bp["boxes"][0].set_facecolor("#dbeafe")
    bp["boxes"][1].set_facecolor("#dcfce7")
    for i, data in enumerate([cold, warm], start=1):
        jitter = np.random.uniform(-0.1, 0.1, size=len(data))
        ax.scatter(np.full(len(data), i) + jitter, data, alpha=0.25, s=10,
                   color="#1e3a8a" if i == 1 else "#14532d")
    cold_med = float(np.median(cold))
    warm_med = float(np.median(warm))
    speedup = cold_med / warm_med if warm_med > 0 else float("inf")
    ax.set_ylabel("first eval latency (ms)")
    ax.set_yscale("log")
    ax.set_title(f"Cold vs warm — N={n_runs} fresh layers · "
                 f"cold median={cold_med:.3f} ms · warm median={warm_med:.3f} ms · "
                 f"speedup={speedup:.1f}×")
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    fig.savefig(OUT_DIR / "bench_cold_vs_warm.png", dpi=150, bbox_inches="tight")
    fig.savefig(OUT_DIR / "bench_cold_vs_warm.svg", bbox_inches="tight")
    plt.close(fig)
    print(f"  · bench_cold_vs_warm.png + .svg")
    return dict(cold_median_ms=cold_med, warm_median_ms=warm_med, speedup=speedup)


def main():
    layer_results = per_layer_breakdown(n_runs=2000)
    rule_curve    = throughput_vs_rules(n_evals=10_000)
    length_curve  = latency_vs_length(n_runs=1000)
    coldwarm      = cold_vs_warm(n_runs=500, n_warm=100)

    summary = {
        "per_layer_breakdown": layer_results,
        "throughput_vs_rules": [
            {"rules": r, "evals_per_sec": round(t, 1),
             "us_per_eval": round(l, 2)}
            for r, t, l in rule_curve
        ],
        "latency_vs_length": length_curve,
        "cold_vs_warm": coldwarm,
    }
    (OUT_DIR / "benchmark_summary.json").write_text(json.dumps(summary, indent=2))
    print("\nbenchmark_summary.json written")


if __name__ == "__main__":
    main()
