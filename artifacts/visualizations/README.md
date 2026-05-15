# Perturbation-space heat maps + runtime benchmarks

Three generator scripts drive the `GovernanceLayer` API across a sweep of
input perturbations and plot admissibility (PERMIT / BLOCK @ layer) plus
runtime behaviour. Each plot is written as `.png` (raster) and `.svg`
(vector).

## Regenerate

```
pip install matplotlib numpy
python3 artifacts/visualizations/generate.py    # v1 — 4 domains, basic perturbations
python3 artifacts/visualizations/sweep_v2.py    # v2 — 3 new domains, harder perturbations
python3 artifacts/visualizations/benchmark.py   # latency benchmark suite
```

## v1 layout — `generate.py`

Twelve heat maps, three per domain — each chart varies two perturbation axes
while holding other context fixed.

| Domain        | Plot                                    | Perturbation classes                |
|---------------|-----------------------------------------|-------------------------------------|
| FINANCE       | `finance_01_tool_x_amount`              | tool-substitution + arg-mutation    |
| FINANCE       | `finance_02_content_x_tool`             | semantic                            |
| FINANCE       | `finance_03_amount_x_threshold`         | arg-mutation                        |
| CYBERSECURITY | `cyber_01_path_x_tool`                  | arg-mutation + substitution         |
| CYBERSECURITY | `cyber_02_shellop_x_tool`               | arg-mutation + substitution         |
| CYBERSECURITY | `cyber_03_escalation_x_tool`            | semantic + substitution             |
| HEALTHCARE    | `health_01_content_x_tool`              | semantic                            |
| HEALTHCARE    | `health_02_phi_x_tool`                  | context-flip + substitution         |
| HEALTHCARE    | `health_03_auth_x_tool`                 | context-flip + substitution         |
| DATA_PRIVACY  | `privacy_01_pii_x_dest`                 | context-flip × 2                    |
| DATA_PRIVACY  | `privacy_02_pii_x_consent`              | context-flip × 2                    |
| DATA_PRIVACY  | `privacy_03_consent_x_dest`             | context-flip × 2                    |

Plus two runtime-stability plots:

- `stability_eval_time` — N=100 evaluations per scenario, jittered scatter
  of wall-clock latency (ms) with median bar.
- `stability_consistency` — verdict determinism across N=100 runs per scenario.

Aggregate statistics: `summary.json`.

## v2 layout — `sweep_v2.py`

Nine heat maps targeting new domains and harder perturbations.

| Group        | Plot                                    | What it shows                                    |
|--------------|-----------------------------------------|--------------------------------------------------|
| ENTERPRISE   | `enterprise_01_class_x_dest`            | internal_artifact_leak rule                      |
| ENTERPRISE   | `enterprise_02_tool_x_admin`            | unauthorized_role_change rule                    |
| COMPLIANCE   | `compliance_01_pci_x_tool`              | pci_card_exposure rule                           |
| COMPLIANCE   | `compliance_02_purpose_x_consent`       | gdpr_purpose_mismatch rule                       |
| FRAUD        | `fraud_01_tool_x_amount`                | structuring_pattern rule (band $9000–$9999)      |
| FRAUD        | `fraud_02_velocity_x_amount`            | velocity_anomaly + structuring co-fire           |
| ADVERSARIAL  | `adversarial_01_obfuscation_x_tool`     | keyword-evasion robustness                       |
| MULTI-STEP   | `multistep_01_intent_x_length`          | V2 escalation detector (alternating intent)      |
| BOUNDARY     | `boundary_01_amount_eps_x_tool`         | ε-ball around structuring rule edges             |

Aggregate statistics: `summary_v2.json`.

## Benchmark layout — `benchmark.py`

| Plot                                  | What it shows                                                       |
|---------------------------------------|---------------------------------------------------------------------|
| `bench_per_layer_breakdown`           | median time spent in A_safe / V2 / V3 across 4 representative trajectories |
| `bench_throughput_vs_rules`           | evals/sec and µs/eval as loaded rule count scales from 0 → 5000     |
| `bench_latency_vs_length`             | P50/P95/P99/P99.9 latency vs trajectory length (1 → 89 steps)       |
| `bench_cold_vs_warm`                  | first eval vs steady-state median across N=500 fresh layers         |

Raw numbers: `benchmark_summary.json`.

## Cell encoding (heat maps)

| Glyph | Color  | Meaning           |
|-------|--------|-------------------|
| P     | green  | PERMIT            |
| A     | red    | BLOCK @ A_safe    |
| V2    | orange | BLOCK @ V2        |
| V3    | purple | BLOCK @ V3        |

## Findings

Highlights surfaced by the sweeps:

- **Keyword evasion is trivial.** `adversarial_01` shows 5 of 10 obfuscation
  classes (zero-width injection, Cyrillic lookalike, URL/hex/base64 encoding,
  runtime concatenation) bypass `credential_exfiltration` outright. Only the
  plain, upper-cased, padded, and path-traversal variants are caught.
- **Coverage gaps in the default rule list.** `/etc/passwd`, `/var/log/auth.log`,
  and `.ssh/id_rsa` are not in the credential keyword set, so the rule misses
  them across all tools (`cyber_01`).
- **V2 fires as designed.** `multistep_01` confirms that alternating
  benign/sensitive chains of length ≥ 4 trigger V2's escalation detector
  (`escalation_signals ≥ 2`), even when no single step violates A_safe.
- **Structuring boundary is exact.** `fraud_01` and `boundary_01` show the
  $9000–$9999 structuring band lights up cleanly with no leakage at $8999 or
  $10000.
- **Cost is dominated by V2 for multi-step plans.** Per-layer breakdown shows
  V2 ≈ 5× more expensive than A_safe on a 4-step trajectory, dwarfing V3.
- **Throughput is linear in rule count.** ~37K evals/sec at 0 rules → ~1.5K at
  5000 rules; latency rises from 26 µs to 660 µs over the same range.
- **Trajectory length scales near-linearly.** P50 grows from 24 µs at 1 step
  to ~10 ms at 89 steps (~400× for 89× length).

## Layer-firing layout — `layer_firing.py` (V4 / V4+ / V5 / V5+)

| Plot                          | What it shows                                                              |
|-------------------------------|----------------------------------------------------------------------------|
| `layer_activation_matrix`     | scenario × layer via `evaluate_all()` — proves earlier layers don't mask deeper firings; V4 triggers in isolation; V3 only co-fires |
| `adversarial_attribution`     | per V5+ attack class, which layer caught each variant vs bypassed (stacked) |
| `bench_per_layer_v4`          | median cost of A_safe / V2 / V3 / V4 on a 3-step trajectory                 |

Raw numbers: `layer_firing_summary.json`.

### V4–V5+ findings (see also `morrison_governance/LIMITATIONS.md`)

- **multi_turn_chain: 100% bypass.** Two-step pre-compute→exfiltrate plans
  evade A_safe (individually benign) and V2 (one escalation transition, needs
  ≥2). This is the most serious discovered failure surface.
- **hidden_substitution: 86% bypass.** Tool-name spoofing (case, hyphen,
  zero-width, Cyrillic homoglyph) defeats exact-literal tool matching.
- **obfuscation: 60% bypass.** Confirms the v1/v2 keyword-evasion gap at the
  layer-attribution level.
- **No masking.** The activation matrix shows V2 and V4 firing alone, and
  A_safe+V3+V4 co-firing fully visible under `evaluate_all()`.
- **V3 never fires alone.** Forward reachability only triggers as a
  side-effect of credential reads A_safe already catches — sparse coverage.
- **V4 is the cheapest layer** (~0.01 ms); V2 remains the most expensive.

All generators are seed-deterministic; a latent V3 set-iteration
nondeterminism (hash-seed dependent projection slicing) was fixed so the
activation matrix is reproducible across `PYTHONHASHSEED`.
