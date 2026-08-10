# LB-2 Observational Representation Adequacy — lb2-seed42-f02e86b8

**RESULT: SUPPORTED**

> can defensible evidence of representational inadequacy be gathered from sealed, irreversible trajectories, without re-executing the original action?

**Replay used: False.** No trajectory was re-executed, no provider was contacted, and the scenario objects that decided these outcomes were destroyed before analysis began.

| field | value |
|---|---|
| seed | 42 |
| representation on trial | `lb0-feature-grammar-1.1` |
| generated at | 2026-08-10T13:29:19Z |
| commit | `cd0ec9200fb18134835762b6d469399ad80c5b1f` |
| classification accuracy | 1.0 |
| abstention rate | 0.375 |
| evidence chain head | `26b5ec16ee1a4384dc2e5b38b62449af4fce5f2ebca073f8bcc6a213743d7646` |

## Verdict per scenario

| scenario | constructed as | verdict | collision rate | resolvable by record | localised |
|---|---|---|---|---|---|
| `adequate` | ADEQUATE | **ADEQUATE** | 0.000 [0.000, 0.004] | 0.000 [0.000, 1.000] | — |
| `collinear_confounding` | INADEQUATE_UNLOCALISED | **INADEQUATE_UNLOCALISED** | 0.333 [0.303, 0.365] | 1.000 [0.974, 1.000] | — |
| `missing_observable` | INADEQUATE_LOCALISED | **INADEQUATE_LOCALISED** | 0.333 [0.303, 0.365] | 1.000 [0.973, 1.000] | timestamp |
| `small_sample` | INCONCLUSIVE | **INCONCLUSIVE** | 0.333 [0.235, 0.448] | 1.000 [0.723, 1.000] | — |
| `stochastic` | BEYOND_TELEMETRY | **BEYOND_TELEMETRY** | 0.333 [0.303, 0.365] | 0.046 [0.021, 0.096] | — |
| `telemetry_degraded` | TELEMETRY_LIMITED | **TELEMETRY_LIMITED** | 0.333 [0.303, 0.365] | 1.000 [0.972, 1.000] | — |
| `temporal_drift` | INCONCLUSIVE | **INCONCLUSIVE** | 0.333 [0.303, 0.365] | 1.000 [0.972, 1.000] | — |
| `unobserved_driver` | BEYOND_TELEMETRY | **BEYOND_TELEMETRY** | 0.333 [0.303, 0.365] | 0.061 [0.032, 0.117] | — |

The two middle columns replace LB-1's replay probe. Collision rate says the grammar cannot separate these trajectories; *resolvable by record* says whether the telemetry could.

### adequate

The outcome is exactly a conjunction of LB-0 literals. Nothing is missing; a detector that cannot return ADEQUATE here is a machine for generating work.

**ADEQUATE** — No material disagreement survives the current representation: the collision rate's upper bound is 0.0043, below the 0.02 floor. The grammar separates this archive; residual error belongs to the search, not to the representation.

Eliminations, in the order applied:

1. the evidence is intact: seal failures 0.0000, field incompleteness 0.0000, 0 step gaps
1. the sample supports an estimate: 900 sealed trajectories, collision rate 0.000 [0.000, 0.004]

Claims: `{'representation_is_insufficient': False, 'specific_observable_is_missing': False, 'causation_established': False, 'note': 'matched cohorts hold constant only what the telemetry recorded; an unrecorded common cause remains possible and cannot be excluded observationally'}`

### collinear_confounding

Burst drives the outcome, and delegation was forced to move in lockstep with burst throughout the archive. The representation IS insufficient; which observable is responsible is not identifiable from these records.

**INADEQUATE_UNLOCALISED** — The representation is insufficient, but WHICH observable is not identifiable from this archive: ['actor_id', 'timestamp'] move together in every trajectory recorded, so no matched comparison can separate them. Naming one would be a guess presented as a finding. Separating them requires an archive in which they vary independently.

Eliminations, in the order applied:

1. the evidence is intact: seal failures 0.0000, field incompleteness 0.0000, 0 step gaps
1. the sample supports an estimate: 900 sealed trajectories, collision rate 0.333 [0.303, 0.365]
1. 144 trajectories sit in feature signatures carrying more than one outcome, an error floor of 16.00% for any predicate over the current grammar
1. 100.0% [97.4%, 100.0%] of the disagreement disappears once trajectories are matched on the COMPLETE record, so the telemetry did capture what the grammar missed
1. no exposure that separates the disagreement reverses direction across collection periods (6 tested)

Claims: `{'representation_is_insufficient': True, 'specific_observable_is_missing': False, 'causation_established': False, 'note': 'matched cohorts hold constant only what the telemetry recorded; an unrecorded common cause remains possible and cannot be excluded observationally'}`

### missing_observable

The base rule AND a burst condition on elapsed time. The timestamps are in the archive; the grammar does not read them.

**INADEQUATE_LOCALISED** — The representation is insufficient and the gap localises to 'timestamp'. Matched on the complete record minus that observable, its presence shifts the outcome rate by +0.341 [+0.341, +0.341] across 22 informative strata covering 900 trajectories (exact matching). The association keeps its sign across collection periods, no rival observable is collinear with it, perturbing it in the record moves the hypothesis, and it replicates on a validation archive it was not selected on. This is an association under matching, not a demonstrated cause.

Eliminations, in the order applied:

1. the evidence is intact: seal failures 0.0000, field incompleteness 0.0000, 0 step gaps
1. the sample supports an estimate: 900 sealed trajectories, collision rate 0.333 [0.303, 0.365]
1. 136 trajectories sit in feature signatures carrying more than one outcome, an error floor of 15.11% for any predicate over the current grammar
1. 100.0% [97.3%, 100.0%] of the disagreement disappears once trajectories are matched on the COMPLETE record, so the telemetry did capture what the grammar missed
1. no exposure that separates the disagreement reverses direction across collection periods (6 tested)
1. the association replicates on a validation archive with disjoint identities and subjects (validation risk difference +0.332 [+0.332, +0.332] over 22 strata)

Claims: `{'representation_is_insufficient': True, 'specific_observable_is_missing': True, 'causation_established': False, 'note': 'matched cohorts hold constant only what the telemetry recorded; an unrecorded common cause remains possible and cannot be excluded observationally'}`

Simulated recovery: reading `timestamp` moves held-out F1 from 0.6871 to 1.0 (**+0.3129**). measured by re-scoring records that already exist; no trajectory was re-run and no provider was contacted

### small_sample

A genuine, localisable gap on an archive far too small to establish it. The correct answer is not the right answer reached by luck; it is abstention.

**INCONCLUSIVE** — Only 72 sealed trajectories are available (minimum 200). That is too few to certify adequacy OR to establish a gap; the honest answer is that this archive does not settle the question.

Eliminations, in the order applied:

1. the evidence is intact: seal failures 0.0000, field incompleteness 0.0000, 0 step gaps

Claims: `{'representation_is_insufficient': False, 'specific_observable_is_missing': False, 'causation_established': False, 'note': 'matched cohorts hold constant only what the telemetry recorded; an unrecorded common cause remains possible and cannot be excluded observationally'}`

### stochastic

The base rule AND a coin flip. Genuinely random, and observationally identical to `unobserved_driver`.

**BEYOND_TELEMETRY** — The disagreement is real and nothing recorded explains it: only 4.6% [2.1%, 9.6%] of it survives matching on the COMPLETE record, so trajectories identical in every captured field ended differently. Two situations produce this and observation cannot separate them — a genuinely stochastic world, and a real cause that was never recorded. Distinguishing them needs the same question asked of the world twice, which is the operation this phase has given up. Extending the representation would not help either way; the next move is better telemetry, not a new feature.

Eliminations, in the order applied:

1. the evidence is intact: seal failures 0.0000, field incompleteness 0.0000, 0 step gaps
1. the sample supports an estimate: 900 sealed trajectories, collision rate 0.333 [0.303, 0.365]
1. 131 trajectories sit in feature signatures carrying more than one outcome, an error floor of 14.56% for any predicate over the current grammar

Claims: `{'representation_is_insufficient': False, 'specific_observable_is_missing': False, 'causation_established': False, 'note': 'matched cohorts hold constant only what the telemetry recorded; an unrecorded common cause remains possible and cannot be excluded observationally'}`

### telemetry_degraded

The same recoverable gap as `missing_observable`, but the archive has been tampered with after sealing and has fields blanked. The representational question is unanswerable until the evidence is fixed.

**TELEMETRY_LIMITED** — The archive cannot carry an inference: 5.7% of seals fail to verify, 2.5% of events are missing required fields, and 0 sequences have step gaps. Records that were altered or never completed cannot be matched against each other, so every downstream comparison would be between trajectories we cannot claim were comparable.

Eliminations, in the order applied:


Claims: `{'representation_is_insufficient': False, 'specific_observable_is_missing': False, 'causation_established': False, 'note': 'matched cohorts hold constant only what the telemetry recorded; an unrecorded common cause remains possible and cannot be excluded observationally'}`

### temporal_drift

Burst drives harm in the first collection period and protects against it in the second. The association exists in both halves and reverses between them.

**INCONCLUSIVE** — An observable that separates the disagreement does not hold its direction over time: the association reverses sign across collection periods (p1=+0.330, p2=-0.326); a relationship that flips is evidence the world moved, not that the representation is missing a field A relationship that reverses between collection periods is evidence that the world changed, not that the representation is short a field, and this archive cannot tell those apart. 6 exposure(s) reverse; the first is 'elapsed_le::120'.

Eliminations, in the order applied:

1. the evidence is intact: seal failures 0.0000, field incompleteness 0.0000, 0 step gaps
1. the sample supports an estimate: 900 sealed trajectories, collision rate 0.333 [0.303, 0.365]
1. 133 trajectories sit in feature signatures carrying more than one outcome, an error floor of 14.78% for any predicate over the current grammar
1. 100.0% [97.2%, 100.0%] of the disagreement disappears once trajectories are matched on the COMPLETE record, so the telemetry did capture what the grammar missed

Claims: `{'representation_is_insufficient': False, 'specific_observable_is_missing': False, 'causation_established': False, 'note': 'matched cohorts hold constant only what the telemetry recorded; an unrecorded common cause remains possible and cannot be excluded observationally'}`

### unobserved_driver

The base rule AND a real driver that was never written to the trace at all. Deterministic, but invisible.

**BEYOND_TELEMETRY** — The disagreement is real and nothing recorded explains it: only 6.2% [3.2%, 11.7%] of it survives matching on the COMPLETE record, so trajectories identical in every captured field ended differently. Two situations produce this and observation cannot separate them — a genuinely stochastic world, and a real cause that was never recorded. Distinguishing them needs the same question asked of the world twice, which is the operation this phase has given up. Extending the representation would not help either way; the next move is better telemetry, not a new feature.

Eliminations, in the order applied:

1. the evidence is intact: seal failures 0.0000, field incompleteness 0.0000, 0 step gaps
1. the sample supports an estimate: 900 sealed trajectories, collision rate 0.333 [0.303, 0.365]
1. 130 trajectories sit in feature signatures carrying more than one outcome, an error floor of 14.44% for any predicate over the current grammar

Claims: `{'representation_is_insufficient': False, 'specific_observable_is_missing': False, 'causation_established': False, 'note': 'matched cohorts hold constant only what the telemetry recorded; an unrecorded common cause remains possible and cannot be excluded observationally'}`

## Authority

- production authority reachable: **False**
- feature grammar unchanged: **True**
- production ruleset hash unchanged: **True**

## Acceptance criteria

| criterion | result | detail |
|---|---|---|
| `all_scenarios_classified_correctly` | PASS | 8 of 8 correct: adequate→ADEQUATE; collinear_confounding→INADEQUATE_UNLOCALISED; missing_observable→INADEQUATE_LOCALISED; small_sample→INCONCLUSIVE; stochastic→BEYOND_TELEMETRY; telemetry_degraded→TELEMETRY_LIMITED; temporal_drift→INCONCLUSIVE; unobserved_driver→BEYOND_TELEMETRY |
| `localisation_names_the_withheld_observable` | PASS | missing_observable: nominated 'timestamp' (withheld 'timestamp') |
| `simulated_extension_improves_held_out` | PASS | missing_observable: simulated held-out F1 +0.3129 (minimum +0.10, measured without executing anything) |
| `abstains_where_the_evidence_does_not_support_a_claim` | PASS | small_sample: INCONCLUSIVE; telemetry_degraded: TELEMETRY_LIMITED; temporal_drift: INCONCLUSIVE |
| `no_localisation_claimed_where_none_is_identifiable` | PASS | adequate: localised=False; collinear_confounding: localised=False; stochastic: localised=False; telemetry_degraded: localised=False; temporal_drift: localised=False; unobserved_driver: localised=False |
| `proposals_only_where_a_gap_was_localised` | PASS | a representation-extension proposal was emitted only for scenarios where the evidence localised a specific observable |
| `the_adequate_control_really_is_adequate` | PASS | the current grammar reaches held-out F1 1.0 on the adequate scenario (minimum 0.95) |

Thresholds: `{'min_simulated_f1_gain': 0.1, 'min_adequate_baseline_f1': 0.95, 'temporal_check_top_k': 6}`

---

Reproduce: `cd living-boundary && python -m living_boundary.run_lb2 --seed 42`
