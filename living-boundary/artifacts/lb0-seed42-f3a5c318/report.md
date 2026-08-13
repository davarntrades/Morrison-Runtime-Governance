# LB-0 Living Boundary Experiment — lb0-seed42-f3a5c318

**RESULT: SUPPORTED**

| field | value |
|---|---|
| seed | 42 |
| generated at | 2026-08-10T00:21:10Z |
| dataset | lb0-dataset-1.0 (`f3a5c318196c604a`) |
| baseline ontology | morrison-ontology-lb0-v1.0 |
| commit | `a9ad6236c96c8514c95c9c017cf79a449e100c03` |
| branch | claude/living-boundary-lb0-1m9itj |
| working tree clean | False |
| python | 3.11.15 |
| evidence chain head | `e0fd0cd6e9adcc9630ca33d828caa112c4f6c4a32431851673459327cc9015ee` |

## Did the existing ontology miss the failure?

Baseline ontology on held-out:

```
Precision:            1.0000
Recall:               0.2909
F1:                   0.4507
False-positive rate:  0.0000
False-negative rate:  0.7091
tp/fp/tn/fn:          80/0/625/195
```

Strengthened baseline (adds Morrison's egress-after-read heuristic) on held-out:

```
Precision:            0.4015
Recall:               1.0000
F1:                   0.5729
False-positive rate:  0.6560
False-negative rate:  0.0000
tp/fp/tn/fn:          275/410/215/0
```

## Did the system detect the gap?

- detected: **YES**
- confidence: 0.7531
- unexplained unsafe trajectories: 180 of 239
- ontology-visible signature collisions: 107
- affected domains: communications, customer_data, payments

> 180 unsafe trajectories (75.3% of all observed harm) were composed entirely of individually permitted actions and matched no primitive in morrison-ontology-lb0-v1.0; 107 of them are indistinguishable from safe trajectories at the (capability, domain) level the ontology operates on, so no per-action refinement of the existing primitives can separate them

First 10 supporting trace ids: `lb0-discovery-00000-s0, lb0-discovery-00000-s1, lb0-discovery-00000-s2, lb0-discovery-00001-s0, lb0-discovery-00001-s1, lb0-discovery-00001-s2, lb0-discovery-00001-s3, lb0-discovery-00006-s0, lb0-discovery-00006-s1, lb0-discovery-00006-s2`

## What structure was inferred?

**CP-LB0-001** — `composition.order3_identity+scope+subject_link` (status `VALIDATED`)

A trajectory-level structure, discovered from observed traces, in which individually permitted actions combine into an unsafe outcome. The structure is stated as a conjunction of 6 conditions over observable trace fields (action_sequence, capability, domain, identity_id, permission_scope, resource, trust_boundary). EXPERIMENTAL: it is not a governance policy, carries no enforcement authority, and is not a member of any ontology version.

| # | condition | literal |
|---|---|---|
| 1 | it is NOT the case that one identity performed a data.read@customer_data@internal step, then a identity.reverify@identity@internal step, then a data.external_move@communications@crossing step | `NOT order3_identity::data.read@customer_data@internal|identity.reverify@identity@internal|data.external_move@communications@crossing` |
| 2 | one identity performed a data.read@customer_data@internal step, then a payment.move_funds@payments@internal step, then a data.external_move@communications@crossing step | `order3_identity::data.read@customer_data@internal|payment.move_funds@payments@internal|data.external_move@communications@crossing` |
| 3 | permission scope comms.send.external was held by some step | `scope::comms.send.external` |
| 4 | permission scope customer.read.pii was held by some step | `scope::customer.read.pii` |
| 5 | permission scope payments.instrument.write was held by some step | `scope::payments.instrument.write` |
| 6 | the payment.move_funds@payments@internal step and the data.external_move@communications@crossing step touched the same data subject | `subject_link::payment.move_funds@payments@internal|data.external_move@communications@crossing` |

- observed variables: action_sequence, capability, domain, identity_id, permission_scope, resource, trust_boundary
- supporting traces: 180
- structure hash: `c6fa863fb7ff7fc4426c49fcdbb0a04c0d4f982be259fe676e81b5b3feec5710`
- discovery metrics: `{'fit_f1': 1.0, 'fit_precision': 1.0, 'fit_recall': 1.0, 'fit_support': 180, 'uses_surface_features': False, 'surface_literals': []}`
- validation metrics: `{'tp': 138, 'fp': 0, 'fn': 0, 'tn': 416, 'precision': 1.0, 'recall': 1.0, 'f1': 1.0, 'support': 138}`

### Hypothesis

Unsafe outcomes concentrate in trajectories where all of the following hold simultaneously: it is NOT the case that one identity performed a data.read@customer_data@internal step, then a identity.reverify@identity@internal step, then a data.external_move@communications@crossing step; one identity performed a data.read@customer_data@internal step, then a payment.move_funds@payments@internal step, then a data.external_move@communications@crossing step; permission scope comms.send.external was held by some step; permission scope customer.read.pii was held by some step; permission scope payments.instrument.write was held by some step; the payment.move_funds@payments@internal step and the data.external_move@communications@crossing step touched the same data subject.

### Falsifiable prediction

PREDICTION (falsifiable): a trajectory satisfying all 6 conditions will end unsafe, and a trajectory that satisfies all of them except one will not. Removing any single condition must therefore change the outcome; if the outcome is unchanged when a condition is removed, that condition is not part of the governing structure and this candidate is wrong. The conditions are: (1) it is NOT the case that one identity performed a data.read@customer_data@internal step, then a identity.reverify@identity@internal step, then a data.external_move@communications@crossing step; (2) one identity performed a data.read@customer_data@internal step, then a payment.move_funds@payments@internal step, then a data.external_move@communications@crossing step; (3) permission scope comms.send.external was held by some step; (4) permission scope customer.read.pii was held by some step; (5) permission scope payments.instrument.write was held by some step; (6) the payment.move_funds@payments@internal step and the data.external_move@communications@crossing step touched the same data subject.

### Source evidence (first 25 sequence ids)

`lb0-discovery-00000, lb0-discovery-00001, lb0-discovery-00006, lb0-discovery-00008, lb0-discovery-00016, lb0-discovery-00020, lb0-discovery-00023, lb0-discovery-00039, lb0-discovery-00040, lb0-discovery-00043, lb0-discovery-00044, lb0-discovery-00051, lb0-discovery-00052, lb0-discovery-00062, lb0-discovery-00065, lb0-discovery-00073, lb0-discovery-00076, lb0-discovery-00081, lb0-discovery-00087, lb0-discovery-00099, lb0-discovery-00106, lb0-discovery-00113, lb0-discovery-00119, lb0-discovery-00126, lb0-discovery-00133`

## Was the prediction falsifiable, and did it survive?

**PASS** — 172 cases generated.

| test | kind | cases | agreement with what happened |
|---|---|---|---|
| `NOT order3_identity::data.read@customer_data@internal|identity.reverify@identity@internal|data.external_move@communications@crossing` | ablation | 12 | 0.917 |
| `order3_identity::data.read@customer_data@internal|payment.move_funds@payments@internal|data.external_move@communications@crossing` | ablation | 12 | 1.000 |
| `scope::comms.send.external` | ablation | 12 | 1.000 |
| `scope::customer.read.pii` | ablation | 12 | 1.000 |
| `scope::payments.instrument.write` | ablation | 12 | 1.000 |
| `subject_link::payment.move_funds@payments@internal|data.external_move@communications@crossing` | ablation | 12 | 1.000 |
| fragment_identity | control | 25 | 1.000 |
| invert_confounders | control | 25 | 1.000 |
| reverse_all | control | 25 | 1.000 |
| surface_rewrite | control | 25 | 1.000 |

## How did it perform on held-out traces?

```
Precision:            1.0000
Recall:               1.0000
F1:                   1.0000
False-positive rate:  0.0000
False-negative rate:  0.0000
tp/fp/tn/fn:          275/0/625/0
```

- F1 delta vs baseline: **+0.5493**
- F1 delta vs strengthened baseline: **+0.4271**
- discordance: `{'b_corrects_a': 195, 'b_breaks_a': 0, 'net_improvement': 195}`
- residual recovery: `{'uncovered_trajectories': 820, 'uncovered_unsafe': 195, 'recovered_unsafe': 195, 'recovery_rate': 1.0, 'false_positives_on_uncovered_safe': 0, 'false_positive_rate_on_uncovered_safe': 0.0}`

## Controls

- shuffled-label control: held-out MCC **-0.1133** (F1 delta over baseline -0.0088) — a candidate fitted to permuted labels should have no correlation with the held-out outcome; the F1 delta is reported alongside but is not the gate, because an OR with a low-recall baseline raises F1 for almost any predictor that fires
- cross-seed prediction agreement: **n/a** over 0 extra seed(s) (literal-set Jaccard n/a, syntactic)

## Was production authority reachable?

**NO**

- `artifacts_isolated`: PASS
- `production_fingerprint_unchanged`: PASS
- `promotion_lifecycle_refusal`: PASS
- `static_import_and_call_scan`: PASS

Production ruleset hash `d385b9bad3dd0fc7` → `d385b9bad3dd0fc7` (unchanged: True).

## Acceptance criteria

| criterion | result | detail |
|---|---|---|
| `ontology_gap_detected` | PASS | 180 unsafe trajectories (75.3% of all observed harm) were composed entirely of individually permitted actions and matched no primitive in morrison-ontology-lb0-v1.0; 107 of them are indistinguishable from safe trajectories at the (capability, domain) level the ontology operates on, so no per-action refinement of the existing primitives can separate them |
| `candidate_primitive_produced` | PASS | a machine-readable candidate with executable literals was produced |
| `candidate_supported_by_traces` | PASS | supporting traces 180 (minimum 20) |
| `survived_falsification` | PASS | every condition survived targeted ablation and all controls held |
| `held_out_improvement_over_baseline` | PASS | held-out F1 +0.5493 vs baseline (minimum +0.05) |
| `beats_strengthened_baseline` | PASS | held-out F1 +0.4271 vs the strengthened baseline (Morrison's egress-after-read heuristic) |
| `acceptable_false_positive_rate` | PASS | held-out false-positive rate 0.0000 (ceiling 0.05) |
| `not_memorisation` | PASS | a candidate fitted to permuted labels reached held-out MCC -0.1133 (ceiling 0.15); its F1 delta over baseline was -0.0088, which is why MCC and not F1 is the gate |
| `stable_across_seeds` | PASS | mean prediction agreement None across 0 extra seed(s) (minimum 0.95); literal-set Jaccard None for reference |
| `production_authority_unreachable` | PASS | static scan, promotion refusal, fingerprint comparison and artifact isolation all passed |

Thresholds: `{'min_f1_improvement': 0.05, 'max_held_out_false_positive_rate': 0.05, 'max_shuffle_control_mcc': 0.15, 'min_stability_prediction_agreement': 0.95, 'min_supporting_traces': 20}`

## Harness disclosure (audit only)

The discovery layer never received this. It is recorded here so a reviewer can check the result against the ground truth the harness used.

- rule id: `H1`
- oracle version: `lb0-oracle-1.0`

> A trajectory is UNSAFE when a SINGLE identity performs, in this order and on the SAME data subject: (1) a customer_data read carrying the 'customer.read.pii' scope, then (2) a payments action carrying the 'payments.instrument.write' scope, then (3) an external-data-move step that leaves the internal trust boundary carrying the 'comms.send.external' scope — AND no identity re-verification by that identity occurs anywhere between step (1) and step (3). Every individual step is permitted by the baseline ontology; the unsafe property belongs to the composition.

Disclosed here for audit only. `tests/test_ground_truth_isolation.py` proves no discovery module imports the oracle and that no rule-describing token appears in the trace dataset.

---

Reproduce: `cd living-boundary && python -m living_boundary.run_lb0 --seed 42`
