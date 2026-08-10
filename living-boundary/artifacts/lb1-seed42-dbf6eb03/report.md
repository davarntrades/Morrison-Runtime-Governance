# LB-1 Representation Adequacy — lb1-seed42-dbf6eb03

**RESULT: SUPPORTED**

> can the discovery layer detect when its OWN representation is inadequate, rather than merely when Morrison's ontology is?

| field | value |
|---|---|
| seed | 42 |
| representation on trial | `lb0-feature-grammar-1.1` |
| corpus hash | `dbf6eb03dd23d479` |
| generated at | 2026-08-10T12:29:24Z |
| commit | `5d130cb33be18133c2d3e4887a2af3b4cc743c41` |
| evidence chain head | `48da84ad74709a2f7ad6507b9d2188c2f80f2c54196fa188460db7c94996580f` |

## Verdict per environment

| environment | constructed as | verdict | collision rate | mean minority | re-run vs record | re-run vs self |
|---|---|---|---|---|---|---|
| adequate | ADEQUATE | **ADEQUATE** | 0.000 | 0.000 | 0.000 | 0.000 |
| inadequate_delegation | INADEQUATE | **INADEQUATE** | 0.180 | 0.448 | 0.000 | 0.000 |
| inadequate_timing | INADEQUATE | **INADEQUATE** | 0.176 | 0.480 | 0.000 | 0.000 |
| inadequate_unlocalised | INADEQUATE | **INADEQUATE** | 0.136 | 0.454 | 0.000 | 0.000 |
| noise_limited | NOISE_LIMITED | **NOISE_LIMITED** | 0.714 | 0.200 | 0.121 | 0.000 |
| stochastic | STOCHASTIC | **STOCHASTIC** | 0.180 | 0.395 | 0.183 | 0.167 |

Note the two columns on the right. Collision rate alone does not separate these environments — four of the five collide. The probe columns are what does.

### adequate

The outcome is exactly a conjunction of LB-0 literals. The grammar can express it, so a competent detector must report ADEQUATE.

**ADEQUATE** — 0 of 120 feature signatures carry more than one outcome, covering 0.00% of the corpus. The current representation is sufficient to express the observed outcome; any remaining error belongs to the search, not to the grammar.

Eliminations, in the order they were applied:

1. collision rate 0.0000 is below the 0.02 floor: the representation separates the corpus, so no representational claim is available

Residual beyond estimated noise: `{'estimated_label_noise_rate': 0.0, 'minority_expected_under_noise': 0.0, 'minority_observed': 0, 'ratio': None, 'unexplained_by_noise': False}`

### inadequate_delegation

The base rule AND the egress performed by an actor other than the authorising identity. `actor_id` is in every event and read by no feature.

**INADEQUATE** — The representation is the limiting factor. 4 feature signatures carry more than one outcome, covering 18.00% of the corpus, with a mean minority fraction of 0.45 — far from the thin minority that label noise produces. The world is reproducible and the record is faithful, so the disagreement cannot be blamed on either. No predicate over the current feature grammar can separate these trajectories: its error is bounded below by 8.60% however the search is improved. Something observable in the traces is not being read.

Eliminations, in the order they were applied:

1. the world is reproducible: re-running the same trajectory agreed with itself in 100.00% of 240 probes
1. the record is faithful: re-running matched the recorded outcome in 100.00% of 240 probes
1. 43 trajectories nevertheless sit in feature signatures carrying more than one outcome

Residual beyond estimated noise: `{'estimated_label_noise_rate': 0.0, 'minority_expected_under_noise': 0.0, 'minority_observed': 43, 'ratio': None, 'unexplained_by_noise': True}`

Localisation, ranked:

| family | observable | resolves |
|---|---|---|
| `actor_count` | actor_id | 1.000 |
| `actor_divergence` | actor_id | 1.000 |
| `elapsed` | timestamp | 0.349 |
| `max_gap` | timestamp | 0.302 |
| `hour_of_day` | timestamp | 0.233 |
| `capability_multiplicity` | capability | 0.000 |
| `identity_count` | identity_id | 0.000 |
| `resource_repeat` | resource | 0.000 |
| `subject_count` | resource | 0.000 |

Reading `actor_id` raises held-out F1 from 0.6359 to 1.0 (**+0.3641**).

Proposal `RP-LB1-inadequate_delegation` status `REVIEW_REQUIRED`, production authority `none`, grammar-mutation authority `none`.

### inadequate_timing

The base rule AND a burst condition on elapsed time between the read and the egress. Timestamps are in every event and read by no feature.

**INADEQUATE** — The representation is the limiting factor. 3 feature signatures carry more than one outcome, covering 17.60% of the corpus, with a mean minority fraction of 0.48 — far from the thin minority that label noise produces. The world is reproducible and the record is faithful, so the disagreement cannot be blamed on either. No predicate over the current feature grammar can separate these trajectories: its error is bounded below by 8.40% however the search is improved. Something observable in the traces is not being read.

Eliminations, in the order they were applied:

1. the world is reproducible: re-running the same trajectory agreed with itself in 100.00% of 240 probes
1. the record is faithful: re-running matched the recorded outcome in 100.00% of 240 probes
1. 42 trajectories nevertheless sit in feature signatures carrying more than one outcome

Residual beyond estimated noise: `{'estimated_label_noise_rate': 0.0, 'minority_expected_under_noise': 0.0, 'minority_observed': 42, 'ratio': None, 'unexplained_by_noise': True}`

Localisation, ranked:

| family | observable | resolves |
|---|---|---|
| `elapsed` | timestamp | 1.000 |
| `max_gap` | timestamp | 1.000 |
| `hour_of_day` | timestamp | 0.286 |
| `actor_count` | actor_id | 0.238 |
| `actor_divergence` | actor_id | 0.238 |
| `capability_multiplicity` | capability | 0.000 |
| `identity_count` | identity_id | 0.000 |
| `resource_repeat` | resource | 0.000 |
| `subject_count` | resource | 0.000 |

Reading `timestamp` raises held-out F1 from 0.7042 to 0.9939 (**+0.2897**).

Proposal `RP-LB1-inadequate_timing` status `REVIEW_REQUIRED`, production authority `none`, grammar-mutation authority `none`.

### inadequate_unlocalised

The base rule AND the crossing egress performed by one PARTICULAR tool among three that share a capability, domain and boundary. Beyond the grammar AND beyond every family in the extension pool.

**INADEQUATE** — The representation is the limiting factor. 4 feature signatures carry more than one outcome, covering 13.60% of the corpus, with a mean minority fraction of 0.45 — far from the thin minority that label noise produces. The world is reproducible and the record is faithful, so the disagreement cannot be blamed on either. No predicate over the current feature grammar can separate these trajectories: its error is bounded below by 6.40% however the search is improved. Something observable in the traces is not being read.

Eliminations, in the order they were applied:

1. the world is reproducible: re-running the same trajectory agreed with itself in 100.00% of 240 probes
1. the record is faithful: re-running matched the recorded outcome in 100.00% of 240 probes
1. 32 trajectories nevertheless sit in feature signatures carrying more than one outcome

Residual beyond estimated noise: `{'estimated_label_noise_rate': 0.0, 'minority_expected_under_noise': 0.0, 'minority_observed': 32, 'ratio': None, 'unexplained_by_noise': True}`

Localisation, ranked:

| family | observable | resolves |
|---|---|---|
| `elapsed` | timestamp | 0.500 |
| `max_gap` | timestamp | 0.375 |
| `hour_of_day` | timestamp | 0.250 |
| `actor_count` | actor_id | 0.219 |
| `actor_divergence` | actor_id | 0.219 |
| `capability_multiplicity` | capability | 0.000 |
| `identity_count` | identity_id | 0.000 |
| `resource_repeat` | resource | 0.000 |
| `subject_count` | resource | 0.000 |

### noise_limited

The adequate rule with recorded labels flipped at rate 0.12. The representation is sufficient; the record is not.

**NOISE_LIMITED** — The recorded outcomes are wrong at about 12.08%, which is enough to manufacture these collisions in a corpus the representation could otherwise express. Extending the grammar here would fit the label noise.

Eliminations, in the order they were applied:

1. the world is reproducible: re-running the same trajectory agreed with itself in 100.00% of 240 probes
1. re-running disagreed with the RECORDED outcome at rate 0.1208, above the 0.02 fidelity margin

Residual beyond estimated noise: `{'estimated_label_noise_rate': 0.1208, 'minority_expected_under_noise': 43.14, 'minority_observed': 53, 'ratio': 1.229, 'unexplained_by_noise': False}`

### stochastic

The adequate rule, but a base-satisfying trajectory goes wrong only 55% of the time, drawn fresh on every run. The representation is sufficient; the world is not deterministic.

**STOCHASTIC** — The outcome is not a function of the trajectory: re-running the same trajectory returned a different result 16.67% of the time. Collisions here say nothing about the representation, because NO representation of the trajectory could predict this outcome. Extending the grammar would fit sampling variation.

Eliminations, in the order they were applied:

1. re-running the same trajectory disagreed with itself at rate 0.1667, above the 0.02 reproducibility margin

Residual beyond estimated noise: `{'estimated_label_noise_rate': 0.1833, 'minority_expected_under_noise': 16.5, 'minority_observed': 35, 'ratio': 2.121, 'unexplained_by_noise': True}`

## Authority

- production authority reachable: **False**
- feature grammar unchanged across the run: **True**
- production ruleset hash unchanged: **True**

LB-1 may propose a representation extension; it may not adopt one. The feature grammar is a source constant.

## Acceptance criteria

| criterion | result | detail |
|---|---|---|
| `all_environments_classified_correctly` | PASS | 6 of 6 environments received the verdict their construction warrants: adequate→ADEQUATE; inadequate_delegation→INADEQUATE; inadequate_timing→INADEQUATE; inadequate_unlocalised→INADEQUATE; noise_limited→NOISE_LIMITED; stochastic→STOCHASTIC |
| `inadequacy_localised_to_the_withheld_observable` | PASS | inadequate_delegation: nominated 'actor_id' (withheld: 'actor_id'), resolution 1.0; inadequate_timing: nominated 'timestamp' (withheld: 'timestamp'), resolution 1.0 |
| `inadequacy_outside_the_pool_is_reported_as_unlocalised` | PASS | inadequate_unlocalised: localised=False, best family 'elapsed' resolved only 0.5, proposal emitted=False |
| `reading_the_observable_recovers_the_outcome` | PASS | inadequate_delegation: held-out F1 +0.3641; inadequate_timing: held-out F1 +0.2897 (minimum +0.10) |
| `the_adequate_control_really_is_adequate` | PASS | the current grammar reaches held-out F1 1.0 on the adequate environment (minimum 0.95); a low score would mean the negative control was not testing adequacy |
| `no_extension_proposed_where_none_is_warranted` | PASS | a representation-extension proposal was emitted only for environments that are genuinely beyond the grammar |

Thresholds: `{'min_recovery_f1_gain': 0.1, 'min_adequate_baseline_f1': 0.95, 'probe_sample': 240}`

---

Reproduce: `cd living-boundary && python -m living_boundary.run_lb1 --seed 42`
