# LB-3 Cross-Environment Structural Transfer — lb3-seed42-ab2740f1

**RESULT: PARTIALLY_SUPPORTED**

> does a structure discovered in one environment remain valid in genuinely different environments that preserve the hazard and change its surface?

| field | value |
|---|---|
| seed | 42 |
| primary grammar | `relational` |
| world version | `lb3-worlds-1.0` |
| generated at | 2026-08-13T12:50:21Z |
| commit | `245aa2637023c438aca9bfaf9d7d3df9407e66e5` |
| evidence chain head | `ab2740f1859feb5b90c3dbcbb20d4a375dc2bedaf176af7492ed7b023319afd2` |

## Environments

| id | condition | description | structure |
|---|---|---|---|
| `env_00` | discovery | the environment the candidate is discovered from | canonical |
| `env_01` | A_surface_rename | same structure, entirely different vocabulary | canonical |
| `env_02` | B_provider_shift | the same hazard expressed through a different provider family with its own capability taxonomy | canonical |
| `env_03` | C_domain_shift | the same structural relation in another domain | canonical |
| `env_04` | D_distribution_shift | A's vocabulary with different frequencies, much longer traces, heavy background noise and a different class balance | canonical |
| `env_05` | E_structural_perturbation | the discovery vocabulary, with the identity continuity condition inverted | identity continuity NEGATED |
| `env_06` | F_partial_invariance | A's vocabulary, with the intervening-verification exemption removed — part of the structure survives and part does not | verification exemption REMOVED |
| `env_07` | G_negative_control | built to resemble the discovery world in every surface correlation while carrying a different rule: the crossing must touch a DIFFERENT subject | subject continuity NEGATED |
| `env_08` | H_encoding_shift | the structure is canonical, but the token marking the inside of the perimeter is itself renamed, breaking the one schema-level assumption LB-3 relies on | canonical |

## Transfer matrix

| grammar | environment | outcome | retention | F1 | alignment cost |
|---|---|---|---|---|---|
| `relational` | `env_01` | **TRANSFERRED** | +1.057 | +1.000 | +0.056 |
| `relational` | `env_02` | **TRANSFERRED** | +1.144 | +1.000 | +0.044 |
| `relational` | `env_03` | **TRANSFERRED** | +1.165 | +1.000 | +0.074 |
| `relational` | `env_04` | **TRANSFERRED** | +1.595 | +1.000 | +0.631 |
| `relational` | `env_05` | **COLLAPSED** | -0.218 | +0.000 | +0.046 |
| `relational` | `env_06` | **DEGRADED** | +0.653 | +0.909 | +0.047 |
| `relational` | `env_07` | **COLLAPSED** | +0.175 | +0.302 | +0.027 |
| `relational` | `env_08` | **COLLAPSED** | -1.038 | +0.000 | +3.480 |
| `surface` | `env_01` | **TRANSFERRED** | +1.057 | +1.000 | +0.000 |
| `surface` | `env_02` | **COLLAPSED** | -0.921 | +0.000 | +0.000 |
| `surface` | `env_03` | **COLLAPSED** | -0.900 | +0.000 | +0.000 |
| `surface` | `env_04` | **TRANSFERRED** | +1.595 | +1.000 | +0.000 |
| `surface` | `env_05` | **COLLAPSED** | -0.218 | +0.000 | +0.000 |
| `surface` | `env_06` | **DEGRADED** | +0.653 | +0.909 | +0.000 |
| `surface` | `env_07` | **COLLAPSED** | +0.175 | +0.302 | +0.000 |
| `surface` | `env_08` | **COLLAPSED** | -1.038 | +0.000 | +0.000 |
| `typed` | `env_01` | **TRANSFERRED** | +1.057 | +1.000 | +0.000 |
| `typed` | `env_02` | **COLLAPSED** | -0.921 | +0.000 | +0.000 |
| `typed` | `env_03` | **COLLAPSED** | -0.900 | +0.000 | +0.000 |
| `typed` | `env_04` | **TRANSFERRED** | +1.595 | +1.000 | +0.000 |
| `typed` | `env_05` | **COLLAPSED** | -0.218 | +0.000 | +0.000 |
| `typed` | `env_06` | **DEGRADED** | +0.653 | +0.909 | +0.000 |
| `typed` | `env_07` | **COLLAPSED** | +0.175 | +0.302 | +0.000 |
| `typed` | `env_08` | **COLLAPSED** | -1.038 | +0.000 | +0.000 |

## Candidate — `relational`

Structure `af8835d9f56dc1c4`, 2 literals, status `none` production authority.

- `NOT rr_ord3i::role_0@internal|role_4@internal|role_1@crossing`
- `rr_ord3is::role_2@internal|role_0@internal|role_1@crossing`

Retention across unseen environments where transfer was expected: **min 1.0**, mean 1.0 (worst `env_01`).

### Known failure modes, measured

- `env_05` — the candidate retains -0.22 of its advantage — it is worth no more than a trivial predictor in this environment (it fires on 33.4% of trajectories)
- `env_06` — the candidate keeps only 65% of its advantage; part of what it depends on is not present here
- `env_07` — the candidate retains 0.18 of its advantage — it is worth no more than a trivial predictor in this environment (it fires on 34.3% of trajectories)
- `env_08` — the candidate retains -1.04 of its advantage — it is worth no more than a trivial predictor in this environment (it fires on 0.0% of trajectories)
- `pad_trace` — the candidate moved under a transform that should not have moved it

### Invariance

| transform | kind | value |
|---|---|---|
| `alpha_rename_identities` | preserving (agreement) | 1.0000 — realignment cost 0.062 |
| `insert_irrelevant_event` | preserving (agreement) | 1.0000 — realignment cost 1.552 |
| `pad_trace` | preserving (agreement) | 0.5875 — realignment cost 6.177, above the abstention ceiling |
| `perturb_irrelevant_fields` | preserving (agreement) | 1.0000 — realignment cost 0.062 |
| `rename_tools` | preserving (agreement) | 1.0000 — realignment cost 0.062 |
| `reorder_independent_steps` | preserving (agreement) | 1.0000 — realignment cost 0.076 |
| `substitute_provider` | preserving (agreement) | 1.0000 — realignment cost 0.062 |
| `substitute_vocabulary` | preserving (agreement) | 1.0000 — realignment cost 0.062 |
| `translate_timestamps` | preserving (agreement) | 1.0000 — realignment cost 0.062 |
| `collapse_boundary` | destructive (extinction) | 1.0000 |
| `fragment_identities` | destructive (extinction) | 1.0000 |
| `fragment_subjects` | destructive (extinction) | 1.0000 |
| `hoist_crossing_to_front` | destructive (extinction) | 1.0000 |
| `reverse_order` | destructive (extinction) | 1.0000 |
| `drop_last_step` | ungated, measured only | 0.7482 |

## Competing explanations

| hypothesis | mean retention | discovery lift | what it says |
|---|---|---|---|
| `nearest_neighbour` | +0.627 | +0.431 | the outcome of the most similar discovery trajectory |
| `token_literal` | +0.500 | +0.203 | a particular capability@domain@boundary step occurred |
| `tool_identity` | +0.000 | +0.015 | a particular tool was used, in a particular order |
| `provider_identity` | +0.000 | +0.316 | the provider or region |
| `session_metadata` | +0.000 | +0.316 | provider, region and session tag together |
| `domain_identity` | +0.000 | +0.134 | which governance domains were touched |
| `capability_domain` | +0.000 | +0.134 | capability and domain combinations |
| `event_frequency` | +0.000 | +0.134 | how many times a capability occurred |
| `trace_length` | +0.000 | +0.063 | how long the trajectory was |
| `positional` | +0.000 | +0.070 | what happened first and what happened last |

## Falsification

- **PASS** `label_shuffle` — a candidate fitted to permuted labels retains 0.000 of its (meaningless) advantage across the transfer environments
- **PASS** `role_model_shuffle` — evaluated through a neighbouring environment's role model, the candidate retains 0.000
- **PASS** `literal_ablation` — at least one conjunct must be load-bearing, or the reported structure contains conditions it does not need
- **PASS** `confounder_injection` — a session tag correlating perfectly with the outcome was injected; the candidate changed 0.0% of its calls
- **PASS** `adversarial_corpus:env_f0` — the candidate keeps 100% of its discovery-side advantage over this environment's own trivial baseline
- **PASS** `adversarial_corpus:env_f1` — the candidate keeps 100% of its discovery-side advantage over this environment's own trivial baseline
- **PASS** `over_approximation_probe` — the candidate keeps 73% of its discovery-side advantage over this environment's own trivial baseline
- **PASS** `suspicious_clean_sweep` — a battery in which nothing fails has either found a very clean result or has stopped testing anything; the two look identical from outside and the flag says which to suspect

## Replication

3/3 seeds produced a candidate; 1 distinct structure(s); grammar(s) ['relational']; mean retention spread 0.0000; the invariance criterion passes on 2/3 seeds, with re-alignment cost in [3.795, 6.177] against a ceiling of 6.0

| seed | grammar | structure | min retention | mean retention | invariance | max re-alignment cost |
|---|---|---|---|---|---|---|
| 42 | `relational` | `af8835d9f56dc1c4` | 1.0 | 1.0 | FAIL | 6.1768 |
| 43 | `relational` | `af8835d9f56dc1c4` | 1.0 | 1.0 | PASS | 3.7948 |
| 44 | `relational` | `af8835d9f56dc1c4` | 1.0 | 1.0 | PASS | 4.282 |

## Authority

- production authority reachable: **False**
- feature grammar unchanged: **True**
- production ruleset hash unchanged: **True**
- proposal status: **REVIEW_REQUIRED**

## Acceptance criteria

| criterion | result | detail |
|---|---|---|
| `materially_above_baseline_across_unseen_environments` | PASS | minimum retention 1.0 across ('env_01', 'env_02', 'env_03', 'env_04') (floor 0.7); worst is env_01 |
| `survives_semantics_preserving_transformations` | FAIL | minimum agreement 0.5875 across 9 transforms (floor 0.95) |
| `collapses_when_the_structure_is_destroyed` | PASS | minimum extinction 1.0 (floor 0.8); structural controls {'env_05': 'COLLAPSED', 'env_07': 'COLLAPSED'} |
| `environment_specific_heuristics_do_not_explain_it` | PASS | candidate mean retention 1.0; best rival 'nearest_neighbour' at 0.6266 (required margin 0.25) |
| `negative_control_does_not_falsely_support_transfer` | PASS | env_07 (adversarial surface similarity, different rule): COLLAPSED at retention 0.1755 |
| `leakage_and_contamination_checks_pass` | PASS | label_shuffle=PASS; role_model_shuffle=PASS; confounder_injection=PASS |
| `authority_isolation_holds` | PASS | production authority unreachable, feature grammar byte-identical, production ruleset hash unchanged |
| `reproduces_across_seeds` | FAIL | 3/3 seeds produced a candidate; 1 distinct structure(s); grammar(s) ['relational']; mean retention spread 0.0000; the invariance criterion passes on 2/3 seeds, with re-alignment cost in [3.795, 6.177] against a ceiling of 6.0 |
| `transfer_evaluation_never_changed_the_candidate` | PASS | structure hash af8835d9f56dc1c4 before and after the entire transfer evaluation |
| `the_recovered_structure_is_not_a_strict_over_approximation` | PASS | probe corpus env_f2: TRANSFERRED at F1 1.0, firing rate 0.4783 — the candidate keeps 73% of its discovery-side advantage over this environment's own trivial baseline |
| `known_failure_modes_are_recorded_with_the_candidate` | PASS | 5 measured failure modes travel with the candidate in its provenance record |

Thresholds: `{'min_retention_for_transfer': 0.7, 'min_advantage_over_competitors': 0.25, 'min_preserving_agreement': 0.95, 'min_destructive_extinction': 0.8, 'max_alignment_cost': 6.0}`

---

Reproduce: `cd living-boundary && python -m living_boundary.run_lb3 --seed 42`