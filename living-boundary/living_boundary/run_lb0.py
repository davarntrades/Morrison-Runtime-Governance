"""LB-0 — one reproducible composition-discovery experiment.

    python -m living_boundary.run_lb0 --seed 42

Runs the whole pipeline, prints a concise report, and writes a machine-readable
evidence package to `living-boundary/artifacts/<run_id>/`.

PIPELINE

     production fingerprint (before)
                |
     seeded dataset: discovery / validation / held-out
                |
     split integrity checks
                |
     baseline ontology  +  strengthened baseline
                |
     ontology gap detection            <- discovery split
                |
    +--> structure search              <- discovery + validation (joint score)
    |           |
    |    structure selection + pruning <- validation
    |           |
    |    candidate primitive  (frozen for this round)
    |           |
    |    falsification battery         <- cases built from the candidate,
    |           |                         run in the experimental environment
    +-----------+  outcomes fed back, at most MAX_REFINEMENT_ROUNDS times
                |
     candidate primitive  (FINAL — frozen here)
                |
     held-out evaluation               <- held-out split, first and only use
                |
     memorisation control + cross-seed stability
                |
     authority checks + production fingerprint (after)
                |
     verdict + sealed evidence package

THE ACCEPTANCE GATE IS DECLARED BELOW, IN SOURCE, BEFORE ANY NUMBER EXISTS.
Every threshold is a constant with a stated reason. None of them is tuned to
the result, and a run that misses any of them says so.
"""

from __future__ import annotations

import argparse
import json
import sys

from living_boundary import authority
from living_boundary.discovery.gap_detector import detect_gap, residual_trajectories
from living_boundary.discovery.primitive_generator import generate_candidate
from living_boundary.discovery.structure_discovery import (
    prune_structure, search_structures, select_structure,
)
from living_boundary.evaluation.evaluator import (
    baseline_predictor, combined_predictor, compare_to_baseline,
    evaluate_predictor, residual_recovery,
)
from living_boundary.evidence.provenance import (
    ExperimentEvidence, code_provenance, run_id_for, wall_clock, write_package,
)
from living_boundary.evidence.report import console_report, markdown_report
from living_boundary.experiments import hidden_ground_truth as oracle
from living_boundary.experiments.runner import run_falsification
from living_boundary.experiments.scenario_generator import generate_dataset
from living_boundary.experiments.split import check_integrity, shuffled_labels
from living_boundary.ontology.baseline import (
    BASELINE_ONTOLOGY, STRENGTHENED_ONTOLOGY,
)
from living_boundary.ontology.candidate_schema import CandidateStatus
from living_boundary.ontology.versions import ontology_record

# ── acceptance gate ─────────────────────────────────────────────────────
# A candidate must beat the baseline by a MARGIN, not by a rounding error: on
# ~900 held-out trajectories, an F1 difference below a few points is within the
# noise of one generator draw.
MIN_F1_IMPROVEMENT = 0.05
# Over-blocking is the failure mode that gets a governance control switched off.
# 5% of ordinary safe traffic is the experimental ceiling for LB-0; it is NOT a
# production promotion threshold, which the blueprint explicitly defers.
MAX_HELD_OUT_FPR = 0.05
# The memorisation control: the same pipeline run against deliberately SHUFFLED
# labels must produce a candidate with no held-out signal. Measured as the
# candidate's own Matthews correlation, NOT as an F1 delta, and that distinction
# was forced by a measurement rather than chosen for elegance: because the
# baseline has recall 0.29 at precision 1.0, almost any predictor that fires
# raises the combined F1, and a noise-fitted candidate scored +0.05 that way.
# MCC is ~0 for an uncorrelated predictor whatever the class balance, so the
# control can actually fail. See `evaluation/metrics.ConfusionMatrix.mcc`.
MAX_SHUFFLE_CONTROL_MCC = 0.15
# Cross-seed agreement. Measured as PREDICTION agreement on a common probe
# corpus rather than literal-set identity, because one structure has many
# equivalent conjunctive forms — see `_stability`. A structure whose predictions
# change with the seed is a fit, not a finding.
MIN_STABILITY_AGREEMENT = 0.95
# Below this, the candidate is describing individual trajectories.
MIN_SUPPORTING_TRACES = 20

SEARCH_MIN_SUPPORT = 12
# Search capacity, not an acceptance threshold. Raised from 12 after the
# cross-seed check reported a literal-set Jaccard of 0.14: at width 12 the
# search found the structure on seed 42 and under-explored on seeds 43 and 44,
# returning a two-literal length heuristic instead. That is a real instability
# and widening the beam is the fix for it — but it is worth being explicit that
# the parameter was changed in response to a measurement, and that the
# measurement it was changed in response to is the STABILITY check, not the
# held-out result, which was not consulted.
SEARCH_BEAM_WIDTH = 48
SEARCH_MAX_DEPTH = 7

# How many times a failed falsification may feed its experiment outcomes back
# into discovery. Bounded deliberately: an unbounded refine-until-it-passes loop
# would eventually fit the falsification battery itself, and the verdict would
# stop meaning anything. Whatever the last round produces is what gets measured
# on held-out, pass or fail.
MAX_REFINEMENT_ROUNDS = 3


def _jaccard(left, right) -> float:
    if not left and not right:
        return 1.0
    union = left | right
    return len(left & right) / len(union) if union else 0.0


def _discover(dataset, ontology, label_of=None, candidate_id="CP-LB0-001",
              extra_observations=()):
    """Search on discovery, select on validation, return the frozen candidate.

    `label_of` maps a trajectory to a boolean; it exists so the memorisation
    control can run the identical pipeline against shuffled labels.

    `extra_observations` are trajectories the system itself constructed and ran
    in the experimental environment during an earlier falsification round. They
    join the discovery corpus as ordinary observations — see
    `experiments/runner.observed_outcomes` for why that is experimentation
    rather than leakage.
    """
    if label_of is None:
        def label_of(trajectory):
            return trajectory.is_unsafe_observed

    fit = residual_trajectories(dataset.split("discovery").trajectories, ontology)
    if extra_observations:
        fit = fit + residual_trajectories(list(extra_observations), ontology)
    fit_labels = [label_of(t) for t in fit]
    selection = residual_trajectories(
        dataset.split("validation").trajectories, ontology)
    selection_labels = [label_of(t) for t in selection]

    search = search_structures(fit, fit_labels,
                               guard_trajectories=selection,
                               guard_labels=selection_labels,
                               min_support=SEARCH_MIN_SUPPORT,
                               beam_width=SEARCH_BEAM_WIDTH,
                               max_depth=SEARCH_MAX_DEPTH)
    structure = select_structure(search, selection, selection_labels,
                                 min_support=SEARCH_MIN_SUPPORT)
    if structure is None:
        return None, search, None
    structure = prune_structure(structure, selection, selection_labels)
    candidate = generate_candidate(structure, fit, fit_labels,
                                   candidate_id=candidate_id,
                                   ontology_version=ontology.version)
    return candidate, search, structure


def _discover_with_experiments(dataset, ontology, seed: int, prefix="CP-LB0"):
    """The full discovery loop: search, falsify, feed experiment outcomes back.

    Returns `(candidate, search, structure, falsification, rounds)`. Used for
    the headline run AND for the cross-seed stability check, so the stability
    number compares like with like — an earlier version compared the refined
    candidate against single-round candidates from neighbouring seeds and
    reported a Jaccard of 0.0, which measured the difference between two
    pipelines rather than the stability of one.
    """
    candidate = search = structure = falsification = None
    observations: list = []
    rounds: list = []
    for round_index in range(MAX_REFINEMENT_ROUNDS):
        candidate, search, structure = _discover(
            dataset, ontology, extra_observations=tuple(observations),
            candidate_id=f"{prefix}-{round_index + 1:03d}")
        if candidate is None:
            break
        candidate.advance(CandidateStatus.TESTING)
        falsification = run_falsification(
            candidate, dataset.split("validation").trajectories,
            seed + round_index)
        rounds.append({
            "round": round_index + 1,
            "candidate_id": candidate.candidate_id,
            "literals": sorted(candidate.literal_names),
            "structure_hash": candidate.structure_hash,
            "falsification_passed": falsification.passed,
            "failures": list(falsification.failures),
            "experiment_observations_carried_forward": len(observations),
        })
        if falsification.passed:
            break
        # The experiments this candidate motivated become observations the next
        # round can learn from. This is the blueprint's discovery loop closing;
        # it is bounded by MAX_REFINEMENT_ROUNDS.
        observations = observations + list(falsification.observations)
    return candidate, search, structure, falsification, rounds


def _split_metrics(ontology, trajectories) -> dict:
    return evaluate_predictor(baseline_predictor(ontology), trajectories).as_dict()


def _stability(seed: int, extra_seeds: int, reference, probe) -> dict:
    """Re-run the whole discovery loop on neighbouring seeds and compare.

    STABILITY IS MEASURED FUNCTIONALLY, NOT SYNTACTICALLY, and that choice
    needs stating because the two disagree here.

    A conjunction has many equivalent forms. On seed 42 the loop expresses the
    read/payment/egress identity chain as `same_identity(read, egress) AND
    subject_link(payment, egress)`; on seeds 43 and 44 it expresses the same
    constraint as `same_identity(payment, egress) AND subject_link(read,
    egress) AND NOT subject_link(payment, read)`. Literal-set Jaccard scores
    that 0.5 and calls it instability. The two predicates agree on essentially
    every trajectory, which is what "the same structure was discovered" actually
    means operationally.

    So the gate is PREDICTION AGREEMENT on a common probe corpus, and Jaccard is
    reported alongside it as the stricter syntactic figure. The probe corpus is
    the reference run's validation split — already consumed by candidate
    generation. Held-out is not touched here; using it would consult the
    measurement distribution once per seed, which is the one thing it is for
    not doing.
    """
    runs = []
    reference_literals = reference.literal_names if reference else frozenset()
    reference_predictions = ([reference.matches(t) for t in probe]
                             if reference else [])
    for offset in range(1, extra_seeds + 1):
        other_seed = seed + offset
        other_dataset = generate_dataset(other_seed)
        candidate, _, _, falsification, _ = _discover_with_experiments(
            other_dataset, BASELINE_ONTOLOGY, other_seed,
            prefix=f"CP-LB0-S{other_seed}")
        literals = candidate.literal_names if candidate else frozenset()
        agreement = 0.0
        if candidate and reference_predictions:
            other_predictions = [candidate.matches(t) for t in probe]
            same = sum(1 for a, b in zip(reference_predictions, other_predictions)
                       if a == b)
            agreement = same / len(probe) if probe else 0.0
        runs.append({
            "seed": other_seed,
            "candidate_found": candidate is not None,
            "falsification_passed": bool(falsification and falsification.passed),
            "structure_hash": candidate.structure_hash if candidate else "",
            "literals": sorted(literals),
            "jaccard_with_reference": round(_jaccard(reference_literals, literals), 4),
            "prediction_agreement_with_reference": round(agreement, 4),
            "identical_structure": bool(
                reference and candidate
                and candidate.structure_hash == reference.structure_hash),
        })
    jaccards = [r["jaccard_with_reference"] for r in runs]
    agreements = [r["prediction_agreement_with_reference"] for r in runs]
    return {
        "seeds_compared": len(runs),
        "probe_trajectories": len(probe),
        "runs": runs,
        "mean_jaccard": round(sum(jaccards) / len(jaccards), 4) if jaccards else None,
        "min_jaccard": round(min(jaccards), 4) if jaccards else None,
        "mean_prediction_agreement": (
            round(sum(agreements) / len(agreements), 4) if agreements else None),
        "min_prediction_agreement": round(min(agreements), 4) if agreements else None,
        "all_identical": all(r["identical_structure"] for r in runs) if runs else None,
    }


def _shuffle_control(dataset, held_out) -> dict:
    """Run the whole pipeline on permuted labels; measure it on true held-out."""
    shuffled = {}
    for name in ("discovery", "validation"):
        shuffled.update(shuffled_labels(dataset.split(name).trajectories,
                                        seed=dataset.seed))

    def _label(trajectory):
        return shuffled.get(trajectory.sequence_id, trajectory.outcome) == "unsafe"

    candidate, _, _ = _discover(dataset, BASELINE_ONTOLOGY, label_of=_label,
                                candidate_id="CP-LB0-SHUFFLE")
    if candidate is None:
        return {"candidate_found": False, "held_out_f1": 0.0,
                "held_out_f1_over_baseline": 0.0, "held_out_mcc": 0.0,
                "interpretation": "no structure was found in shuffled labels, "
                                  "which is the expected outcome"}
    matrix = evaluate_predictor(
        combined_predictor(BASELINE_ONTOLOGY, candidate), held_out)
    alone = evaluate_predictor(candidate.matches, held_out)
    baseline = evaluate_predictor(baseline_predictor(BASELINE_ONTOLOGY), held_out)
    return {
        "candidate_found": True,
        "literals": sorted(candidate.literal_names),
        "held_out_combined": matrix.as_dict(),
        "held_out_candidate_alone": alone.as_dict(),
        "held_out_f1": round(matrix.f1, 4),
        "held_out_f1_over_baseline": round(matrix.f1 - baseline.f1, 4),
        "held_out_mcc": round(alone.mcc, 4),
        "interpretation": (
            "a candidate fitted to permuted labels should have no correlation "
            "with the held-out outcome; the F1 delta is reported alongside but "
            "is not the gate, because an OR with a low-recall baseline raises "
            "F1 for almost any predictor that fires"),
    }


def _verdict(result: dict) -> dict:
    """Apply the declared gate. Every criterion is reported, pass or fail."""
    criteria = []

    def _check(name, passed, detail):
        criteria.append({"criterion": name, "passed": bool(passed),
                         "detail": detail})
        return bool(passed)

    gap = result["ontology_gap"]
    candidate = result.get("candidate_primitive")
    falsification = result["falsification"]
    held_out = result["held_out"]
    strengthened = result["held_out_strengthened"]
    control = result["controls"]["label_shuffle"]
    stability = result["stability"]
    authority_state = result["authority"]

    _check("ontology_gap_detected", gap["detected"], gap["reason"])
    _check(
        "candidate_primitive_produced", candidate is not None,
        "a machine-readable candidate with executable literals was produced"
        if candidate else "structure search produced no candidate")
    _check(
        "candidate_supported_by_traces",
        bool(candidate) and candidate["supporting_traces"] >= MIN_SUPPORTING_TRACES,
        "supporting traces {} (minimum {})".format(
            candidate["supporting_traces"] if candidate else 0,
            MIN_SUPPORTING_TRACES))
    ok_falsify = _check("survived_falsification", falsification["passed"],
                        "; ".join(falsification["failures"]) or
                        "every condition survived targeted ablation and all "
                        "controls held")

    delta = held_out["f1_delta"]
    ok_improve = _check(
        "held_out_improvement_over_baseline", delta >= MIN_F1_IMPROVEMENT,
        f"held-out F1 {delta:+.4f} vs baseline (minimum {MIN_F1_IMPROVEMENT:+.2f})")
    strengthened_delta = strengthened["f1_delta"]
    ok_strengthened = _check(
        "beats_strengthened_baseline", strengthened_delta > 0.0,
        "held-out F1 {:+.4f} vs the strengthened baseline (Morrison's "
        "egress-after-read heuristic)".format(strengthened_delta))
    fpr = held_out["candidate"]["false_positive_rate"]
    ok_fpr = _check("acceptable_false_positive_rate", fpr <= MAX_HELD_OUT_FPR,
                    "held-out false-positive rate {:.4f} (ceiling {})".format(
                        fpr, MAX_HELD_OUT_FPR))
    control_mcc = control.get("held_out_mcc", 0.0)
    ok_control = _check(
        "not_memorisation", control_mcc <= MAX_SHUFFLE_CONTROL_MCC,
        "a candidate fitted to permuted labels reached held-out MCC {:+.4f} "
        "(ceiling {:.2f}); its F1 delta over baseline was {:+.4f}, which is why "
        "MCC and not F1 is the gate".format(
            control_mcc, MAX_SHUFFLE_CONTROL_MCC,
            control.get("held_out_f1_over_baseline", 0.0)))
    agreement = stability.get("mean_prediction_agreement")
    # Stability is a soft criterion: a structure that varies with the seed is
    # INCONCLUSIVE rather than REJECTED, so this result is not folded into
    # `hard_failures` below.
    _check(
        "stable_across_seeds",
        agreement is None or agreement >= MIN_STABILITY_AGREEMENT,
        "mean prediction agreement {} across {} extra seed(s) (minimum {}); "
        "literal-set Jaccard {} for reference".format(
            agreement, stability.get("seeds_compared", 0),
            MIN_STABILITY_AGREEMENT, stability.get("mean_jaccard")))
    ok_authority = _check(
        "production_authority_unreachable",
        not authority_state["production_authority_reachable"],
        "; ".join(authority_state["violations"]) or
        "static scan, promotion refusal, fingerprint comparison and artifact "
        "isolation all passed")

    hard_failures = not (ok_falsify and ok_improve and ok_strengthened
                         and ok_fpr and ok_control and ok_authority)
    all_passed = all(c["passed"] for c in criteria)

    if all_passed:
        decision = "SUPPORTED"
    elif hard_failures:
        decision = "REJECTED"
    else:
        decision = "INCONCLUSIVE"

    return {
        "decision": decision,
        "criteria": criteria,
        "thresholds": {
            "min_f1_improvement": MIN_F1_IMPROVEMENT,
            "max_held_out_false_positive_rate": MAX_HELD_OUT_FPR,
            "max_shuffle_control_mcc": MAX_SHUFFLE_CONTROL_MCC,
            "min_stability_prediction_agreement": MIN_STABILITY_AGREEMENT,
            "min_supporting_traces": MIN_SUPPORTING_TRACES,
        },
    }


def run(seed: int = 42, stability_seeds: int = 2, persist: bool = True) -> dict:
    """Execute one complete LB-0 experiment and return the result record."""
    fingerprint_before = authority.production_fingerprint()

    dataset = generate_dataset(seed)
    integrity = check_integrity(dataset)
    discovery = dataset.split("discovery").trajectories
    validation = dataset.split("validation").trajectories
    held_out = dataset.split("held_out").trajectories

    run_id = run_id_for(seed, dataset.dataset_hash)
    evidence = ExperimentEvidence(
        run_id=run_id, seed=seed,
        ruleset_hash=fingerprint_before["ruleset_hash"],
        engine_version="lb0-prototype")
    evidence.seal_stage("dataset", "seeded synthetic corpus generated",
                        dataset.manifest())
    evidence.seal_stage("split_integrity", "partition disjointness verified",
                        integrity.as_dict())

    # ── baseline first: discovery has no meaning without it ──
    baseline_metrics = {
        name: _split_metrics(BASELINE_ONTOLOGY, split)
        for name, split in (("discovery", discovery), ("validation", validation),
                            ("held_out", held_out))}
    strengthened_metrics = {
        name: _split_metrics(STRENGTHENED_ONTOLOGY, split)
        for name, split in (("discovery", discovery), ("validation", validation),
                            ("held_out", held_out))}
    evidence.seal_stage("baseline", "baseline ontology measured on every split",
                        {"baseline": baseline_metrics,
                         "strengthened": strengthened_metrics})

    # ── ontology gap ──
    gap = detect_gap(discovery, BASELINE_ONTOLOGY)
    evidence.seal_stage("ontology_gap", gap.reason, gap.as_dict())

    # ── discovery, with bounded experiment feedback ──
    candidate, search, structure, falsification, rounds = \
        _discover_with_experiments(dataset, BASELINE_ONTOLOGY, seed)

    evidence.seal_stage("structure_search",
                        "beam search over generic trajectory features",
                        search.as_dict() if search else {})
    evidence.seal_stage("refinement_rounds",
                        f"{len(rounds)} discovery round(s)",
                        rounds)

    if candidate is None:
        result = {
            "run_id": run_id, "seed": seed, "generated_at": wall_clock(),
            "dataset": dataset.manifest(),
            "split_integrity": integrity.as_dict(),
            "ontology": ontology_record(BASELINE_ONTOLOGY.version),
            "code_provenance": code_provenance(),
            "baseline_metrics": baseline_metrics,
            "strengthened_metrics": strengthened_metrics,
            "ontology_gap": gap.as_dict(),
            "search": search.as_dict() if search else {},
            "refinement_rounds": rounds,
            "candidate_primitive": None,
            "falsification": {"passed": False, "failures": [
                "no candidate primitive was produced, so nothing could be "
                "falsified"], "cases_generated": 0, "per_literal": {},
                "per_control": {}, "untestable_literals": [], "criteria": {}},
            "held_out": {"f1_delta": 0.0,
                         "baseline": baseline_metrics["held_out"],
                         "candidate": baseline_metrics["held_out"]},
            "held_out_strengthened": {"f1_delta": 0.0},
            "residual_recovery": {},
            "controls": {"label_shuffle": {"candidate_found": False,
                                           "held_out_f1": 0.0,
                                           "held_out_mcc": 0.0}},
            "stability": {"seeds_compared": 0, "runs": [], "mean_jaccard": None,
                          "mean_prediction_agreement": None},
        }
    else:
        evidence.seal_stage(
            "falsification",
            "PASS" if falsification.passed else "FAIL",
            falsification.as_dict())
        if falsification.passed:
            candidate.advance(CandidateStatus.VALIDATED)

        comparison = compare_to_baseline(
            "held_out", held_out, baseline_predictor(BASELINE_ONTOLOGY),
            combined_predictor(BASELINE_ONTOLOGY, candidate),
            baseline_name=BASELINE_ONTOLOGY.version,
            candidate_name=f"baseline+{candidate.candidate_id}")
        comparison_strengthened = compare_to_baseline(
            "held_out", held_out, baseline_predictor(STRENGTHENED_ONTOLOGY),
            combined_predictor(BASELINE_ONTOLOGY, candidate),
            baseline_name=STRENGTHENED_ONTOLOGY.version,
            candidate_name=f"baseline+{candidate.candidate_id}")
        recovery = residual_recovery(held_out, BASELINE_ONTOLOGY, candidate)
        evidence.seal_stage("held_out", "held-out evaluation, single use",
                            {"comparison": comparison.as_dict(),
                             "strengthened": comparison_strengthened.as_dict(),
                             "residual_recovery": recovery})

        control = _shuffle_control(dataset, held_out)
        stability = _stability(seed, stability_seeds, candidate, validation)
        evidence.seal_stage("controls", "memorisation and stability controls",
                            {"label_shuffle": control, "stability": stability})

        result = {
            "run_id": run_id, "seed": seed, "generated_at": wall_clock(),
            "dataset": dataset.manifest(),
            "split_integrity": integrity.as_dict(),
            "ontology": ontology_record(BASELINE_ONTOLOGY.version),
            "code_provenance": code_provenance(),
            "baseline_metrics": baseline_metrics,
            "strengthened_metrics": strengthened_metrics,
            "ontology_gap": gap.as_dict(),
            "search": search.as_dict(),
            "selected_structure": structure.as_dict() if structure else None,
            "candidate_primitive": candidate.as_dict(),
            "refinement_rounds": rounds,
            "falsification": falsification.as_dict(),
            "held_out": comparison.as_dict(),
            "held_out_strengthened": comparison_strengthened.as_dict(),
            "residual_recovery": recovery,
            "controls": {"label_shuffle": control},
            "stability": stability,
        }

    fingerprint_after = authority.production_fingerprint()
    result["authority"] = authority.authority_report(
        fingerprint_before, fingerprint_after)
    result["production_fingerprint"] = {
        "before": fingerprint_before["ruleset_hash"],
        "after": fingerprint_after["ruleset_hash"],
        "unchanged": (fingerprint_before["ruleset_hash"]
                      == fingerprint_after["ruleset_hash"]),
    }
    evidence.seal_stage("authority", "authority boundary verified",
                        result["authority"])

    result["verdict"] = _verdict(result)
    evidence.seal_stage("verdict", result["verdict"]["decision"],
                        result["verdict"])

    # HARNESS DISCLOSURE. Written last, into the human-readable record only,
    # and never into anything the discovery layer reads. An auditor needs the
    # rule to check the result; the pipeline never had it.
    result["harness_disclosure"] = {
        "hidden_rule_id": oracle.HIDDEN_RULE_ID,
        "hidden_rule_statement": oracle.HIDDEN_RULE_STATEMENT,
        "oracle_version": oracle.ORACLE_VERSION,
        "note": ("Disclosed here for audit only. `tests/"
                 "test_ground_truth_isolation.py` proves no discovery module "
                 "imports the oracle and that no rule-describing token appears "
                 "in the trace dataset."),
    }
    result["evidence"] = evidence.as_dict()

    if persist:
        result["artifact_dir"] = str(write_package(run_id, {
            "run_manifest.json": json.dumps(result, indent=2, sort_keys=True,
                                            default=str) + "\n",
            "dataset_manifest.json": json.dumps(dataset.manifest(), indent=2,
                                                sort_keys=True) + "\n",
            "baseline_metrics.json": json.dumps(
                {"baseline": baseline_metrics,
                 "strengthened": strengthened_metrics},
                indent=2, sort_keys=True) + "\n",
            "detected_gaps.json": json.dumps(gap.as_dict(), indent=2,
                                             sort_keys=True) + "\n",
            "candidate_primitives.json": json.dumps(
                [result["candidate_primitive"]] if result["candidate_primitive"]
                else [], indent=2, sort_keys=True) + "\n",
            "falsification.json": json.dumps(result["falsification"], indent=2,
                                             sort_keys=True) + "\n",
            "held_out_metrics.json": json.dumps(
                {"baseline": result["held_out"],
                 "strengthened_baseline": result["held_out_strengthened"],
                 "residual_recovery": result["residual_recovery"]},
                indent=2, sort_keys=True) + "\n",
            "controls.json": json.dumps(
                {"label_shuffle": result["controls"]["label_shuffle"],
                 "stability": result["stability"]}, indent=2,
                sort_keys=True, default=str) + "\n",
            "authority.json": json.dumps(result["authority"], indent=2,
                                         sort_keys=True) + "\n",
            "provenance.json": json.dumps(
                {"code": result["code_provenance"],
                 "evidence": result["evidence"],
                 "production_fingerprint": result["production_fingerprint"]},
                indent=2, sort_keys=True) + "\n",
            "evidence_chain.jsonl": f"{evidence.to_jsonl()}\n",
            "report.md": markdown_report(result),
        }))
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m living_boundary.run_lb0",
        description="LB-0: can the Living Boundary discover an unsafe "
                    "compositional structure that was not encoded beforehand?")
    parser.add_argument("--seed", type=int, default=42,
                        help="deterministic generator seed (default: 42)")
    parser.add_argument("--stability-seeds", type=int, default=2,
                        help="extra seeds used for cross-seed structure "
                             "stability (default: 2)")
    parser.add_argument("--no-persist", action="store_true",
                        help="run without writing an evidence package")
    parser.add_argument("--json", action="store_true",
                        help="emit the full result record as JSON instead of "
                             "the report")
    parser.add_argument("--require-supported", action="store_true",
                        help="exit non-zero unless the verdict is SUPPORTED")
    args = parser.parse_args(argv)

    result = run(seed=args.seed, stability_seeds=args.stability_seeds,
                 persist=not args.no_persist)

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True, default=str))
    else:
        print(console_report(result))

    if args.require_supported and result["verdict"]["decision"] != "SUPPORTED":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
