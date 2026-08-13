"""LB-2 — representational inadequacy from sealed, irreversible evidence.

    cd living-boundary
    python -m living_boundary.run_lb2 --seed 42

LB-1 established that the discovery layer can notice its own representation is
inadequate. It did so with a replay probe — run the trajectory again, twice —
and that operation is unavailable on the evidence a governance system most needs
to learn from. An email already sent, a payment already initiated, a healthcare
record already read: re-running any of them to test an ontology hypothesis would
cause the harm a second time in order to study it.

    Can the system gather defensible evidence that its current representation is
    insufficient, from irreversible observational trajectories, without
    re-executing the original real-world action?

THE SUBSTITUTE FOR REPLAY

Two levels of disagreement, and the gap between them:

    feature-level collision   same features, different outcome
    record-level collision    same COMPLETE record, different outcome

Records determine features, so the second is nested in the first, and the
difference is disagreement the telemetry captured and the representation
ignored. Matched cohorts, temporal consistency, record-level shadow perturbation
and replication on a disjoint validation archive then decide whether one
observable can be named.

WHAT IS KNOWN TO BE LOST, AND IS NOT PAPERED OVER

`BEYOND_TELEMETRY` covers two worlds that LB-1 separated and LB-2 cannot: a
genuinely stochastic outcome, and a real cause that was never recorded. Both
leave archives in which trajectories identical in every captured field ended
differently. Two of the eight scenarios are built to be exactly that pair, and
the acceptance gate expects the SAME verdict for both — the run is scored on
reporting the limit, not on beating it.

SAFETY INVARIANT

Nothing here executes anything. The scenario objects that decided these outcomes
are destroyed before analysis begins; a `SealedArchive` has no execution surface
to call. No production mutation, no live replay, no policy adoption, no
enforcement.

THE ACCEPTANCE GATE IS DECLARED BELOW, BEFORE ANY NUMBER EXISTS.
"""

from __future__ import annotations

import argparse
import json
import sys

from living_boundary import authority
from living_boundary.discovery.features import FEATURE_FAMILIES, feature_set
from living_boundary.evidence.lb2_report import (
    lb2_console_report, lb2_markdown_report,
)
from living_boundary.evidence.provenance import (
    ExperimentEvidence, code_provenance, wall_clock, write_package,
)
from living_boundary.experiments.lb2_builder import build_archives, dataset_manifest
from living_boundary.experiments.lb2_scenarios import SCENARIOS
from living_boundary.observational.archive import feature_signature
from living_boundary.observational.cohorts import (
    analyse_cohorts, candidate_exposures, evaluate_exposure,
)
from living_boundary.observational.counterfactual import shadow_consistency
from living_boundary.observational.inference import Lb2Verdict, assess
from living_boundary.observational.strata import resolution_for, stratify
from living_boundary.observational.temporal import (
    check_consistency, distribution_shift,
)
from living_boundary.representation.extensions import EXTENSION_POOL
from living_boundary.representation.proposal import (
    ProposalStatus, RepresentationProposal,
)
from living_boundary.representation.refit import evaluate_refit, fit_conjunction

REPRESENTATION_UNDER_TEST = "lb0-feature-grammar-1.1"

# ── acceptance gate ─────────────────────────────────────────────────────
# Every scenario must receive the verdict its construction warrants, INCLUDING
# the three that warrant abstention. A pipeline that never abstains is not
# doing observational inference, it is guessing with extra steps.
REQUIRE_ALL_SCENARIOS_CORRECT = True
# Where a gap is localisable, the named observable must be the withheld one.
REQUIRE_CORRECT_LOCALISATION = True
# Adding the nominated observable must improve held-out prediction — measured in
# simulation, on records that already exist, with nothing executed.
MIN_SIMULATED_F1_GAIN = 0.10
# The adequate control must actually be adequate, or it is not a control.
MIN_ADEQUATE_BASELINE_F1 = 0.95
# How many candidate exposures get a temporal consistency check. Ranked by how
# much disagreement they RESOLVE, which is sign-blind — see `resolution_for`.
TEMPORAL_CHECK_TOP_K = 6
# An exposure has to separate a real share of the disagreement before its
# temporal behaviour is worth testing.
MIN_RESOLUTION_FOR_TEMPORAL_CHECK = 0.30


def _labels(trajectories):
    return [t.is_unsafe_observed for t in trajectories]


def _rank_exposures_by_resolution(trajectories, exposures, base_minority,
                                  feature_keys=None):
    """Order candidates by how much disagreement each would remove."""
    ranked = []
    for name, family in exposures:
        def _extra(trajectory, _name=name, _family=family):
            return {_name} if _name in _family.features(trajectory) else set()
        ranked.append((resolution_for(trajectories, _extra, base_minority,
                                      feature_keys=feature_keys),
                       name, family))
    ranked.sort(key=lambda row: (-row[0], row[1]))
    return ranked


def _analyse_scenario(seed: int, scenario) -> dict:
    """Everything LB-2 does for one world. The scenario is used to BUILD, then
    dropped — only archives cross into the analysis below."""
    built = build_archives(seed, scenario)
    manifest = dataset_manifest(seed, built)

    discovery = list(built["discovery"].archive.trajectories)
    validation = list(built["validation"].archive.trajectories)
    held_out = list(built["held_out"].archive.trajectories)
    integrity = built["discovery"].archive.integrity()

    strata = stratify(discovery)
    feature_keys = [feature_signature(t) for t in discovery]
    exposures = candidate_exposures(discovery, EXTENSION_POOL)
    ranked = _rank_exposures_by_resolution(discovery, exposures,
                                           strata.feature_minority,
                                           feature_keys=feature_keys)
    cohorts = analyse_cohorts(discovery, EXTENSION_POOL)

    temporal_checks = {}
    for resolution, name, family in ranked[:TEMPORAL_CHECK_TOP_K]:
        if resolution < MIN_RESOLUTION_FOR_TEMPORAL_CHECK:
            continue
        temporal_checks[name] = check_consistency(discovery, name, family)

    # Shadow perturbation for whatever the cohorts support, using the base-grammar
    # refit extended with that family as the hypothesis under test.
    shadow_results = {}
    for result in cohorts.supported[:4]:
        family = next(f for f in EXTENSION_POOL if f.name == result.family)
        extended_fn = family.extend()
        refit = fit_conjunction(discovery, _labels(discovery), extended_fn)
        shadow_results[result.name] = shadow_consistency(
            discovery, result.name, family,
            lambda t, _r=refit, _f=extended_fn: _r.predict(_f(t)))

    # Re-measure whatever discovery supported on a DISJOINT validation archive.
    # Held-out is reserved for the simulated recovery and is not consulted here.
    replication = {}
    for result in cohorts.supported[:4]:
        family = next(f for f in EXTENSION_POOL if f.name == result.family)
        confirmed = evaluate_exposure(validation, result.name, family)
        flipped = (confirmed.association.pooled_risk_difference
                   * result.association.pooled_risk_difference) < 0
        replication[result.name] = {
            "supported": confirmed.supported,
            "sign_flipped": bool(flipped),
            "matching": confirmed.matching,
            "detail": (f"validation risk difference "
                       f"{confirmed.association.pooled_risk_difference:+.3f} "
                       f"[{confirmed.association.lower:+.3f}, "
                       f"{confirmed.association.upper:+.3f}] over "
                       f"{confirmed.association.strata_informative} strata"),
            "association": confirmed.association.as_dict(),
        }

    assessment = assess(integrity, strata, cohorts, temporal_checks,
                        shadow_results, replication=replication)

    base_refit = fit_conjunction(discovery, _labels(discovery), feature_set)
    record = {
        "scenario": scenario.as_dict(),
        "dataset": manifest,
        "integrity": integrity,
        "strata": strata.as_dict(),
        "cohorts": cohorts.as_dict(),
        "temporal": {name: check.as_dict()
                     for name, check in sorted(temporal_checks.items())},
        "shadow": {name: result.as_dict()
                   for name, result in sorted(shadow_results.items())},
        "replication": replication,
        "assessment": assessment.as_dict(),
        "distribution_shift": distribution_shift(discovery, held_out).as_dict(),
        "base_refit": {
            "literals": list(base_refit.literals),
            "held_out": evaluate_refit(base_refit, held_out,
                                       _labels(held_out), feature_set),
        },
        "simulated_recovery": None,
        "proposal": None,
    }

    if assessment.verdict != Lb2Verdict.INADEQUATE_LOCALISED:
        return record

    family = next(f for f in EXTENSION_POOL
                  if f.name == assessment.localisation["family"])
    extended_fn = family.extend()
    extended_refit = fit_conjunction(discovery, _labels(discovery), extended_fn)
    extended_metrics = evaluate_refit(extended_refit, held_out,
                                      _labels(held_out), extended_fn)
    base_metrics = record["base_refit"]["held_out"]
    recovery = {
        "observable": family.observable,
        "family": family.name,
        "base_held_out": base_metrics,
        "extended_held_out": extended_metrics,
        "f1_gain": round(extended_metrics["f1"] - base_metrics["f1"], 4),
        "executed_anything": False,
        "note": ("measured by re-scoring records that already exist; no "
                 "trajectory was re-run and no provider was contacted"),
    }
    record["simulated_recovery"] = recovery

    proposal = RepresentationProposal(
        proposal_id=f"RP-LB2-{scenario.name}",
        representation=REPRESENTATION_UNDER_TEST,
        verdict=assessment.verdict,
        missing_observable=family.observable,
        extension_family=family.name,
        rationale=assessment.reason,
        evidence={"strata": record["strata"], "integrity": integrity,
                  "cohorts": record["cohorts"]},
        localisation=assessment.localisation,
        demonstrated_recovery=recovery)
    proposal.advance(ProposalStatus.REVIEW_REQUIRED)
    record["proposal"] = proposal.as_dict()
    return record


def _verdict(results: dict) -> dict:
    """Score the run against what each scenario was constructed to be."""
    criteria = []
    rows = []

    def _check(name, passed, detail):
        criteria.append({"criterion": name, "passed": bool(passed),
                         "detail": detail})
        return bool(passed)

    correct = 0
    abstained = 0
    for name, record in sorted(results.items()):
        expected = record["expectations"]["expected_verdict"]
        actual = record["assessment"]["verdict"]
        rows.append({"scenario": name, "expected": expected, "actual": actual,
                     "correct": expected == actual,
                     "abstained": record["assessment"]["abstained"]})
        correct += 1 if expected == actual else 0
        abstained += 1 if record["assessment"]["abstained"] else 0

    summary = "; ".join(
        f"{r['scenario']}→{r['actual']}"
        f"{'' if r['correct'] else ' (expected ' + r['expected'] + ')'}"
        for r in rows)
    _check("all_scenarios_classified_correctly", correct == len(results),
           f"{correct} of {len(results)} correct: {summary}")

    localisable = {n: r for n, r in results.items()
                   if r["expectations"].get("missing_observable")
                   and r["expectations"]["expected_verdict"]
                   == Lb2Verdict.INADEQUATE_LOCALISED}
    ok = True
    details = []
    for name, record in sorted(localisable.items()):
        expected = record["expectations"]["missing_observable"]
        actual = (record["assessment"].get("localisation") or {}).get("observable")
        ok = ok and actual == expected
        details.append(f"{name}: nominated {actual!r} (withheld {expected!r})")
    _check("localisation_names_the_withheld_observable", ok and bool(localisable),
           "; ".join(details) or "no localisable scenario ran")

    ok = True
    details = []
    for name, record in sorted(localisable.items()):
        recovery = record.get("simulated_recovery") or {}
        gain = recovery.get("f1_gain", 0.0)
        ok = ok and gain >= MIN_SIMULATED_F1_GAIN
        details.append(f"{name}: simulated held-out F1 {gain:+.4f}")
    _check("simulated_extension_improves_held_out", ok and bool(localisable),
           "; ".join(details) + f" (minimum {MIN_SIMULATED_F1_GAIN:+.2f}, "
           f"measured without executing anything)")

    # The abstentions are the point, so they are gated individually rather than
    # folded into the overall accuracy number.
    abstaining = {n: r for n, r in results.items()
                  if r["expectations"]["expected_verdict"]
                  in (Lb2Verdict.INCONCLUSIVE, Lb2Verdict.TELEMETRY_LIMITED)}
    ok = all(results[n]["assessment"]["abstained"] for n in abstaining)
    _check("abstains_where_the_evidence_does_not_support_a_claim",
           ok and bool(abstaining),
           "; ".join(f"{n}: {results[n]['assessment']['verdict']}"
                     for n in sorted(abstaining)))

    # Never claim a localisation where none is identifiable.
    non_localisable = {n: r for n, r in results.items()
                       if not r["expectations"].get("missing_observable")}
    ok = all(not (r["assessment"].get("localisation") or {}).get("localised")
             for r in non_localisable.values())
    _check("no_localisation_claimed_where_none_is_identifiable", ok,
           "; ".join(f"{n}: localised="
                     f"{(r['assessment'].get('localisation') or {}).get('localised', False)}"
                     for n, r in sorted(non_localisable.items())))

    ok = all(r.get("proposal") is None for n, r in results.items()
             if r["assessment"]["verdict"] != Lb2Verdict.INADEQUATE_LOCALISED)
    _check("proposals_only_where_a_gap_was_localised", ok,
           "a representation-extension proposal was emitted only for scenarios "
           "where the evidence localised a specific observable")

    adequate_f1 = (results.get("adequate", {}).get("base_refit", {})
                   .get("held_out", {}).get("f1", 0.0))
    _check("the_adequate_control_really_is_adequate",
           adequate_f1 >= MIN_ADEQUATE_BASELINE_F1,
           f"the current grammar reaches held-out F1 {adequate_f1} on the "
           f"adequate scenario (minimum {MIN_ADEQUATE_BASELINE_F1})")

    decision = "SUPPORTED" if all(c["passed"] for c in criteria) else "REJECTED"
    return {"decision": decision, "criteria": criteria, "per_scenario": rows,
            "abstention_rate": round(abstained / max(1, len(results)), 4),
            "classification_accuracy": round(correct / max(1, len(results)), 4),
            "thresholds": {
                "min_simulated_f1_gain": MIN_SIMULATED_F1_GAIN,
                "min_adequate_baseline_f1": MIN_ADEQUATE_BASELINE_F1,
                "temporal_check_top_k": TEMPORAL_CHECK_TOP_K,
            }}


def run(seed: int = 42, persist: bool = True) -> dict:
    """Execute the complete LB-2 experiment and return the result record."""
    fingerprint_before = authority.production_fingerprint()
    grammar_before = tuple(FEATURE_FAMILIES)

    evidence = ExperimentEvidence(
        run_id=f"lb2-seed{seed}", seed=seed,
        ruleset_hash=fingerprint_before["ruleset_hash"],
        engine_version="lb2-prototype")

    results = {}
    for scenario in SCENARIOS:
        record = _analyse_scenario(seed, scenario)
        # Harness expectations attach AFTER the analysis, for scoring only.
        record["expectations"] = dict(scenario.metadata)
        results[scenario.name] = record
        evidence.seal_stage(f"scenario:{scenario.name}",
                            record["assessment"]["verdict"], record)

    run_id = f"lb2-seed{seed}-{evidence.chain.head[:8]}"
    result = {
        "run_id": run_id,
        "seed": seed,
        "phase": "LB-2",
        "generated_at": wall_clock(),
        "question": ("can defensible evidence of representational inadequacy "
                     "be gathered from sealed, irreversible trajectories, "
                     "without re-executing the original action?"),
        "representation_under_test": REPRESENTATION_UNDER_TEST,
        "replay_used": False,
        "code_provenance": code_provenance(),
        "scenarios": results,
    }

    fingerprint_after = authority.production_fingerprint()
    result["authority"] = authority.authority_report(fingerprint_before,
                                                     fingerprint_after)
    result["grammar_immutability"] = {
        "families_before": list(grammar_before),
        "families_after": list(FEATURE_FAMILIES),
        "unchanged": grammar_before == tuple(FEATURE_FAMILIES),
    }
    result["production_fingerprint"] = {
        "before": fingerprint_before["ruleset_hash"],
        "after": fingerprint_after["ruleset_hash"],
        "unchanged": (fingerprint_before["ruleset_hash"]
                      == fingerprint_after["ruleset_hash"]),
    }
    evidence.seal_stage("authority", "authority boundary verified",
                        {"authority": result["authority"],
                         "grammar": result["grammar_immutability"]})

    result["verdict"] = _verdict(results)
    evidence.seal_stage("verdict", result["verdict"]["decision"],
                        result["verdict"])
    result["evidence"] = evidence.as_dict()

    if persist:
        result["artifact_dir"] = str(write_package(f"lb2/{run_id}", {
            "run_manifest.json": json.dumps(result, indent=2, sort_keys=True,
                                            default=str) + "\n",
            "dataset_manifest.json": json.dumps(
                {name: record["dataset"] for name, record in results.items()},
                indent=2, sort_keys=True, default=str) + "\n",
            "observational_cohorts.json": json.dumps(
                {name: record["cohorts"] for name, record in results.items()},
                indent=2, sort_keys=True, default=str) + "\n",
            "collision_analysis.json": json.dumps(
                {name: record["strata"] for name, record in results.items()},
                indent=2, sort_keys=True, default=str) + "\n",
            "uncertainty_analysis.json": json.dumps(
                {name: {"collision_rate": record["strata"]["collision_rate"],
                        "resolvable_fraction":
                            record["strata"]["resolvable_fraction"],
                        "temporal": record["temporal"],
                        "distribution_shift": record["distribution_shift"]}
                 for name, record in results.items()},
                indent=2, sort_keys=True, default=str) + "\n",
            "candidate_extensions.json": json.dumps(
                [record["proposal"] for record in results.values()
                 if record["proposal"]], indent=2, sort_keys=True,
                default=str) + "\n",
            "falsification_results.json": json.dumps(
                {name: record["shadow"] for name, record in results.items()},
                indent=2, sort_keys=True, default=str) + "\n",
            "held_out_metrics.json": json.dumps(
                {name: {"base": record["base_refit"]["held_out"],
                        "simulated_recovery": record["simulated_recovery"]}
                 for name, record in results.items()},
                indent=2, sort_keys=True, default=str) + "\n",
            "provenance.json": json.dumps(
                {"code": result["code_provenance"],
                 "evidence": result["evidence"],
                 "authority": result["authority"],
                 "grammar_immutability": result["grammar_immutability"],
                 "production_fingerprint": result["production_fingerprint"]},
                indent=2, sort_keys=True, default=str) + "\n",
            "report.md": lb2_markdown_report(result),
        }))
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m living_boundary.run_lb2",
        description="LB-2: representational inadequacy from sealed, "
                    "irreversible evidence, without replay.")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--no-persist", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--require-supported", action="store_true")
    args = parser.parse_args(argv)

    result = run(seed=args.seed, persist=not args.no_persist)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True, default=str))
    else:
        print(lb2_console_report(result))

    if args.require_supported and result["verdict"]["decision"] != "SUPPORTED":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
