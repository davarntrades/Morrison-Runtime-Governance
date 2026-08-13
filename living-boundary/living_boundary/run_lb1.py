"""LB-1 — can the discovery layer detect that ITS OWN representation is inadequate?

    cd living-boundary
    python -m living_boundary.run_lb1 --seed 42

LB-0 established that the Living Boundary can find a compositional structure
Morrison's ontology could not express. It also documented, as its first
weakness, that the same argument applies one level up:

    "A structure outside the grammar is undiscoverable, silently."

LB-1 attacks the word SILENTLY. The question is not whether the grammar is
complete — no representation is — but whether the system can NOTICE when it is
not, and can tell that apart from ordinary noise.

THE EXPERIMENT

One trace corpus, generated once, labelled by six different environments:

    adequate                the outcome is a conjunction of LB-0 literals
    inadequate_timing       ... AND a burst condition on elapsed time
    inadequate_delegation   ... AND the egress performed by a delegated actor
    inadequate_unlocalised  ... AND one PARTICULAR tool among three that share
                            a capability — outside the grammar AND outside
                            every family in the extension pool
    noise_limited           the adequate rule, labels flipped at 12%
    stochastic              the adequate rule, fired only 55% of the time

The traces handed to the analysis layer are byte-identical across all six, so
any difference in the verdict is caused by the environment and nothing else.
Five of the six produce trajectories that are feature-identical and
outcome-different; only three of those five are representation problems, and
only two of those three are ones the extension pool can explain.

THE PIPELINE, PER ENVIRONMENT

    label the corpus
          |
    feature-space collisions        <- proof the grammar cannot separate
          |
    reproducibility probe           <- ACTIVE EXPERIMENT: run it again, twice
          |
    adequacy verdict                <- by elimination, in a fixed order
          |
    localisation (only if INADEQUATE)
          |
    demonstrated recovery on held-out
          |
    representation-extension proposal  (EXPERIMENTAL, adopts nothing)

THE ACCEPTANCE GATE IS DECLARED BELOW, BEFORE ANY NUMBER EXISTS.
"""

from __future__ import annotations

import argparse
import json
import sys

from living_boundary import authority
from living_boundary.discovery.features import FEATURE_FAMILIES, feature_set
from living_boundary.evidence.lb1_report import (
    lb1_console_report, lb1_markdown_report,
)
from living_boundary.evidence.provenance import (
    ExperimentEvidence, code_provenance, wall_clock, write_package,
)
from living_boundary.experiments.lb1_environment import ENVIRONMENTS
from living_boundary.experiments.lb1_generator import (
    generate_dataset, label_corpus,
)
from living_boundary.experiments.replay_probe import run_probe
from living_boundary.representation.adequacy import (
    AdequacyVerdict, assess_representation,
)
from living_boundary.representation.collisions import find_collisions
from living_boundary.representation.extensions import localise_inadequacy
from living_boundary.representation.proposal import (
    ProposalStatus, RepresentationProposal,
)
from living_boundary.representation.refit import evaluate_refit, fit_conjunction

REPRESENTATION_UNDER_TEST = "lb0-feature-grammar-1.1"

# ── acceptance gate ─────────────────────────────────────────────────────
# Every environment must receive the verdict its construction warrants. This is
# the whole claim: a detector that returns INADEQUATE for everything is not
# detecting anything, and one that never returns it is not either.
REQUIRE_ALL_VERDICTS_CORRECT = True
# The nominated observable must be the one actually withheld. "Something is
# missing" is worth much less than "the timestamps are not being read".
REQUIRE_CORRECT_LOCALISATION = True
# Reading the nominated observable must materially recover the outcome on
# held-out data. Without this, localisation is a plausible story.
MIN_RECOVERY_F1_GAIN = 0.10
# On the adequate environment the grammar should already do well; if it does
# not, the negative control is not testing what it claims to.
MIN_ADEQUATE_BASELINE_F1 = 0.95
# Probe budget. Large enough that a 2% rate is distinguishable from zero.
PROBE_SAMPLE = 240


def _labels(trajectories):
    return [t.is_unsafe_observed for t in trajectories]


def _analyse_environment(dataset, environment, seed: int) -> dict:
    """Run the whole LB-1 analysis for one environment.

    Everything the analysis layer receives is produced here: labelled traces,
    a collision report and two probe rates. The environment object itself is
    used only by the harness — to label, and to re-run during the probe.
    """
    discovery = label_corpus(dataset.corpus("discovery"), environment, seed)
    held_out = label_corpus(dataset.corpus("held_out"), environment, seed)

    collision = find_collisions(discovery)
    probe = run_probe(discovery, environment, seed, sample=PROBE_SAMPLE)
    assessment = assess_representation(collision, probe,
                                       representation=REPRESENTATION_UNDER_TEST)

    record = {
        "environment": environment.as_dict(),
        "collision": collision.as_dict(),
        "probe": probe.as_dict(),
        "assessment": assessment.as_dict(),
        "localisation": None,
        "recovery": None,
        "proposal": None,
    }

    # A refit under the CURRENT grammar, for every environment. It is the
    # honest reference point: "how well can the representation do here at all?"
    base_refit = fit_conjunction(discovery, _labels(discovery), feature_set)
    record["base_refit"] = {
        "literals": list(base_refit.literals),
        "held_out": evaluate_refit(base_refit, held_out, _labels(held_out),
                                   feature_set),
    }

    if assessment.verdict != AdequacyVerdict.INADEQUATE:
        return record

    # ── localisation, which only happens AFTER the verdict ──
    localisation = localise_inadequacy(discovery, collision)
    record["localisation"] = localisation.as_dict()
    if not localisation.localised:
        return record

    family = next(f for f in _pool() if f.name == localisation.best.family)
    extended_fn = family.extend()
    extended_refit = fit_conjunction(discovery, _labels(discovery), extended_fn)
    extended_metrics = evaluate_refit(extended_refit, held_out,
                                      _labels(held_out), extended_fn)
    base_metrics = record["base_refit"]["held_out"]
    recovery = {
        "extension_family": family.name,
        "observable": family.observable,
        "base_held_out": base_metrics,
        "extended_held_out": extended_metrics,
        "f1_gain": round(extended_metrics["f1"] - base_metrics["f1"], 4),
        "extended_literals": list(extended_refit.literals),
    }
    record["recovery"] = recovery

    proposal = RepresentationProposal(
        proposal_id=f"RP-LB1-{environment.name}",
        representation=REPRESENTATION_UNDER_TEST,
        verdict=assessment.verdict,
        missing_observable=family.observable,
        extension_family=family.name,
        rationale=(
            f"{assessment.reason} The disagreement is resolved by reading "
            f"{family.observable!r} ({family.description}), which accounts for "
            f"{localisation.best.resolution:.0%} of it; adding that observable "
            f"raises held-out F1 by {recovery['f1_gain']:+.4f}."),
        evidence={"collision": collision.as_dict(), "probe": probe.as_dict()},
        localisation=localisation.as_dict(),
        demonstrated_recovery=recovery)
    proposal.advance(ProposalStatus.REVIEW_REQUIRED)
    record["proposal"] = proposal.as_dict()
    return record


def _pool():
    from living_boundary.representation.extensions import EXTENSION_POOL
    return EXTENSION_POOL


def _verdict(results: dict) -> dict:
    """Score the run against what each environment was constructed to be.

    The expectations come from the harness, exactly as ground truth did in
    LB-0. The analysis layer never saw them.
    """
    criteria = []
    rows = []

    def _check(name, passed, detail):
        criteria.append({"criterion": name, "passed": bool(passed),
                         "detail": detail})
        return bool(passed)

    correct = 0
    for name, record in sorted(results.items()):
        expected = record["environment_expectations"]["expected_verdict"]
        actual = record["assessment"]["verdict"]
        matched = expected == actual
        correct += 1 if matched else 0
        rows.append({"environment": name, "expected": expected,
                     "actual": actual, "correct": matched})

    _check("all_environments_classified_correctly", correct == len(results),
           "{} of {} environments received the verdict their construction "
           "warrants: {}".format(
               correct, len(results),
               "; ".join(f"{r['environment']}→{r['actual']}"
                         f"{'' if r['correct'] else ' (expected ' + r['expected'] + ')'}"
                         for r in rows)))

    inadequate = {name: record for name, record in results.items()
                  if record["environment_expectations"]["expected_verdict"]
                  == AdequacyVerdict.INADEQUATE}
    # Split by whether the withheld observable is one the extension pool could
    # possibly offer. Both halves have to behave correctly, and the second is
    # the one that keeps the first honest.
    localisable = {n: r for n, r in inadequate.items()
                   if r["environment_expectations"].get("missing_observable")}
    unlocalisable = {n: r for n, r in inadequate.items()
                     if not r["environment_expectations"].get("missing_observable")}

    localised_ok = True
    localisation_details = []
    for name, record in sorted(localisable.items()):
        expected_observable = record["environment_expectations"].get(
            "missing_observable")
        localisation = record.get("localisation") or {}
        best = localisation.get("best") or {}
        actual_observable = best.get("observable")
        ok = bool(localisation.get("localised")) and \
            actual_observable == expected_observable
        localised_ok = localised_ok and ok
        localisation_details.append(
            f"{name}: nominated {actual_observable!r} "
            f"(withheld: {expected_observable!r}), "
            f"resolution {best.get('resolution')}")
    _check("inadequacy_localised_to_the_withheld_observable",
           localised_ok and bool(localisable),
           "; ".join(localisation_details) or "no localisable environment ran")

    # The load-bearing negative control for localisation. An inadequacy whose
    # cause is outside the extension pool must be reported as UNLOCALISED. If
    # the pipeline instead nominated its best partial correlate, every
    # localisation above would be worth nothing, because we could not tell
    # "found it" from "picked the closest thing on offer".
    honest_ok = True
    honest_details = []
    for name, record in sorted(unlocalisable.items()):
        localisation = record.get("localisation") or {}
        best = localisation.get("best") or {}
        ok = (not localisation.get("localised")) and record.get("proposal") is None
        honest_ok = honest_ok and ok
        honest_details.append(
            f"{name}: localised={localisation.get('localised')}, "
            f"best family {best.get('family')!r} resolved only "
            f"{best.get('resolution')}, proposal emitted="
            f"{record.get('proposal') is not None}")
    _check("inadequacy_outside_the_pool_is_reported_as_unlocalised",
           honest_ok and bool(unlocalisable),
           "; ".join(honest_details) or "no unlocalisable environment ran")

    recovery_ok = True
    recovery_details = []
    for name, record in sorted(localisable.items()):
        recovery = record.get("recovery") or {}
        gain = recovery.get("f1_gain", 0.0)
        recovery_ok = recovery_ok and gain >= MIN_RECOVERY_F1_GAIN
        recovery_details.append(f"{name}: held-out F1 {gain:+.4f}")
    _check("reading_the_observable_recovers_the_outcome",
           recovery_ok and bool(localisable),
           "; ".join(recovery_details) + f" (minimum {MIN_RECOVERY_F1_GAIN:+.2f})")

    adequate = results.get("adequate", {})
    adequate_f1 = (adequate.get("base_refit", {})
                   .get("held_out", {}).get("f1", 0.0))
    _check("the_adequate_control_really_is_adequate",
           adequate_f1 >= MIN_ADEQUATE_BASELINE_F1,
           f"the current grammar reaches held-out F1 {adequate_f1} on the "
           f"adequate environment (minimum {MIN_ADEQUATE_BASELINE_F1}); a low "
           f"score would mean the negative control was not testing adequacy")

    no_false_alarm = all(
        record.get("proposal") is None
        for name, record in results.items()
        if record["environment_expectations"]["expected_verdict"]
        != AdequacyVerdict.INADEQUATE)
    _check("no_extension_proposed_where_none_is_warranted", no_false_alarm,
           "a representation-extension proposal was emitted only for "
           "environments that are genuinely beyond the grammar")

    decision = ("SUPPORTED" if all(c["passed"] for c in criteria)
                else "REJECTED")
    return {"decision": decision, "criteria": criteria, "per_environment": rows,
            "thresholds": {
                "min_recovery_f1_gain": MIN_RECOVERY_F1_GAIN,
                "min_adequate_baseline_f1": MIN_ADEQUATE_BASELINE_F1,
                "probe_sample": PROBE_SAMPLE,
            }}


def run(seed: int = 42, persist: bool = True) -> dict:
    """Execute the complete LB-1 experiment and return the result record."""
    fingerprint_before = authority.production_fingerprint()
    grammar_before = tuple(FEATURE_FAMILIES)

    dataset = generate_dataset(seed)
    run_id = f"lb1-seed{seed}-{dataset.corpus_hash[:8]}"
    evidence = ExperimentEvidence(
        run_id=run_id, seed=seed,
        ruleset_hash=fingerprint_before["ruleset_hash"],
        engine_version="lb1-prototype")
    evidence.seal_stage("corpus", "one corpus, five environments",
                        dataset.manifest())

    results = {}
    for environment in ENVIRONMENTS:
        record = _analyse_environment(dataset, environment, seed)
        # Harness expectations are attached AFTER the analysis, for scoring
        # only. Nothing in `representation/` received them.
        record["environment_expectations"] = dict(environment.metadata)
        results[environment.name] = record
        evidence.seal_stage(
            f"environment:{environment.name}",
            record["assessment"]["verdict"], record)

    result = {
        "run_id": run_id,
        "seed": seed,
        "generated_at": wall_clock(),
        "phase": "LB-1",
        "question": ("can the discovery layer detect when its OWN "
                     "representation is inadequate, rather than merely when "
                     "Morrison's ontology is?"),
        "representation_under_test": REPRESENTATION_UNDER_TEST,
        "dataset": dataset.manifest(),
        "code_provenance": code_provenance(),
        "environments": results,
    }

    fingerprint_after = authority.production_fingerprint()
    grammar_after = tuple(FEATURE_FAMILIES)
    result["authority"] = authority.authority_report(
        fingerprint_before, fingerprint_after)
    result["grammar_immutability"] = {
        "families_before": list(grammar_before),
        "families_after": list(grammar_after),
        "unchanged": grammar_before == grammar_after,
        "note": ("LB-1 may propose a representation extension; it may not "
                 "adopt one. The feature grammar is a source constant."),
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
        result["artifact_dir"] = str(write_package(run_id, {
            "run_manifest.json": json.dumps(result, indent=2, sort_keys=True,
                                            default=str) + "\n",
            "corpus_manifest.json": json.dumps(dataset.manifest(), indent=2,
                                               sort_keys=True) + "\n",
            "adequacy_assessments.json": json.dumps(
                {name: record["assessment"] for name, record in results.items()},
                indent=2, sort_keys=True) + "\n",
            "collisions.json": json.dumps(
                {name: record["collision"] for name, record in results.items()},
                indent=2, sort_keys=True) + "\n",
            "probes.json": json.dumps(
                {name: record["probe"] for name, record in results.items()},
                indent=2, sort_keys=True) + "\n",
            "proposals.json": json.dumps(
                [record["proposal"] for record in results.values()
                 if record["proposal"]], indent=2, sort_keys=True) + "\n",
            "authority.json": json.dumps(
                {"authority": result["authority"],
                 "grammar_immutability": result["grammar_immutability"]},
                indent=2, sort_keys=True) + "\n",
            "evidence_chain.jsonl": evidence.to_jsonl() + "\n",
            "report.md": lb1_markdown_report(result),
        }))
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m living_boundary.run_lb1",
        description="LB-1: can the discovery layer detect that its own "
                    "representation is inadequate?")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--no-persist", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--require-supported", action="store_true")
    args = parser.parse_args(argv)

    result = run(seed=args.seed, persist=not args.no_persist)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True, default=str))
    else:
        print(lb1_console_report(result))

    if args.require_supported and result["verdict"]["decision"] != "SUPPORTED":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
