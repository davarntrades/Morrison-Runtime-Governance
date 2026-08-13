"""LB-3 — does a discovered structure survive a genuinely different environment?

    cd living-boundary
    python -m living_boundary.run_lb3 --seed 42

LB-0 discovered a compositional hazard. LB-1 showed the discovery layer can
notice when its own representation is inadequate. LB-2 showed that inadequacy
can be established from sealed evidence without replay. All three worked inside
ONE environment, and every one of their claims is therefore conditional on a
question none of them asked:

    is the thing that was discovered a property of the trajectory, or a property
    of the world it was discovered in?

LB-3 asks it. A candidate is discovered in `env_00`, sealed, and evaluated in
eight environments it has never seen — renamed, re-provisioned, moved to another
domain, redistributed, structurally perturbed, partially altered, adversarially
mimicked, and re-encoded. Three representations are carried through the same
matrix, ten competing explanations are fitted and transferred on identical
terms, and the result is a statement about WHICH LEVEL OF ABSTRACTION TRANSFERS
rather than a yes or a no.

THE EXPERIMENT IS DESIGNED TO FAIL IN FOUR SPECIFIC WAYS

  · `env_05` inverts the identity-continuity relation while leaving the
    vocabulary alone. A candidate that transfers here has learned surface.
  · `env_07` is built to resemble the discovery world in every correlation a
    candidate might have latched onto, and carries a different rule. A
    candidate that transfers here fails LB-3 outright.
  · `env_06` keeps part of the structure and removes part. Anything other than
    a degraded result here is an overclaim.
  · `env_08` breaks the one schema-level assumption the whole method rests on.
    It is included so the assumption is measured rather than asserted.

THE ACCEPTANCE GATE IS DECLARED BELOW, BEFORE ANY NUMBER EXISTS. So is the
transfer retention metric, in `transfer/retention.py`.

AUTHORITY. LB-3 observes, compares, measures, falsifies, ranks and proposes. It
does not adopt. Every surviving candidate terminates at REVIEW_REQUIRED and
every LB-0/LB-1/LB-2 invariant is re-verified on each run.
"""

from __future__ import annotations

import argparse
import json
import sys

from living_boundary import authority
from living_boundary.discovery.features import FEATURE_FAMILIES
from living_boundary.evidence.lb3_report import (
    lb3_console_report, lb3_markdown_report,
)
from living_boundary.evidence.provenance import (
    ExperimentEvidence, code_provenance, wall_clock, write_package,
)
from living_boundary.experiments.lb3_generator import (
    LB3_DATASET_VERSION, build_corpus, build_discovery_splits, corpus_manifest,
)
from living_boundary.experiments.lb3_worlds import (
    DISCOVERY_ENV, FALSIFICATION_ENVIRONMENTS, LB3_WORLD_VERSION,
    OVER_APPROXIMATION_PROBE_ENV, TRANSFER_ENVIRONMENTS, environment_metadata,
)
from living_boundary.representation.proposal import (
    ProposalStatus, RepresentationProposal,
)
from living_boundary.representation.refit import fit_conjunction
from living_boundary.transfer import falsification
from living_boundary.transfer.evaluator import (
    ABSTAINED, COLLAPSED, DEGRADED, MAX_ALIGNMENT_COST,
    MIN_DESTRUCTIVE_EXTINCTION, MIN_PRESERVING_AGREEMENT,
    MIN_RETENTION_FOR_TRANSFER, TRANSFERRED, evaluate_environment,
    invariance_battery,
)
from living_boundary.transfer.freeze import freeze
from living_boundary.transfer.grammars import GRAMMARS, grammar_fn, grammar_version
from living_boundary.transfer.hypotheses import HYPOTHESES
from living_boundary.transfer.retention import (
    MIN_DISCOVERY_LIFT, aggregate, lift, retention,
)
from living_boundary.transfer.roles import align, induce_roles

# ═══════════════════════════════════════════════════════════════════════
# Acceptance gate — declared before the experiment was ever run
# ═══════════════════════════════════════════════════════════════════════
# The environments in which transfer is SUPPOSED to hold. Everything else in
# the matrix is a control, and a control that transfers is a failure.
TRANSFER_EXPECTED = ("env_01", "env_02", "env_03", "env_04")
# Controls, with what each is supposed to do.
MUST_NOT_TRANSFER = ("env_05", "env_07")
MUST_DEGRADE = ("env_06",)
ASSUMPTION_PROBE = "env_08"
# A competing explanation must fall at least this far short of the candidate's
# mean retention, or the evidence does not distinguish the two stories.
MIN_ADVANTAGE_OVER_COMPETITORS = 0.25
# Seeds for replication. Three, per the LB-3 specification.
REPLICATION_SEEDS = (42, 43, 44)
# Search depths tried at selection time; the winner is chosen by the WORSE of
# its two independent discovery-side scores, never by the better.
SEARCH_DEPTHS = (2, 3, 4, 5, 6)

SCORING_RULE = "min(F1_fit, F1_select) over depths 2..6, ties to fewer literals"


def _labels(corpus):
    return list(corpus.labels)


# ═══════════════════════════════════════════════════════════════════════
# Discovery — reads env_00 and nothing else
# ═══════════════════════════════════════════════════════════════════════

def _discover(splits, grammar, reference_roles):
    """Fit a candidate on the discovery environment. No transfer corpus in scope.

    Two independently generated discovery corpora are used: one proposes the
    conjunction, the other decides between proposals. LB-0 established the hard
    way that a confounder perfectly correlated inside one corpus is
    indistinguishable from structure using that corpus alone; here the
    second-corpus gate sits at SELECTION time rather than inside the beam, which
    is weaker than LB-0's arrangement and is recorded as such in the README.
    """
    feature_fn = grammar_fn(grammar, reference_roles)
    fit_corpus, select_corpus = splits["fit"], splits["select"]

    best_key = None
    best = ()
    for depth in SEARCH_DEPTHS:
        refit = fit_conjunction(fit_corpus.trajectories, _labels(fit_corpus),
                                feature_fn, max_depth=depth)
        if not refit.literals:
            continue
        fit_score = lift(
            [refit.predict(feature_fn(t)) for t in fit_corpus.trajectories],
            fit_corpus.labels)
        select_score = lift(
            [refit.predict(feature_fn(t)) for t in select_corpus.trajectories],
            select_corpus.labels)
        score = min(fit_score["f1"], select_score["f1"])
        key = (-score, len(refit.literals), tuple(sorted(refit.literals)))
        if best_key is None or key < best_key:
            best_key = key
            best = (refit, fit_score, select_score, depth)

    if best_key is None:
        return None, {}
    refit, fit_score, select_score, depth = best

    held_out = splits["held_out"]
    held_score = lift(
        [refit.predict(feature_fn(t)) for t in held_out.trajectories],
        held_out.labels)
    metrics = {
        "fit": fit_score, "select": select_score, "held_out": held_score,
        "search_depth": depth,
        "scoring_rule": SCORING_RULE,
    }
    candidate = freeze(
        candidate_id=f"LB3-{grammar.upper()}",
        grammar=grammar, grammar_version=grammar_version(grammar),
        literals=refit.literals, discovery_env=splits["fit"].env_id,
        thresholds={
            "min_retention_for_transfer": MIN_RETENTION_FOR_TRANSFER,
            "max_alignment_cost": MAX_ALIGNMENT_COST,
            "min_preserving_agreement": MIN_PRESERVING_AGREEMENT,
            "min_destructive_extinction": MIN_DESTRUCTIVE_EXTINCTION,
            "min_discovery_lift": MIN_DISCOVERY_LIFT,
        },
        scoring_rule=SCORING_RULE, discovery_metrics=metrics)
    return candidate, metrics


# ═══════════════════════════════════════════════════════════════════════
# Transfer
# ═══════════════════════════════════════════════════════════════════════

def _transfer_matrix(candidate, corpora, reference_roles, discovery_lift):
    results = {}
    for corpus in corpora:
        results[corpus.env_id] = evaluate_environment(
            candidate, corpus, reference_roles, discovery_lift)
    return results


def _summarise(results, environments) -> dict:
    measures = []
    for env_id in environments:
        result = results.get(env_id)
        if result is None or not result.retention.get("defined"):
            continue
        measures.append(retention(env_id, result.retention["discovery_lift"],
                                  result.retention["transfer_lift"]))
    summary = aggregate(measures)
    summary["abstained"] = [env_id for env_id in environments
                            if results.get(env_id)
                            and results[env_id].outcome == ABSTAINED]
    return summary


def _competing(splits, corpora, discovery_lifts) -> dict:
    """Fit every rival explanation on the discovery environment and transfer it."""
    fit_corpus = splits["fit"]
    held_out = splits["held_out"]
    out = {}
    for hypothesis in HYPOTHESES:
        predictor, literals = hypothesis.fit(fit_corpus.trajectories,
                                             _labels(fit_corpus))
        discovery_side = lift([predictor(t) for t in held_out.trajectories],
                              held_out.labels)
        rows = {}
        measures = []
        for corpus in corpora:
            performance = lift([predictor(t) for t in corpus.trajectories],
                               corpus.labels)
            measure = retention(corpus.env_id, discovery_side["lift"],
                                performance["lift"])
            rows[corpus.env_id] = {
                "f1": performance["f1"], "lift": performance["lift"],
                "retention": measure.as_dict(),
            }
            if corpus.env_id in TRANSFER_EXPECTED and measure.defined:
                measures.append(measure)
        summary = aggregate(measures)
        out[hypothesis.name] = {
            "description": hypothesis.description,
            "literals": list(literals),
            "discovery": discovery_side,
            "per_environment": rows,
            "expected_transfer_summary": summary,
        }
    discovery_lifts.update({name: row["discovery"]["lift"]
                            for name, row in out.items()})
    return out


# ═══════════════════════════════════════════════════════════════════════
# Verdict
# ═══════════════════════════════════════════════════════════════════════

def _known_failure_modes(results, invariance, environments) -> list:
    """Failure modes derived from what was MEASURED, not from prose.

    The evidence package is required to carry these; a candidate presented
    without them is a candidate presented without its experimental history,
    which is the thing §11 of the LB-3 specification exists to prevent.
    """
    modes = []
    for env_id, result in sorted(results.items()):
        if result.outcome in (COLLAPSED, DEGRADED, ABSTAINED):
            modes.append({
                "environment": env_id,
                "condition": environments.get(env_id, {}).get("condition", ""),
                "outcome": result.outcome,
                "retention": result.retention.get("retention"),
                "reason": result.reason,
            })
    for name, row in sorted(invariance.get("preserving", {}).items()):
        if row["agreement"] < MIN_PRESERVING_AGREEMENT:
            modes.append({"transform": name, "kind": "preserving",
                          "agreement": row["agreement"],
                          "reason": "the candidate moved under a transform "
                                    "that should not have moved it"})
    for name, row in sorted(invariance.get("destructive", {}).items()):
        if row["extinction"] < MIN_DESTRUCTIVE_EXTINCTION:
            modes.append({"transform": name, "kind": "destructive",
                          "extinction": row["extinction"],
                          "reason": "the candidate kept firing after the "
                                    "relation it claims to need was destroyed"})
    return modes


def _falsification_failure_modes(checks) -> list:
    """Battery failures are failure modes of the candidate, not footnotes."""
    return [{"check": check["check"], "outcome": check.get("outcome"),
             "reason": check.get("detail", "")}
            for check in checks if not check.get("passed", True)]


def _verdict(record) -> dict:
    """Score the run against the gate declared at the top of this module."""
    criteria = []

    def _check(name, passed, detail):
        criteria.append({"criterion": name, "passed": bool(passed),
                         "detail": detail})
        return bool(passed)

    grammar = record["primary_grammar"]
    if grammar is None:
        return {"decision": "INDETERMINATE", "criteria": [],
                "detail": "no grammar produced a candidate clearing the "
                          "minimum discovery lift"}

    per_grammar = record["grammars"][grammar]
    results = per_grammar["transfer"]
    summary = per_grammar["expected_transfer_summary"]
    invariance = per_grammar["invariance"]

    _check("materially_above_baseline_across_unseen_environments",
           summary.get("defined") and summary["minimum"] >= MIN_RETENTION_FOR_TRANSFER,
           f"minimum retention {summary.get('minimum')} across "
           f"{TRANSFER_EXPECTED} (floor {MIN_RETENTION_FOR_TRANSFER}); worst is "
           f"{summary.get('worst_environment')}")

    _check("survives_semantics_preserving_transformations",
           invariance["preserving_passes"],
           f"minimum agreement {invariance['min_preserving_agreement']} across "
           f"{len(invariance['preserving'])} transforms "
           f"(floor {MIN_PRESERVING_AGREEMENT})")

    destroyed = [results[e]["outcome"] for e in MUST_NOT_TRANSFER
                 if e in results]
    _check("collapses_when_the_structure_is_destroyed",
           invariance["destructive_passes"]
           and all(outcome != TRANSFERRED for outcome in destroyed),
           f"minimum extinction {invariance['min_destructive_extinction']} "
           f"(floor {MIN_DESTRUCTIVE_EXTINCTION}); structural controls "
           f"{dict(zip(MUST_NOT_TRANSFER, destroyed))}")

    rivals = record["competing_hypotheses"]
    best_rival, best_rival_score = None, -1.0
    for name, row in rivals.items():
        score = row["expected_transfer_summary"].get("mean", 0.0)
        if row["expected_transfer_summary"].get("defined") and score > best_rival_score:
            best_rival, best_rival_score = name, score
    candidate_mean = summary.get("mean", 0.0)
    _check("environment_specific_heuristics_do_not_explain_it",
           best_rival is None
           or candidate_mean - best_rival_score >= MIN_ADVANTAGE_OVER_COMPETITORS,
           f"candidate mean retention {candidate_mean}; best rival "
           f"{best_rival!r} at {round(best_rival_score, 4)} "
           f"(required margin {MIN_ADVANTAGE_OVER_COMPETITORS})")

    control = results.get("env_07", {})
    _check("negative_control_does_not_falsely_support_transfer",
           control.get("outcome") in (COLLAPSED, DEGRADED, ABSTAINED),
           f"env_07 (adversarial surface similarity, different rule): "
           f"{control.get('outcome')} at retention "
           f"{control.get('retention', {}).get('retention')}")

    leakage = record["falsification"]
    leak_checks = [c for c in leakage if c["check"] in
                   ("label_shuffle", "role_model_shuffle",
                    "confounder_injection")]
    _check("leakage_and_contamination_checks_pass",
           all(c.get("passed", False) for c in leak_checks),
           "; ".join(f"{c['check']}={'PASS' if c.get('passed') else 'FAIL'}"
                     for c in leak_checks))

    _check("authority_isolation_holds",
           record["authority"]["production_authority_reachable"] is False
           and record["grammar_immutability"]["unchanged"]
           and record["production_fingerprint"]["unchanged"],
           "production authority unreachable, feature grammar byte-identical, "
           "production ruleset hash unchanged")

    # TIGHTENED AFTER MEASUREMENT, AND RECORDED AS SUCH.
    #
    # This criterion originally required only that the discovered STRUCTURE be
    # identical across seeds, which it is on every seed tried. Running the
    # invariance battery per seed showed that the VERDICT is not: the
    # `pad_trace` re-alignment cost lands in [3.8, 6.2] against a declared
    # ceiling of 6.0, and which side of it a seed falls on decides whether the
    # invariance criterion passes. A replication check that reports "stable"
    # while the run's own verdict flips between seeds is not a replication
    # check. Tightening a gate so it detects a measured instability is the
    # opposite of the move this project warns about; loosening one to make a
    # run pass is what it warns about.
    replication = record.get("replication", {})
    _check("reproduces_across_seeds",
           replication.get("structure_stable", False)
           and replication.get("invariance_stable", False),
           replication.get("detail", "replication was not run"))

    _check("transfer_evaluation_never_changed_the_candidate",
           per_grammar["structure_hash_before"] == per_grammar["structure_hash_after"],
           f"structure hash {per_grammar['structure_hash_before']} before and "
           f"after the entire transfer evaluation")

    probe = next((c for c in leakage if c["check"] == "over_approximation_probe"),
                 None)
    _check("the_recovered_structure_is_not_a_strict_over_approximation",
           bool(probe) and probe.get("passed"),
           (f"probe corpus {probe.get('environment')}: {probe.get('outcome')} "
            f"at F1 {probe.get('f1')}, firing rate {probe.get('firing_rate')} — "
            f"{probe.get('detail')}") if probe else "the probe did not run")

    _check("known_failure_modes_are_recorded_with_the_candidate",
           bool(per_grammar["known_failure_modes"]),
           f"{len(per_grammar['known_failure_modes'])} measured failure modes "
           f"travel with the candidate in its provenance record")

    passed = [c["criterion"] for c in criteria if c["passed"]]
    failed = [c["criterion"] for c in criteria if not c["passed"]]

    # The ladder. SUPPORTED requires everything; the interesting outcomes are
    # the two in the middle, and they are distinguished by whether the failure
    # is about REACH or about VALIDITY.
    integrity = {"negative_control_does_not_falsely_support_transfer",
                 "leakage_and_contamination_checks_pass",
                 "authority_isolation_holds",
                 "transfer_evaluation_never_changed_the_candidate",
                 "collapses_when_the_structure_is_destroyed"}
    if not failed:
        decision = "SUPPORTED"
    elif integrity & set(failed):
        decision = "NOT_SUPPORTED"
    elif summary.get("defined") and summary.get("mean", 0.0) > 0.0:
        decision = "PARTIALLY_SUPPORTED"
    else:
        decision = "INDETERMINATE"

    return {"decision": decision, "criteria": criteria,
            "passed": passed, "failed": failed,
            "primary_grammar": grammar,
            "thresholds": {
                "min_retention_for_transfer": MIN_RETENTION_FOR_TRANSFER,
                "min_advantage_over_competitors": MIN_ADVANTAGE_OVER_COMPETITORS,
                "min_preserving_agreement": MIN_PRESERVING_AGREEMENT,
                "min_destructive_extinction": MIN_DESTRUCTIVE_EXTINCTION,
                "max_alignment_cost": MAX_ALIGNMENT_COST,
            }}


# ═══════════════════════════════════════════════════════════════════════
# One seed
# ═══════════════════════════════════════════════════════════════════════

def analyse(seed: int, full: bool = True, battery: bool = None) -> dict:
    """The whole LB-3 pipeline for one seed.

    `full` controls the expensive comparative work — the rival hypotheses and
    the falsification battery. `battery` controls the invariance transforms
    separately, because replication needs those (the invariance result turned
    out to be the least stable thing in the run) without paying for the rest.
    """
    battery = full if battery is None else battery
    splits = build_discovery_splits(seed, DISCOVERY_ENV)
    transfer = [build_corpus(seed, env, "transfer")
                for env in TRANSFER_ENVIRONMENTS]

    # Roles are induced from the discovery environment's UNLABELLED traces.
    reference_roles = induce_roles(
        DISCOVERY_ENV.env_id,
        list(splits["fit"].trajectories) + list(splits["select"].trajectories))
    reference_roles.alignment = align(reference_roles, reference_roles)

    environments = environment_metadata()
    record = {
        "seed": seed,
        "grammars": {},
        "primary_grammar": None,
        "competing_hypotheses": {},
        "falsification": [],
        "dataset": corpus_manifest(
            list(splits.values()) + transfer),
        "role_models": {"env_00": reference_roles.as_dict()},
    }

    best_grammar, best_score = None, -1.0
    for grammar in GRAMMARS:
        candidate, metrics = _discover(splits, grammar, reference_roles)
        if candidate is None:
            record["grammars"][grammar] = {
                "candidate": None,
                "reason": "no conjunction could be fitted in this grammar"}
            continue

        discovery_lift = metrics["held_out"]["lift"]
        before_hash = candidate.structure_hash
        results = _transfer_matrix(candidate, transfer, reference_roles,
                                   discovery_lift)
        summary = _summarise(results, TRANSFER_EXPECTED)
        measured = (invariance_battery(candidate, splits["held_out"],
                                       reference_roles) if battery
                    else {"preserving": {}, "destructive": {},
                          "partially_destructive_ungated": {},
                          "min_preserving_agreement": 0.0,
                          "min_destructive_extinction": 0.0,
                          "max_realignment_cost": 0.0,
                          "preserving_passes": False,
                          "destructive_passes": False})
        record["grammars"][grammar] = {
            "candidate": candidate.as_dict(),
            "discovery": metrics,
            "transfer": {env_id: result.as_dict()
                         for env_id, result in sorted(results.items())},
            "expected_transfer_summary": summary,
            "invariance": measured,
            "structure_hash_before": before_hash,
            "structure_hash_after": candidate.structure_hash,
            "known_failure_modes": _known_failure_modes(
                results, measured, environments),
            "_candidate": candidate,
        }
        if summary.get("defined") and summary["mean"] > best_score:
            best_grammar, best_score = grammar, summary["mean"]

    record["primary_grammar"] = best_grammar
    if best_grammar is None:
        return record

    primary = record["grammars"][best_grammar]["_candidate"]
    primary_lift = record["grammars"][best_grammar]["discovery"]["held_out"]["lift"]

    if full:
        record["competing_hypotheses"] = _competing(splits, transfer, {})
        record["falsification"] = _falsify(
            seed, splits, transfer, primary, reference_roles=reference_roles,
            discovery_lift=primary_lift, grammar=best_grammar)
        # A battery failure is a failure mode of the candidate, and it travels
        # with the candidate rather than sitting in an appendix.
        record["grammars"][best_grammar]["known_failure_modes"].extend(
            _falsification_failure_modes(record["falsification"]))
        for env_id, cell in record["grammars"][best_grammar]["transfer"].items():
            if cell.get("role_model"):
                record["role_models"][env_id] = cell["role_model"]
    for row in record["grammars"].values():
        row.pop("_candidate", None)
    return record


def _falsify(seed, splits, transfer, candidate, *, reference_roles,
             discovery_lift, grammar) -> list:
    """Every attack in the battery, plus two harness-built adversarial corpora."""
    checks = [
        falsification.label_shuffle(splits["fit"], transfer, grammar,
                                    reference_roles, seed),
        falsification.role_model_shuffle(candidate, transfer, reference_roles,
                                         discovery_lift),
        falsification.literal_ablation(candidate, transfer, reference_roles,
                                       discovery_lift),
        falsification.confounder_injection(candidate, transfer[0],
                                           reference_roles),
    ]
    for environment in FALSIFICATION_ENVIRONMENTS + (OVER_APPROXIMATION_PROBE_ENV,):
        corpus = build_corpus(seed, environment, "falsification")
        result = evaluate_environment(candidate, corpus, reference_roles,
                                      discovery_lift)
        name = ("over_approximation_probe"
                if environment is OVER_APPROXIMATION_PROBE_ENV
                else f"adversarial_corpus:{corpus.env_id}")
        checks.append({
            "check": name,
            "environment": corpus.env_id,
            "outcome": result.outcome,
            "retention": result.retention.get("retention"),
            "firing_rate": round(result.firing_rate, 4),
            "f1": result.performance.get("f1"),
            "passed": result.outcome == TRANSFERRED,
            "detail": result.reason,
        })
    checks.append({
        "check": "suspicious_clean_sweep",
        "passed": True,
        "flag": falsification.suspicious_clean_sweep(checks),
        "detail": ("a battery in which nothing fails has either found a very "
                   "clean result or has stopped testing anything; the two look "
                   "identical from outside and the flag says which to suspect"),
    })
    return checks


# ═══════════════════════════════════════════════════════════════════════
# Replication
# ═══════════════════════════════════════════════════════════════════════

def replicate(seeds) -> dict:
    """Per-seed results, variance, and whether the structure held.

    Unstable seeds are reported individually. Nothing here is averaged before
    it is shown.
    """
    rows = []
    for seed in seeds:
        record = analyse(seed, full=False, battery=True)
        grammar = record["primary_grammar"]
        if grammar is None:
            rows.append({"seed": seed, "grammar": None, "structure_hash": None,
                         "minimum_retention": None, "mean_retention": None,
                         "min_preserving_agreement": None,
                         "max_realignment_cost": None,
                         "invariance_would_pass": False})
            continue
        per_grammar = record["grammars"][grammar]
        summary = per_grammar["expected_transfer_summary"]
        battery = per_grammar["invariance"]
        rows.append({
            "seed": seed,
            "grammar": grammar,
            "structure_hash": per_grammar["candidate"]["structure_hash"],
            "literals": per_grammar["candidate"]["literals"],
            "minimum_retention": summary.get("minimum"),
            "mean_retention": summary.get("mean"),
            "min_preserving_agreement": battery.get("min_preserving_agreement"),
            "max_realignment_cost": battery.get("max_realignment_cost"),
            "invariance_would_pass": bool(battery.get("preserving_passes")),
            "per_environment": {
                env_id: result["retention"].get("retention")
                for env_id, result in per_grammar["transfer"].items()},
        })

    usable = [row for row in rows if row["mean_retention"] is not None]
    means = [row["mean_retention"] for row in usable]
    hashes = {row["structure_hash"] for row in usable}
    grammars = {row["grammar"] for row in usable}
    spread = (max(means) - min(means)) if means else 0.0
    mean_of_means = (sum(means) / len(means)) if means else 0.0
    variance = (sum((m - mean_of_means) ** 2 for m in means) / len(means)
                if means else 0.0)
    stable = (len(usable) == len(rows) and len(grammars) == 1
              and len(hashes) == 1 and spread <= 0.10)

    # The candidate being identical on every seed is NOT the same thing as the
    # RUN reaching the same verdict on every seed, and on this experiment the
    # two came apart. `pad_trace` re-alignment sits close enough to the
    # abstention ceiling that which side of it a seed lands on decides whether
    # the invariance criterion passes. Reporting only the structure hash would
    # have hidden that completely, so the invariance outcome is carried per seed
    # and summarised separately.
    votes = [row.get("invariance_would_pass") for row in usable]
    costs = [row["max_realignment_cost"] for row in usable
             if row.get("max_realignment_cost") is not None]
    span = [round(min(costs), 3), round(max(costs), 3)] if costs else None
    return {
        "seeds": list(seeds),
        "per_seed": rows,
        "grammars_selected": sorted(g for g in grammars if g),
        "distinct_structures": len(hashes),
        "mean_of_means": round(mean_of_means, 4),
        "variance": round(variance, 6),
        "spread": round(spread, 4),
        "structure_stable": stable,
        "invariance_stable": len(set(votes)) <= 1,
        "invariance_passes_on": sum(1 for vote in votes if vote),
        "realignment_cost_range": span,
        "realignment_ceiling": MAX_ALIGNMENT_COST,
        "stable": stable,
        "detail": (f"{len(usable)}/{len(rows)} seeds produced a candidate; "
                   f"{len(hashes)} distinct structure(s); grammar(s) "
                   f"{sorted(g for g in grammars if g)}; mean retention spread "
                   f"{spread:.4f}; the invariance criterion passes on "
                   f"{sum(1 for vote in votes if vote)}/{len(usable)} seeds, "
                   f"with re-alignment cost in {span} against a ceiling of "
                   f"{MAX_ALIGNMENT_COST}"),
    }


# ═══════════════════════════════════════════════════════════════════════
# Run
# ═══════════════════════════════════════════════════════════════════════

def run(seed: int = 42, persist: bool = True, seeds=None) -> dict:
    """Execute LB-3 and return the result record."""
    fingerprint_before = authority.production_fingerprint()
    grammar_before = tuple(FEATURE_FAMILIES)

    evidence = ExperimentEvidence(
        run_id=f"lb3-seed{seed}", seed=seed,
        ruleset_hash=fingerprint_before["ruleset_hash"],
        engine_version="lb3-prototype")

    record = analyse(seed, full=True)
    for grammar, row in sorted(record["grammars"].items()):
        evidence.seal_stage(f"grammar:{grammar}",
                            (row.get("expected_transfer_summary", {})
                             .get("minimum", "no candidate")), row)
    evidence.seal_stage("competing_hypotheses",
                        f"{len(record['competing_hypotheses'])} rivals fitted",
                        record["competing_hypotheses"])
    evidence.seal_stage("falsification",
                        f"{len(record['falsification'])} checks",
                        record["falsification"])

    record["replication"] = replicate(seeds or REPLICATION_SEEDS)
    evidence.seal_stage("replication", record["replication"]["detail"],
                        record["replication"])

    fingerprint_after = authority.production_fingerprint()
    record["authority"] = authority.authority_report(fingerprint_before,
                                                     fingerprint_after)
    record["grammar_immutability"] = {
        "families_before": list(grammar_before),
        "families_after": list(FEATURE_FAMILIES),
        "unchanged": grammar_before == tuple(FEATURE_FAMILIES),
    }
    record["production_fingerprint"] = {
        "before": fingerprint_before["ruleset_hash"],
        "after": fingerprint_after["ruleset_hash"],
        "unchanged": (fingerprint_before["ruleset_hash"]
                      == fingerprint_after["ruleset_hash"]),
    }
    evidence.seal_stage("authority", "authority boundary verified",
                        {"authority": record["authority"],
                         "grammar": record["grammar_immutability"]})

    record["verdict"] = _verdict(record)
    evidence.seal_stage("verdict", record["verdict"]["decision"],
                        record["verdict"])

    run_id = f"lb3-seed{seed}-{evidence.chain.head[:8]}"
    result = dict(record)
    result.update({
        "run_id": run_id,
        "phase": "LB-3",
        "generated_at": wall_clock(),
        "question": ("does a structure discovered in one environment remain "
                     "valid in genuinely different environments that preserve "
                     "the hazard and change its surface?"),
        "world_version": LB3_WORLD_VERSION,
        "dataset_version": LB3_DATASET_VERSION,
        "environments": environment_metadata(),
        "code_provenance": code_provenance(),
        "evidence": evidence.as_dict(),
    })
    result["proposal"] = _proposal(result)

    if persist:
        result["artifact_dir"] = str(write_package(f"lb3/{run_id}",
                                                   _artifacts(result)))
    return result


def _proposal(result) -> dict:
    """The only thing LB-3 is allowed to emit, and only when it earned it."""
    grammar = result["primary_grammar"]
    decision = result["verdict"]["decision"]
    if grammar is None or decision not in ("SUPPORTED", "PARTIALLY_SUPPORTED"):
        return None
    per_grammar = result["grammars"][grammar]
    proposal = RepresentationProposal(
        proposal_id=f"RP-LB3-{grammar}",
        representation=per_grammar["candidate"]["grammar_version"],
        verdict=decision,
        missing_observable="",
        extension_family=grammar,
        rationale=("a candidate discovered in one environment retained "
                   f"{per_grammar['expected_transfer_summary'].get('minimum')} "
                   f"of its advantage in the worst unseen environment where "
                   f"transfer was expected"),
        evidence={
            "candidate": per_grammar["candidate"],
            "transfer": per_grammar["transfer"],
            "invariance": per_grammar["invariance"],
            "competing_hypotheses": {
                name: row["expected_transfer_summary"]
                for name, row in result["competing_hypotheses"].items()},
            "falsification": result["falsification"],
            "replication": result["replication"],
        },
        localisation={"known_failure_modes": per_grammar["known_failure_modes"]},
        demonstrated_recovery={})
    proposal.advance(ProposalStatus.REVIEW_REQUIRED)
    return proposal.as_dict()


def _artifacts(result) -> dict:
    def _json(payload):
        return json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n"

    return {
        "run_manifest.json": _json(result),
        "dataset_manifest.json": _json(result["dataset"]),
        "environment_manifest.json": _json(result["environments"]),
        "role_models.json": _json(result["role_models"]),
        "candidates.json": _json({name: row.get("candidate")
                                  for name, row in result["grammars"].items()}),
        "transfer_matrix.json": _json({
            name: row.get("transfer", {})
            for name, row in result["grammars"].items()}),
        "competing_hypotheses.json": _json(result["competing_hypotheses"]),
        "invariance_results.json": _json({
            name: row.get("invariance", {})
            for name, row in result["grammars"].items()}),
        "falsification_results.json": _json(result["falsification"]),
        "replication.json": _json(result["replication"]),
        "provenance.json": _json({
            "code": result["code_provenance"],
            "evidence": result["evidence"],
            "authority": result["authority"],
            "grammar_immutability": result["grammar_immutability"],
            "production_fingerprint": result["production_fingerprint"],
            "proposal": result["proposal"],
        }),
        "report.md": lb3_markdown_report(result),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m living_boundary.run_lb3",
        description="LB-3: cross-environment structural transfer.")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--no-persist", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--seeds", type=int, nargs="*", default=None)
    parser.add_argument("--require-supported", action="store_true")
    args = parser.parse_args(argv)

    result = run(seed=args.seed, persist=not args.no_persist, seeds=args.seeds)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True, default=str))
    else:
        print(lb3_console_report(result))

    if args.require_supported and result["verdict"]["decision"] != "SUPPORTED":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
