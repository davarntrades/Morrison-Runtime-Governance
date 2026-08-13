"""The battery that tries to make cross-environment transfer look like nothing.

Each check below is an attempt to produce the transfer result WITHOUT the
structure — or to show that the result survives something it should not. A
candidate that passes all of them has not been proved invariant; it has failed
to be disproved by the specific attacks somebody thought of, which is the most
any falsification battery gives you and is worth saying plainly.

    label_shuffle           refit on permuted labels and transfer the result.
                            A transfer number that survives label destruction is
                            a property of the environments, not of the finding.
    role_model_shuffle      evaluate one environment's traces through ANOTHER
                            environment's role model. If retention survives, the
                            alignment step is decorative.
    literal_ablation        drop each conjunct in turn and re-measure transfer.
                            A conjunct whose removal costs nothing was never
                            load-bearing, and its presence in the reported
                            structure is an overclaim.
    surface_inversion       a discovery-vocabulary corpus in which the session
                            metadata correlation is INVERTED. A candidate that
                            leaned on it collapses here.
    confounder_injection    a transfer corpus with a fresh, perfectly correlated
                            session tag added. A structural candidate must not
                            move at all.
    unseen_vocabulary       a corpus whose every action string is new.
    structural_counterexample
                            corpora built with the relation deliberately altered
                            — supplied by the harness, evaluated here blind.

WHAT A CLEAN SWEEP WOULD MEAN

If every check passes perfectly on every grammar, that is not a triumph, it is a
symptom: the environments are probably not as independent as they look, or a
label has leaked. The run reports a `suspicious_clean_sweep` flag for exactly
that reason, and the README says what to do about it.
"""

from __future__ import annotations

from living_boundary.transfer.evaluator import (
    MIN_RETENTION_FOR_TRANSFER, evaluate_environment,
)
from living_boundary.transfer.freeze import freeze
from living_boundary.transfer.grammars import grammar_fn, grammar_version
from living_boundary.transfer.retention import aggregate, lift, retention
from living_boundary.transfer.roles import align, induce_roles
from living_boundary.representation.refit import fit_conjunction

# A shuffled-label candidate is allowed this much aggregate retention before the
# transfer result is considered contaminated.
MAX_SHUFFLE_RETENTION = 0.25
# A candidate evaluated through the wrong environment's role model is allowed
# this much before the alignment step is considered decorative.
MAX_MISALIGNED_RETENTION = 0.50
# Injecting a perfectly correlated confounder must not move the predictions of
# a structural candidate by more than this.
MAX_CONFOUNDER_DRIFT = 0.02


def _shuffled(labels, seed: int):
    """A deterministic permutation. Local RNG, harness-free, seed-derived."""
    import random
    rng = random.Random(seed)
    out = list(labels)
    rng.shuffle(out)
    return out


def label_shuffle(discovery, transfer_corpora, grammar, reference_roles,
                  seed: int) -> dict:
    """Fit on permuted labels, then transfer. Should retain nothing."""
    feature_fn = grammar_fn(grammar, reference_roles)
    permuted = _shuffled(discovery.labels, seed)
    refit = fit_conjunction(discovery.trajectories, permuted, feature_fn)
    if not refit.literals:
        return {"check": "label_shuffle", "fitted": False, "passed": True,
                "detail": "no conjunction could be fitted to permuted labels"}

    candidate = freeze(
        candidate_id="LB3-SHUFFLE", grammar=grammar,
        grammar_version=grammar_version(grammar), literals=refit.literals,
        discovery_env=discovery.env_id, thresholds={}, scoring_rule="shuffled",
        discovery_metrics={})
    predictions = candidate.predict_all(discovery.trajectories, feature_fn)
    discovery_side = lift(predictions, permuted)

    retentions = []
    for corpus in transfer_corpora:
        result = evaluate_environment(candidate, corpus, reference_roles,
                                      discovery_side["lift"])
        if result.retention.get("defined"):
            retentions.append(retention(
                corpus.env_id, discovery_side["lift"],
                result.performance["lift"]))
    summary = aggregate(retentions)
    mean = summary.get("mean", 0.0)
    return {
        "check": "label_shuffle", "fitted": True,
        "literals": list(refit.literals),
        "discovery_lift": discovery_side["lift"],
        "mean_retention": mean,
        "threshold": MAX_SHUFFLE_RETENTION,
        "passed": mean <= MAX_SHUFFLE_RETENTION,
        "detail": ("a candidate fitted to permuted labels retains "
                   f"{mean:.3f} of its (meaningless) advantage across the "
                   f"transfer environments"),
    }


def role_model_shuffle(candidate, corpora, reference_roles,
                       discovery_lift: float) -> dict:
    """Evaluate each environment through the NEXT environment's role model."""
    if candidate.grammar != "relational":
        return {"check": "role_model_shuffle", "applicable": False,
                "passed": True,
                "detail": ("only the relational grammar has an alignment step "
                           "to shuffle")}
    models = {}
    for corpus in corpora:
        model = induce_roles(corpus.env_id, corpus.trajectories)
        model.alignment = align(reference_roles, model)
        models[corpus.env_id] = model

    rows = []
    order = [c.env_id for c in corpora]
    for index, corpus in enumerate(corpora):
        wrong = models[order[(index + 1) % len(order)]]
        feature_fn = grammar_fn("relational", wrong)
        predictions = candidate.predict_all(corpus.trajectories, feature_fn)
        performance = lift(predictions, corpus.labels)
        rows.append(retention(corpus.env_id, discovery_lift,
                              performance["lift"]))
    summary = aggregate(rows)
    mean = summary.get("mean", 0.0)
    return {
        "check": "role_model_shuffle", "applicable": True,
        "mean_retention": mean, "threshold": MAX_MISALIGNED_RETENTION,
        "passed": mean <= MAX_MISALIGNED_RETENTION,
        "per_environment": [row.as_dict() for row in rows],
        "detail": ("evaluated through a neighbouring environment's role model, "
                   f"the candidate retains {mean:.3f}"),
    }


def literal_ablation(candidate, corpora, reference_roles,
                     discovery_lift: float) -> dict:
    """Drop each conjunct in turn; report what transfer costs."""
    rows = []
    for dropped in candidate.literals:
        remaining = tuple(x for x in candidate.literals if x != dropped)
        if not remaining:
            continue
        ablated = freeze(
            candidate_id=f"{candidate.candidate_id}-ABL",
            grammar=candidate.grammar,
            grammar_version=candidate.grammar_version, literals=remaining,
            discovery_env=candidate.discovery_env, thresholds={},
            scoring_rule="ablation", discovery_metrics={})
        measures = []
        for corpus in corpora:
            result = evaluate_environment(ablated, corpus, reference_roles,
                                          discovery_lift)
            if result.retention.get("defined"):
                measures.append(result.retention["retention_clipped"])
        rows.append({
            "dropped": dropped,
            "mean_retention": round(sum(measures) / len(measures), 4)
            if measures else 0.0,
            "environments": len(measures),
        })
    rows.sort(key=lambda row: (row["mean_retention"], row["dropped"]))
    return {
        "check": "literal_ablation",
        "per_literal": rows,
        "load_bearing": [row["dropped"] for row in rows
                         if row["mean_retention"] < MIN_RETENTION_FOR_TRANSFER],
        "passed": bool(rows) and any(
            row["mean_retention"] < MIN_RETENTION_FOR_TRANSFER for row in rows),
        "detail": ("at least one conjunct must be load-bearing, or the reported "
                   "structure contains conditions it does not need"),
    }


def confounder_injection(candidate, corpus, reference_roles) -> dict:
    """Add a perfectly correlated session tag; a structural candidate ignores it."""
    from dataclasses import replace

    from living_boundary.observer.trajectory_builder import NormalisedTrajectory

    feature_fn = _fn_for(candidate, corpus, reference_roles)
    before = candidate.predict_all(corpus.trajectories, feature_fn)

    injected = []
    for trajectory, label in zip(corpus.trajectories, corpus.labels):
        tag = "injected_hot" if label else "injected_cold"
        injected.append(NormalisedTrajectory(
            sequence_id=trajectory.sequence_id,
            events=tuple(replace(e, session_tag=tag)
                         for e in trajectory.events)))
    after = candidate.predict_all(injected, _fn_for(candidate, corpus,
                                                    reference_roles, injected))
    drift = sum(1 for a, b in zip(before, after) if a != b) / max(1, len(before))
    return {
        "check": "confounder_injection", "environment": corpus.env_id,
        "prediction_drift": round(drift, 4), "threshold": MAX_CONFOUNDER_DRIFT,
        "passed": drift <= MAX_CONFOUNDER_DRIFT,
        "detail": ("a session tag correlating perfectly with the outcome was "
                   f"injected; the candidate changed {drift:.1%} of its calls"),
    }


def _fn_for(candidate, corpus, reference_roles, trajectories=None):
    if candidate.grammar != "relational":
        return grammar_fn(candidate.grammar)
    model = induce_roles(corpus.env_id,
                         trajectories if trajectories is not None
                         else corpus.trajectories)
    model.alignment = align(reference_roles, model)
    return grammar_fn("relational", model)


def suspicious_clean_sweep(checks) -> bool:
    """True when nothing failed anywhere — which deserves investigation.

    A battery that never fires has either found a very clean result or has
    stopped testing anything, and the two look identical from the outside. The
    flag exists so the second possibility is on the page rather than in
    somebody's head.
    """
    return bool(checks) and all(check.get("passed", True) for check in checks)
