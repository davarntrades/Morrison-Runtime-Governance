"""LB-3's leakage controls and authority boundary, checked structurally.

LB-3 needs stronger leakage controls than LB-2, because it has a new thing to
leak: the transfer environments. The discovery half must not be able to reach
their labels, their construction parameters, or the hidden rule — and "must not"
has to mean something a reviewer can verify, not a convention somebody followed.

So the checks below are almost all STATIC. They walk the import graph, parse the
source, and read function signatures. A runtime check would pass on a version
that merely happened not to use the reference it was holding; an import-graph
check fails on a version that could.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from living_boundary._repo_paths import PACKAGE_ROOT

ANALYSIS_PACKAGE = "transfer"

HARNESS_MODULES = (
    "living_boundary.experiments.lb3_worlds",
    "living_boundary.experiments.lb3_generator",
    "living_boundary.experiments.lb2_scenarios",
    "living_boundary.experiments.lb2_builder",
    "living_boundary.experiments.lb1_environment",
    "living_boundary.experiments.hidden_ground_truth",
    "living_boundary.experiments.replay_probe",
    "living_boundary.experiments.scenario_generator",
)


def _module_name(path: Path) -> str:
    relative = path.relative_to(PACKAGE_ROOT).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(["living_boundary"] + parts)


def _imports(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("living_boundary"):
                    found.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            if node.module.startswith("living_boundary"):
                found.add(node.module)
                for alias in node.names:
                    found.add(f"{node.module}.{alias.name}")
    return found


def _graph():
    graph = {}
    for path in sorted(Path(PACKAGE_ROOT).rglob("*.py")):
        relative = path.relative_to(PACKAGE_ROOT).as_posix()
        if relative.startswith("tests/") or "__pycache__" in relative:
            continue
        graph[_module_name(path)] = _imports(path)
    return graph


def _reachable(graph, start):
    seen, frontier = set(), [start]
    while frontier:
        current = frontier.pop()
        for target in graph.get(current, ()):
            candidates = [target]
            if target not in graph:
                candidates.append(target.rsplit(".", 1)[0])
            for candidate in candidates:
                if candidate in seen:
                    continue
                seen.add(candidate)
                if candidate in graph:
                    frontier.append(candidate)
    return seen


def _analysis_modules(graph):
    return [module for module in sorted(graph)
            if module[len("living_boundary."):].startswith(ANALYSIS_PACKAGE)]


# ── 1. the analysis layer cannot reach anything that knows the answer ──

def test_the_transfer_layer_cannot_reach_any_harness_module():
    graph = _graph()
    offenders = []
    for module in _analysis_modules(graph):
        reachable = _reachable(graph, module)
        for harness in HARNESS_MODULES:
            if harness in reachable:
                offenders.append((module, harness))
    assert not offenders, f"the transfer layer reaches the harness: {offenders}"


def test_the_transfer_layer_cannot_reach_the_hidden_rule():
    """The single most important edge in the graph."""
    graph = _graph()
    for module in _analysis_modules(graph):
        assert "living_boundary.experiments.lb3_worlds" not in _reachable(
            graph, module), module


def test_role_induction_never_sees_an_outcome():
    """Roles are induced from unlabelled traces, and the signature proves it.

    `induce_roles` takes an environment id and a list of trajectories. If a
    labels argument ever appears, the alignment could be fitted to the answer
    and every transfer number in the run would be worthless.
    """
    from living_boundary.transfer.roles import induce_roles, observe_statistics

    for function in (induce_roles, observe_statistics):
        parameters = list(inspect.signature(function).parameters)
        assert not any("label" in name or "outcome" in name
                       for name in parameters), (function.__name__, parameters)

    source = inspect.getsource(observe_statistics)
    for forbidden in ("is_unsafe_observed", "trajectory_outcome", ".outcome"):
        assert forbidden not in source, (
            f"role induction reads {forbidden!r}; it must be blind to outcomes")


def test_the_discovery_step_receives_only_discovery_corpora():
    """`_discover` is handed the discovery splits and nothing else.

    Checked on the source rather than at runtime: a runtime check passes on a
    version that merely happened not to use the transfer corpora it was given.
    """
    from living_boundary import run_lb3

    # IDENTIFIERS, not substrings, and with the docstring stripped. Two earlier
    # versions of this guard were wrong in the two available ways: one fired on
    # its own documentation, and one fired on the sealed threshold name
    # `min_retention_for_transfer`. A guard that fires on the thing it is
    # documenting trains people to delete the documentation, which
    # `test_portable_paths.py` in this repository already learned the hard way.
    source = inspect.getsource(run_lb3._discover)  # pylint: disable=protected-access
    function = ast.parse(source.lstrip()).body[0]
    if isinstance(function.body[0], ast.Expr):
        function.body = function.body[1:]

    referenced = set()
    for node in ast.walk(ast.Module(body=function.body, type_ignores=[])):
        if isinstance(node, ast.Name):
            referenced.add(node.id)
        elif isinstance(node, ast.Attribute):
            referenced.add(node.attr)

    forbidden = {"TRANSFER_ENVIRONMENTS", "FALSIFICATION_ENVIRONMENTS",
                 "OVER_APPROXIMATION_PROBE_ENV", "build_corpus",
                 "evaluate_environment", "environment_metadata", "transfer"}
    assert not (referenced & forbidden), (
        f"the discovery step references {sorted(referenced & forbidden)}")

    signature = inspect.signature(run_lb3._discover)  # pylint: disable=protected-access
    assert list(signature.parameters) == ["splits", "grammar",
                                          "reference_roles"]


def test_the_analysis_layer_is_deterministic_apart_from_the_declared_shuffle():
    """RNG is confined to the one check that needs a permutation.

    `falsification.label_shuffle` needs to permute labels and says so in its own
    name. Everywhere else in the transfer package, a random draw would mean a
    number that cannot be reproduced from a seed.
    """
    for path in sorted((Path(PACKAGE_ROOT) / ANALYSIS_PACKAGE).rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            if "random" in names:
                assert path.name == "falsification.py", (
                    f"{path.name} imports random outside the declared shuffle")


def test_environment_identifiers_carry_no_answer():
    """What the analysis layer sees of an environment is an opaque id.

    The descriptive names, the rule variants and the expectations live in
    harness metadata that is attached to the record after evaluation. If a
    condition name reached a corpus, the transfer evaluation could branch on it.
    """
    from living_boundary.experiments.lb3_worlds import ALL_ENVIRONMENTS

    for environment in ALL_ENVIRONMENTS:
        assert environment.env_id.startswith("env_")
        assert environment.env_id[4:].isdigit()
        for value in (environment.rule, environment.metadata.get("condition")):
            assert value not in environment.env_id


def test_a_corpus_carries_no_construction_parameter():
    """Nothing in a rendered trace names the rule, the shape or the weights."""
    from living_boundary.experiments.lb3_generator import build_corpus
    from living_boundary.experiments.lb3_worlds import TRANSFER_ENVIRONMENTS

    forbidden = ("canonical", "identity_split", "subject_mismatch",
                 "no_verify_clause", "role_observe", "role_mutate",
                 "role_egress", "role_verify", "hazard", "near_", "benign")
    corpus = build_corpus(11, TRANSFER_ENVIRONMENTS[0], "leak_check", count=40)
    for trajectory in corpus.trajectories:
        for event in trajectory.events:
            blob = " ".join([
                event.action, event.capability, event.domain,
                event.trust_boundary, event.resource, event.identity_id,
                event.session_tag, event.provider, event.region,
                " ".join(event.permission_scope),
                " ".join(f"{k}={v}" for k, v in sorted(event.provenance.items())),
            ])
            for token in forbidden:
                assert token not in blob, (token, blob)


# ── 2. the candidate cannot change once it leaves discovery ──

def test_a_frozen_candidate_cannot_be_mutated():
    from living_boundary.transfer.freeze import freeze

    candidate = freeze("C", "typed", "v1", ("a", "b"), "env_00", {}, "rule", {})
    with pytest.raises(Exception):
        candidate.literals = ("a",)


def test_a_tampered_candidate_raises_instead_of_scoring():
    from dataclasses import replace

    from living_boundary.transfer.freeze import FrozenCandidateError, freeze

    candidate = freeze("C", "typed", "v1", ("a", "b"), "env_00", {}, "rule", {})
    candidate.verify()
    tampered = replace(candidate, literals=("a",))
    with pytest.raises(FrozenCandidateError):
        tampered.verify()


def test_the_evaluator_cannot_import_the_discovery_search():
    """Transfer evaluation has no way to re-fit anything.

    `evaluator.py` scores a sealed candidate. If it could reach the conjunction
    search it could re-fit on the target environment, and the whole experiment
    would be a fitting exercise wearing a transfer label.
    """
    graph = _graph()
    # `living_boundary.transfer` — the package __init__ — is a pure re-export
    # surface with no logic, and importing any submodule executes it, so it
    # reaches everything the package reaches. Walking through it would make this
    # check vacuous, so it is treated as a leaf.
    graph["living_boundary.transfer"] = set()
    reachable = _reachable(graph, "living_boundary.transfer.evaluator")
    assert "living_boundary.representation.refit" not in reachable
    assert "living_boundary.discovery.structure_discovery" not in reachable


# ── 3. every authority invariant, still ──

def test_lb3_cannot_mutate_the_feature_grammar():
    from living_boundary.discovery import features
    from living_boundary.run_lb3 import run

    before = tuple(features.FEATURE_FAMILIES)
    result = run(seed=7, persist=False, seeds=(7,))
    assert tuple(features.FEATURE_FAMILIES) == before
    assert result["grammar_immutability"]["unchanged"] is True


def test_lb3_cannot_change_production_governance():
    from living_boundary import authority
    from living_boundary.run_lb3 import run

    before = authority.production_fingerprint()
    result = run(seed=7, persist=False, seeds=(7,))
    after = authority.production_fingerprint()
    assert not authority.compare_fingerprints(before, after)
    assert result["authority"]["production_authority_reachable"] is False
    assert result["production_fingerprint"]["unchanged"] is True


def test_a_surviving_candidate_terminates_at_review_required():
    from living_boundary.run_lb3 import run

    result = run(seed=7, persist=False, seeds=(7,))
    proposal = result["proposal"]
    assert proposal is not None
    assert proposal["status"] == "REVIEW_REQUIRED"
    assert proposal["production_authority"] == "none"
    assert proposal["grammar_mutation_authority"] == "none"


def test_lb3_cannot_adopt_what_it_proposes():
    from living_boundary.representation.proposal import (
        ProposalAuthorityError, ProposalStatus, RepresentationProposal,
    )

    proposal = RepresentationProposal(proposal_id="RP", representation="r",
                                      verdict="SUPPORTED")
    for status in (ProposalStatus.ADOPTED, ProposalStatus.ENFORCED):
        with pytest.raises(ProposalAuthorityError):
            proposal.advance(status)


def test_crashing_lb3_leaves_the_kernel_untouched(monkeypatch):
    """The invariant LB-0 established, re-checked on this pipeline.

    The crash is injected into role induction — the middle of the pipeline,
    after corpora exist and before any verdict — so the run dies with work in
    flight rather than at a tidy boundary.
    """
    from living_boundary import authority, run_lb3

    def _explode(*_args, **_kwargs):
        raise RuntimeError("injected failure, mid-run")

    before = authority.production_fingerprint()
    monkeypatch.setattr(run_lb3, "induce_roles", _explode)
    with pytest.raises(RuntimeError):
        run_lb3.analyse(3, full=False)
    assert not authority.compare_fingerprints(
        before, authority.production_fingerprint())
