"""LB-1's ground-truth boundary, and its new authority invariant.

LB-0's isolation question was "can the discovery layer reach the oracle?".
LB-1 adds a second one that only arises once a system reasons about its own
representation:

    Can the analysis layer reach the ENVIRONMENT — the thing that decides
    outcomes — rather than merely observing outcomes?

and a new authority invariant:

    Can LB-1 widen its own hypothesis space?

The answer to all three must be no, and none of them is self-evident from
reading the code, because `representation/` legitimately consumes the output of
an active experiment. What it may consume is two rates. What it may not consume
is the thing that produced them.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from living_boundary._repo_paths import PACKAGE_ROOT

# Harness modules. `representation/` may not reach any of them: they know the
# rule, the noise setting and whether the world is deterministic.
HARNESS_MODULES = (
    "living_boundary.experiments.lb1_environment",
    "living_boundary.experiments.lb1_generator",
    "living_boundary.experiments.hidden_ground_truth",
    "living_boundary.experiments.replay_probe",
)

ANALYSIS_PACKAGE = "representation"


def _module_name(path: Path) -> str:
    relative = path.relative_to(PACKAGE_ROOT).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(["living_boundary"] + parts)


def _first_party_imports(path: Path):
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
        graph[_module_name(path)] = _first_party_imports(path)
    return graph


def _reachable(graph, start):
    seen = set()
    frontier = [start]
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


def test_the_analysis_layer_cannot_reach_the_environment():
    """`representation/` must not be able to consult what decides outcomes."""
    graph = _graph()
    offenders = []
    for module in sorted(graph):
        suffix = module[len("living_boundary."):]
        if not suffix.startswith(ANALYSIS_PACKAGE):
            continue
        reachable = _reachable(graph, module)
        for harness in HARNESS_MODULES:
            if harness in reachable:
                offenders.append((module, harness))
    assert not offenders, (
        f"analysis modules can reach the harness transitively: {offenders}. "
        f"LB-1 would be measuring retrieval rather than detection.")


def test_the_harness_can_reach_the_environment():
    """The mirror image: an isolation that isolated everything would be a bug."""
    graph = _graph()
    reachable = _reachable(graph, "living_boundary.experiments.replay_probe")
    assert "living_boundary.run_lb1" not in reachable
    runner = _reachable(graph, "living_boundary.run_lb1")
    assert "living_boundary.experiments.lb1_environment" in runner


def test_the_probe_returns_rates_and_nothing_else():
    """The probe is the one channel across the boundary. Check its shape."""
    from living_boundary.experiments.lb1_environment import TIMING
    from living_boundary.experiments.lb1_generator import (
        generate_dataset, label_corpus,
    )
    from living_boundary.experiments.replay_probe import run_probe

    dataset = generate_dataset(7)
    labelled = label_corpus(dataset.corpus("discovery"), TIMING, 7)
    probe = run_probe(labelled, TIMING, 7, sample=40)
    payload = probe.as_dict()

    allowed = {"sampled", "record_disagreements", "record_disagreement_rate",
               "self_disagreements", "self_disagreement_rate",
               "world_is_reproducible", "record_is_faithful", "examples"}
    assert set(payload) == allowed
    for example in payload["examples"]:
        assert set(example) == {"sequence_id", "recorded", "observations"}
        for observation in example["observations"]:
            assert observation in ("safe", "unsafe"), (
                "the probe may report outcomes, never reasons")


def test_no_analysis_module_names_an_unmodelled_observable_directly():
    """The extension pool is generic, not a list of the withheld answers.

    A pool written as `if timestamps_matter: ...` would make localisation a
    lookup. The families are allowed to READ timestamps and actors — that is
    their job — but nothing under `representation/` may reference the
    environment's own vocabulary for them.
    """
    forbidden = {"BURST_SECONDS", "egress_is_delegated", "satisfies_base_rule",
                 "true_outcome", "extra_condition", "unsafe_probability",
                 "label_noise", "egress_uses_specific_action",
                 "elapsed_read_to_egress", "BASE_RULE_LITERALS"}
    for path in sorted((Path(PACKAGE_ROOT) / ANALYSIS_PACKAGE).rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        used = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                used.add(node.id)
            elif isinstance(node, ast.Attribute):
                used.add(node.attr)
        leaked = forbidden & used
        assert not leaked, f"{path.name} references {sorted(leaked)}"


def test_environment_expectations_are_attached_after_the_analysis():
    """The harness's own expectations must not be an input to the verdict."""
    import inspect

    from living_boundary import run_lb1

    source = inspect.getsource(run_lb1._analyse_environment)
    assert "environment_expectations" not in source, (
        "the per-environment analysis must not read the harness's expected "
        "verdict; it is attached afterwards, for scoring only")


# ── the new authority invariant ─────────────────────────────────────────

def test_lb1_cannot_adopt_its_own_representation_extension():
    from living_boundary.representation.proposal import (
        ProposalAuthorityError, ProposalStatus, RepresentationProposal,
    )

    proposal = RepresentationProposal(proposal_id="RP-TEST",
                                      representation="r", verdict="INADEQUATE")
    proposal.advance(ProposalStatus.REVIEW_REQUIRED)
    for forbidden in (ProposalStatus.ADOPTED, ProposalStatus.ENFORCED):
        with pytest.raises(ProposalAuthorityError):
            proposal.advance(forbidden)
    assert proposal.status == ProposalStatus.REVIEW_REQUIRED
    assert proposal.as_dict()["grammar_mutation_authority"] == "none"


def test_unknown_proposal_status_is_rejected():
    from living_boundary.representation.proposal import RepresentationProposal

    proposal = RepresentationProposal(proposal_id="RP-TEST",
                                      representation="r", verdict="INADEQUATE")
    with pytest.raises(ValueError):
        proposal.advance("LIVE")


def test_a_full_lb1_run_does_not_mutate_the_feature_grammar():
    """The grammar is a source constant. LB-1 proposes; humans adopt."""
    from living_boundary.discovery import features
    from living_boundary.run_lb1 import run

    before = tuple(features.FEATURE_FAMILIES)
    result = run(seed=11, persist=False)
    after = tuple(features.FEATURE_FAMILIES)

    assert before == after
    assert result["grammar_immutability"]["unchanged"] is True


def test_a_full_lb1_run_leaves_production_governance_untouched():
    from living_boundary import authority
    from living_boundary.run_lb1 import run

    before = authority.production_fingerprint()
    result = run(seed=11, persist=False)
    after = authority.production_fingerprint()

    assert authority.compare_fingerprints(before, after) == []
    assert result["authority"]["production_authority_reachable"] is False
    assert result["production_fingerprint"]["unchanged"] is True


def test_lb1_modules_pass_the_lb0_static_authority_scan():
    """LB-1 is held to exactly the bar LB-0 set — the scan walks the whole
    package, so the new modules are covered without any new machinery."""
    from living_boundary import authority

    violations = authority.scan_static_authority()
    assert not violations, "\n".join(violations)
