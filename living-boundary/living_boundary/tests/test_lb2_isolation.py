"""LB-2's safety invariant: it CANNOT replay, and it cannot reach production.

The LB-2 safety requirement is stronger than a rule about what the code should
not do, because a rule can be forgotten. The archive handed to the analysis
layer has no execution surface at all, and the scenario objects that decided the
outcomes are gone by the time analysis starts. These tests check both halves of
that, plus every authority invariant LB-0 and LB-1 established.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from living_boundary._repo_paths import PACKAGE_ROOT

ANALYSIS_PACKAGE = "observational"

HARNESS_MODULES = (
    "living_boundary.experiments.lb2_scenarios",
    "living_boundary.experiments.lb2_builder",
    "living_boundary.experiments.lb1_environment",
    "living_boundary.experiments.hidden_ground_truth",
    "living_boundary.experiments.replay_probe",
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


# ── 1. the analysis layer cannot reach anything that knows the answer ──

def test_the_analysis_layer_cannot_reach_the_harness():
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
    assert not offenders, f"analysis reaches the harness: {offenders}"


def test_the_analysis_layer_cannot_reach_the_lb1_replay_probe():
    """The one operation LB-2 exists to do without."""
    graph = _graph()
    for module in sorted(graph):
        if not module[len("living_boundary."):].startswith(ANALYSIS_PACKAGE):
            continue
        assert "living_boundary.experiments.replay_probe" not in _reachable(
            graph, module), module


def test_the_analysis_layer_is_deterministic():
    """No RNG anywhere in the analysis path.

    A module that can draw random numbers can simulate an outcome, and an
    outcome LB-2 simulated is not an outcome the world produced. Every number
    in an LB-2 verdict has to trace back to a sealed record.
    """
    for path in sorted((Path(PACKAGE_ROOT) / ANALYSIS_PACKAGE).rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name != "random", path.name
            elif isinstance(node, ast.ImportFrom):
                assert node.module != "random", path.name


# ── 2. the archive has no execution surface ──

def _archive(scenario_name="missing_observable"):
    from living_boundary.experiments import lb2_scenarios
    from living_boundary.experiments.lb2_builder import DISCOVERY, build_archive

    scenario = next(s for s in lb2_scenarios.SCENARIOS
                    if s.name == scenario_name)
    return build_archive(7, scenario, DISCOVERY).archive


def test_the_sealed_archive_exposes_nothing_callable():
    archive = _archive()
    for name, value in vars(archive).items():
        assert not callable(value), (
            f"SealedArchive field {name!r} is callable; the archive must be "
            f"data, not a handle on something that can run")


@pytest.mark.parametrize("forbidden", ["observe", "run", "execute", "replay",
                                       "environment", "scenario", "oracle"])
def test_the_sealed_archive_has_no_execution_method(forbidden):
    archive = _archive()
    assert not hasattr(archive, forbidden), (
        f"SealedArchive exposes {forbidden!r}; LB-2's non-replayability must be "
        f"structural, not a convention")


def test_the_archive_declares_itself_non_replayable():
    manifest = _archive().manifest()
    assert manifest["replayable"] is False
    assert "no execution surface" in manifest["note"]


def test_the_analysis_never_receives_a_scenario():
    """The scenario builds the archive and is then dropped.

    Checked on the source rather than at runtime: a runtime check would pass on
    a version that merely happened not to use the reference it was holding.
    """
    from living_boundary import run_lb2

    # The guard is about this exact private function, so reading it by name is
    # the point rather than an accident.
    source = inspect.getsource(run_lb2._analyse_scenario)  # pylint: disable=protected-access
    analysis_calls = ("stratify(", "analyse_cohorts(", "assess(",
                      "check_consistency(", "shadow_consistency(",
                      "candidate_exposures(")
    for line in source.splitlines():
        stripped = line.strip()
        if any(call in stripped for call in analysis_calls):
            assert "scenario" not in stripped, (
                f"an analysis call receives the scenario: {stripped!r}")


def test_a_run_records_that_no_replay_happened():
    from living_boundary.run_lb2 import run

    result = run(seed=5, persist=False)
    assert result["replay_used"] is False
    for record in result["scenarios"].values():
        recovery = record.get("simulated_recovery")
        if recovery:
            assert recovery["executed_anything"] is False
        for shadow in record["shadow"].values():
            assert shadow["executed_anything"] is False


# ── 3. every authority invariant, still ──

def test_lb2_cannot_mutate_the_feature_grammar():
    from living_boundary.discovery import features
    from living_boundary.run_lb2 import run

    before = tuple(features.FEATURE_FAMILIES)
    result = run(seed=5, persist=False)
    assert tuple(features.FEATURE_FAMILIES) == before
    assert result["grammar_immutability"]["unchanged"] is True


def test_lb2_cannot_change_production_governance():
    from living_boundary import authority
    from living_boundary.run_lb2 import run

    before = authority.production_fingerprint()
    result = run(seed=5, persist=False)
    after = authority.production_fingerprint()
    assert not authority.compare_fingerprints(before, after)
    assert result["authority"]["production_authority_reachable"] is False
    assert result["production_fingerprint"]["unchanged"] is True


def test_lb2_cannot_adopt_a_representation_extension():
    from living_boundary.representation.proposal import (
        ProposalAuthorityError, ProposalStatus, RepresentationProposal,
    )

    proposal = RepresentationProposal(proposal_id="RP-LB2-TEST",
                                      representation="r",
                                      verdict="INADEQUATE_LOCALISED")
    proposal.advance(ProposalStatus.REVIEW_REQUIRED)
    for forbidden in (ProposalStatus.ADOPTED, ProposalStatus.ENFORCED):
        with pytest.raises(ProposalAuthorityError):
            proposal.advance(forbidden)


def test_lb2_proposals_are_artifacts_only():
    from living_boundary.run_lb2 import run

    result = run(seed=5, persist=False)
    proposals = [r["proposal"] for r in result["scenarios"].values()
                 if r["proposal"]]
    assert proposals
    for proposal in proposals:
        assert proposal["status"] == "REVIEW_REQUIRED"
        assert proposal["production_authority"] == "none"
        assert proposal["grammar_mutation_authority"] == "none"


def test_lb2_modules_pass_the_static_authority_scan():
    from living_boundary import authority

    violations = authority.scan_static_authority()
    assert not violations, "\n".join(violations)


def test_a_crashing_lb2_leaves_kernel_decisions_unchanged(monkeypatch):
    """Blueprint invariant 8, re-checked for this phase."""
    from living_boundary import run_lb2
    from living_boundary.tests.test_no_production_authority import _decisions

    before, ruleset_before = _decisions()
    monkeypatch.setattr(
        run_lb2, "build_archives",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("LB-2 exploded")))
    with pytest.raises(RuntimeError):
        run_lb2.run(seed=5, persist=False)
    after, ruleset_after = _decisions()

    assert after == before
    assert ruleset_after == ruleset_before
    assert all(entry["verdict"] in ("BLOCK", "ESCALATE") for entry in after)
