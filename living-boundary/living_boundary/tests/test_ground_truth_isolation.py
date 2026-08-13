"""The hidden rule must be unreachable from the discovery layer.

If this file's assertions fail, every other result in LB-0 is void: the
experiment would be measuring retrieval rather than discovery, and no amount of
held-out performance would mean anything.

Three independent checks:

  1. IMPORT REACHABILITY (transitive). No module under `discovery/`,
     `observer/` or `ontology/` can reach `experiments.hidden_ground_truth`
     through any chain of first-party imports.

  2. DATA CONTENT. The public trace corpus contains no token that names the
     rule, the oracle, or the structural family a trajectory was drawn from.

  3. SCHEMA CLOSURE. Every public event carries only keys from the closed
     schema, so a future generator cannot add a field without this failing.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from living_boundary._repo_paths import PACKAGE_ROOT
from living_boundary.observer.normalizer import ALLOWED_EVENT_KEYS
from living_boundary.experiments.scenario_generator import FAMILIES

ORACLE_MODULE = "living_boundary.experiments.hidden_ground_truth"

# The layers that must never be able to consult the oracle. `experiments/` and
# `evaluation/` are harness and scoring; they are supposed to reach it.
ISOLATED_PACKAGES = ("discovery", "observer", "ontology")

# Words that would describe the RULE or the harness rather than an observable.
# Chosen carefully: `reverify_identity` is a legitimate action name and
# `unsafe` is a legitimate observed outcome, so neither appears here.
FORBIDDEN_TOKENS = (
    "hidden_rule", "hidden_composition", "ground_truth", "oracle",
    "lb0-oracle", "known_bad", "witness", "near_miss", "family",
    "accumulation", "authority_refresh", "composition_direct",
)


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


def _import_graph():
    graph = {}
    for path in sorted(Path(PACKAGE_ROOT).rglob("*.py")):
        relative = path.relative_to(PACKAGE_ROOT).as_posix()
        if relative.startswith("tests/") or "__pycache__" in relative:
            continue
        graph[_module_name(path)] = _first_party_imports(path)
    return graph


def _reachable(graph, start):
    """Modules reachable from `start`, resolving `pkg.name` to `pkg` when the
    former is an attribute import rather than a module."""
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


def test_discovery_layers_cannot_reach_the_oracle():
    graph = _import_graph()
    offenders = []
    for module in sorted(graph):
        suffix = module[len("living_boundary."):]
        if not suffix.startswith(ISOLATED_PACKAGES):
            continue
        if ORACLE_MODULE in _reachable(graph, module):
            offenders.append(module)
    assert not offenders, (
        "these discovery-layer modules can reach the ground-truth oracle "
        "transitively: {}. The experiment would be testing retrieval, not "
        "discovery.".format(offenders))


def test_the_oracle_is_reachable_from_the_harness_and_evaluator():
    """The mirror image — an isolation that isolated everything would be a bug.

    If the oracle became unreachable from the evaluator, scores would silently
    fall back to the trace label, and falsification cases (which carry no label)
    could not be scored at all.
    """
    graph = _import_graph()
    for module in ("living_boundary.evaluation.evaluator",
                   "living_boundary.experiments.runner",
                   "living_boundary.experiments.scenario_generator"):
        assert ORACLE_MODULE in _reachable(graph, module), module


def test_public_events_carry_only_schema_keys(dataset):
    for split in dataset.splits.values():
        for event in split.events:
            extra = set(event) - ALLOWED_EVENT_KEYS
            assert not extra, f"event carries out-of-schema keys: {extra}"


def test_public_corpus_contains_no_rule_describing_token(dataset):
    blob = json.dumps(
        {name: split.events for name, split in dataset.splits.items()},
        sort_keys=True).lower()
    leaked = [token for token in FORBIDDEN_TOKENS if token in blob]
    assert not leaked, f"rule-describing tokens leaked into the corpus: {leaked}"


def test_public_corpus_contains_no_structural_family_name(dataset):
    """The family a trajectory was drawn from is harness-private.

    A family name next to a trace id would be a structural label, and the
    discovery layer would be reading the answer off the data.
    """
    blob = json.dumps(
        {name: split.events for name, split in dataset.splits.items()},
        sort_keys=True).lower()
    leaked = [name for name, _, _ in FAMILIES if name in blob]
    assert not leaked, f"family names leaked into the corpus: {leaked}"


def test_family_manifest_is_not_part_of_the_public_dataset(dataset):
    """Families are recorded, but only in aggregate, and only harness-side."""
    manifest = json.dumps(dataset.manifest(), sort_keys=True)
    for split in dataset.splits.values():
        for sequence_id in list(split.families)[:50]:
            assert sequence_id not in manifest, (
                "the dataset manifest maps a sequence id to its structural "
                "family; that pairing must stay harness-private")


@pytest.mark.parametrize("package", ISOLATED_PACKAGES)
def test_isolated_packages_do_not_read_artifacts(package):
    """A discovery module that read the artifacts tree could read the harness
    disclosure written into `report.md` by an earlier run."""
    for path in sorted((Path(PACKAGE_ROOT) / package).rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        assert "ARTIFACTS_ROOT" not in source, path
        assert "artifacts" not in source.lower().replace("artifacts_root", ""), path
