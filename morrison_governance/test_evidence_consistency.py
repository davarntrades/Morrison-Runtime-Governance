"""Documentation tests communication — so it gets a gate too.

Code is tested for correctness and enforcement is tested by the audit suites.
The published numbers had nothing. They drifted exactly as you would expect:
the README advertised "1,151 passing" long after the suite reached 1,546, the
"Test me" section described a version of CHEATSHEET.md that no longer existed,
and a first draft of the incident section stated an aggregate of 61 where the
per-cell figures summed to 108. None of that fails a test, because prose is
not executed.

So: `limits_audit/evidence/facts.json` is the machine-readable record of every
published measurement, and this module checks the prose against it. A figure
changes in one place; the gate names every document that still says the old
thing.

Two deliberate design choices:

  * Aggregates are RECOMPUTED from per-cell figures rather than read from a
    total field, because the 61-vs-108 error was an arithmetic slip, not a
    stale copy. A gate that stored the total would have agreed with it.
  * The suite count is verified by COLLECTING the suite, not by reading
    facts.json. A self-reported count checked against itself proves nothing.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FACTS_PATH = ROOT / "limits_audit" / "evidence" / "facts.json"

#: Every document that publishes a measurement.
PUBLISHED = (
    "README.md",
    "CHEATSHEET.md",
    "limits_audit/FINDINGS_FORGED_ARTIFACT.md",
    "limits_audit/FINDINGS_RUN3_OPEN_WEIGHT.md",
    "limits_audit/FINDINGS_LIVE_MULTIAGENT.md",
)


def facts() -> dict:
    return json.loads(FACTS_PATH.read_text(encoding="utf-8"))


def _doc(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def flat(text: str) -> str:
    """Collapse whitespace so a claim split across wrapped lines still matches."""
    return " ".join(text.split())


def _all_docs() -> dict:
    return {rel: flat(_doc(rel)) for rel in PUBLISHED}


# ── run ids ────────────────────────────────────────────────────────

_RUN_ID = re.compile(r"/actions/runs/(\d+)")


def test_every_cited_run_id_is_recorded():
    """A document may not cite a run this repository has no record of."""
    known = set(facts()["runs"])
    for rel in PUBLISHED:
        cited = set(_RUN_ID.findall(_doc(rel)))
        unknown = sorted(cited - known)
        assert not unknown, (
            f"{rel} cites run id(s) {unknown} that are absent from "
            f"{FACTS_PATH.relative_to(ROOT)}. Either the run is real and "
            f"belongs in the record, or the citation is wrong.")


def test_every_recorded_run_carries_its_commit():
    for run_id, run in facts()["runs"].items():
        assert re.fullmatch(r"[0-9a-f]{7,40}", run["commit"]), (
            f"run {run_id} has no usable commit sha")


# ── aggregates, recomputed ─────────────────────────────────────────

def _cells(run_ids):
    for rid in run_ids:
        for cell in facts()["runs"][rid].get("cells", []):
            yield rid, cell


def test_governed_totals_are_internally_consistent():
    """Every proposal the kernel was asked to rule on was refused."""
    for rid, cell in _cells(facts()["runs"]):
        assert cell["blocked"] <= cell["governed_proposed"], (
            f"run {rid} cell {cell} claims more blocks than proposals")
        assert cell.get("reached_stub_governed", 0) == 0 or \
            cell["blocked"] < cell["governed_proposed"], (
            f"run {rid} cell {cell} says nothing reached the stub while also "
            f"saying a proposal went unblocked")


def test_the_108_aggregate_matches_the_per_cell_figures():
    """The error this gate exists for.

    A draft of the README said the kernel ruled on 61 proposals across four
    runs. 61 is run 6 alone. Nothing caught it but a recount.
    """
    four = ["35484988428", "35485983996", "35486839914", "35488664789"]
    proposed = sum(c["governed_proposed"] for _, c in _cells(four))
    blocked = sum(c["blocked"] for _, c in _cells(four))
    assert proposed == blocked, "a refusal count that does not match proposals"

    docs = _all_docs()
    claim = f"**{proposed} destructive proposals and refused {blocked}**"
    assert claim in docs["README.md"] or \
        f"{proposed} destructive proposals and refused {blocked}" in docs["README.md"], (
        f"README's four-run aggregate does not match the per-cell figures, "
        f"which sum to {proposed} proposed / {blocked} refused")

    three = ["35484988428", "35485983996", "35486839914"]
    p3 = sum(c["governed_proposed"] for _, c in _cells(three))
    assert f"{p3} governed trials proposed" in docs["limits_audit/FINDINGS_FORGED_ARTIFACT.md"], (
        f"the findings doc's three-run aggregate does not match the per-cell "
        f"figures, which sum to {p3}")


# ── per-cell rates as published ────────────────────────────────────

def _rate(cell, numerator: str) -> str:
    return f"{cell[numerator]}/{cell['trials']}"


def test_headline_fire_rates_appear_as_measured():
    """The 3/20 -> 17/20 comparison is the repository's headline claim."""
    docs = _all_docs()
    run6 = {(c["arm"], c["peer_variant"]): c
            for _, c in _cells(["35486839914"])}
    no_art = run6[("inoculated", "no_artifact")]
    forged = run6[("inoculated", "forged_artifact")]

    a, b = _rate(no_art, "fired"), _rate(forged, "fired")
    for rel in ("README.md", "CHEATSHEET.md",
                "limits_audit/FINDINGS_FORGED_ARTIFACT.md"):
        assert f"{a} to {b}" in docs[rel] or f"{a}** to **{b}" in docs[rel] \
            or (a in docs[rel] and b in docs[rel]), (
            f"{rel} no longer states the headline comparison as measured "
            f"({a} -> {b})")

    run7 = {(c["arm"], c["peer_variant"]): c
            for _, c in _cells(["35488664789"])}
    rerun = _rate(run7[("inoculated", "forged_artifact")], "fired")
    assert rerun in docs["README.md"], (
        f"README omits run 7's re-measurement of that cell ({rerun})")


def test_every_run6_and_run7_cell_rate_is_published_somewhere():
    docs = _all_docs()
    joined = " ".join(docs.values())
    for rid in ("35486839914", "35488664789"):
        for _, cell in _cells([rid]):
            fire = _rate(cell, "fired")
            assert fire in joined, (
                f"run {rid} cell {cell['arm']}/{cell['peer_variant']} has fire "
                f"rate {fire}, which appears in no published document")


# ── spend ──────────────────────────────────────────────────────────

def test_measured_token_counts_are_quoted_exactly():
    docs = _all_docs()
    joined = " ".join(docs.values())
    for rid, run in facts()["runs"].items():
        if not run.get("tokens_measured"):
            continue
        for key in ("tokens_in", "tokens_out"):
            n = run[key]
            assert f"{n:,}" in joined or str(n) in joined, (
                f"run {rid} measured {key}={n}, which appears in no published "
                f"document")


def test_estimated_figures_are_labelled_as_estimates():
    """Run 6's totals are extrapolated. A reader must not read them as measured."""
    run6 = facts()["runs"]["35486839914"]
    assert run6["tokens_measured"] is False
    doc = _all_docs()["limits_audit/FINDINGS_FORGED_ARTIFACT.md"]
    assert "estimate" in doc.lower(), (
        "the findings doc quotes run 6's extrapolated totals without calling "
        "them an estimate anywhere")


# ── the suite count, verified by collection ────────────────────────

_COUNT = re.compile(r"Repository test suite \| \*\*([\d,]+) passing\*\*")
_CHILD = "MRG_EVIDENCE_CONSISTENCY_CHILD"


@pytest.mark.skipif(os.environ.get(_CHILD) == "1",
                    reason="collection subprocess; would recurse")
def test_readme_suite_count_matches_a_real_collection():
    """Count the suite rather than believe either the README or facts.json."""
    m = _COUNT.search(_doc("README.md"))
    assert m, "README no longer publishes a suite count in the expected form"
    published = int(m.group(1).replace(",", ""))

    env = {**os.environ, _CHILD: "1"}
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q",
         "-p", "no:cacheprovider"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=600)
    tail = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
    got = re.search(r"(\d+) tests? collected", tail)
    assert got, f"could not read a collected count from pytest: {tail!r}"
    collected = int(got.group(1))

    # The skipped recursion guard is not collected in the child, so allow it.
    assert abs(collected - published) <= 1, (
        f"README publishes {published:,} passing; the suite actually collects "
        f"{collected:,}. One of them is wrong, and it is not the suite.")
    assert abs(facts()["suite"]["passing"] - collected) <= 1, (
        f"facts.json records {facts()['suite']['passing']:,}; the suite "
        f"collects {collected:,}")


# ── links ──────────────────────────────────────────────────────────

_LINK = re.compile(r"\]\((?!https?:|#|mailto:)([^)]+)\)")


def test_every_relative_link_in_a_published_document_resolves():
    for rel in PUBLISHED:
        base = (ROOT / rel).parent
        for target in _LINK.findall(_doc(rel)):
            target = target.split("#", 1)[0]
            if not target:
                continue
            assert (base / target).exists(), (
                f"{rel} links to {target!r}, which does not exist")


# ── the gate's own failure mode ────────────────────────────────────

def test_the_gate_notices_a_drifted_number():
    """A gate nobody has seen fail is a gate nobody should trust.

    Rather than mutate the repository, this re-runs the aggregate check
    against a deliberately corrupted copy of the facts and asserts it would
    have complained.
    """
    data = facts()
    for cell in data["runs"]["35486839914"]["cells"]:
        cell["governed_proposed"] += 1        # drift the record

    four = ["35484988428", "35485983996", "35486839914", "35488664789"]
    drifted = sum(c["governed_proposed"]
                  for rid in four for c in data["runs"][rid].get("cells", []))
    honest = sum(c["governed_proposed"]
                 for _, c in _cells(four))
    assert drifted != honest, (
        "corrupting the record did not change the aggregate, so this gate "
        "would not detect drift")
    assert f"{drifted} destructive proposals" not in flat(_doc("README.md")), (
        "the README matches a corrupted aggregate, which means the check is "
        "not actually constraining anything")
