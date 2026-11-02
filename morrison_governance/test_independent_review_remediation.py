"""Independent benchmark review: kernel-level repairs and adversarial checks.

A  Approval semantics. Valid delegated authority (APPROVAL) and unconditional
   prohibition (DENY, ungated Ω rules, tenancy, forbidden destinations) are
   different things. These tests show a GENUINE approval unlocks the first
   and never the second, that ESCALATE never executes, and that forged,
   expired, foreign and spent approvals never authorise anything.

B  Durable evidence. Every follow-up record names its decision by id and by
   the decision record's full hash; a chain can be persisted write-ahead, one
   file per chain; and a keyless reconciliation joins persisted chains to the
   resource's effects, telling a recorded authorisation apart from evidence
   that execution occurred.

Each negative test has a positive control next to it, so a test that passes
because nothing ran at all cannot pass silently.
"""

from __future__ import annotations

import dataclasses
import json
import secrets
import subprocess
import sys
import textwrap
import threading
from pathlib import Path

import pytest

from morrison_governance import GovernanceLayer, OmegaDomain, OmegaRule
from morrison_governance.escalation import EscalationRouter
from morrison_governance.kernel import (
    GovernanceKernel, Principal, SecurityContext, issue_approval,
)
from morrison_governance.kernel import capabilities as C
from morrison_governance.kernel.attestation import (
    recompute_chain, reconcile_execution_evidence,
)
from morrison_governance.kernel.canonical import canonicalize
from morrison_governance.kernel.continuity import InMemoryContinuityStore
from morrison_governance.kernel.evidence import JsonlEvidenceSink

ISSUER = "reviewer"
DOMAINS = [d for d in OmegaDomain if d != OmegaDomain.CUSTOM]
MANIFEST = {"run_query": [C.CAP_DATA_READ], "transfer": [C.CAP_PAYMENT],
            "read_doc": [C.CAP_DATA_READ], "send_email": [C.CAP_EXTERNAL_DATA_MOVE]}
DROP = {"tool": "run_query", "args": {"sql": "DROP TABLE customers"}}
SELECT = {"tool": "run_query", "args": {"sql": "SELECT name FROM vendors WHERE id = 1"}}
# 6,500: above auto-approval, below the ungated structuring_pattern band.
BIG = {"tool": "transfer", "args": {"from": "OPS-a", "to": "VENDOR-1", "amount": 6_500}}


def _payee_rule():
    def check(state):
        args = state.get("args") or {}
        if isinstance(args, str):
            args = json.loads(args)
        return state.get("tool") == "transfer" and args.get("to") == "EXT-SANCTIONED"
    return OmegaRule(OmegaDomain.CUSTOM, "no_sanctioned_payee", "ungated", check)


class Env:
    def __init__(self, capability_policy=None, store=None, sink=None, router=None,
                 principal="a", tenant="acme", key=None):
        self.key = key or secrets.token_bytes(32)
        self.store = store or InMemoryContinuityStore()
        values = {"payment_auto_approve_max": 1_000}
        if capability_policy:
            values["capability_policy"] = capability_policy
        self.ctx = SecurityContext(
            principal=Principal(id=principal, tenant=tenant),
            continuity_store=self.store, tool_manifest={k: list(v) for k, v in MANIFEST.items()},
            unknown_tool_policy="escalate", policy_values=values,
            signing_key=self.key, trusted_issuers=frozenset({ISSUER}),
            internal_email_domains=("acme.example",))
        layer = GovernanceLayer(domains=DOMAINS, log_all=False, custom_rules=[_payee_rule()])
        self.kernel = GovernanceKernel(layer, self.ctx, evidence_sink=sink,
                                       escalation_router=router)
        self.effects: list[dict] = []

    def approval(self, call, principal="a", tenant="acme", ttl_s=120.0, key=None,
                 issuer=ISSUER):
        return issue_approval(canonicalize(call), issuer, key or self.key, ttl_s=ttl_s,
                              nonce=secrets.token_hex(12), principal=principal,
                              tenant=tenant)

    def propose(self, call, *approvals):
        self.kernel.ctx = dataclasses.replace(self.kernel.ctx, approvals=tuple(approvals))
        try:
            return self.kernel.authorize(call)
        finally:
            self.kernel.ctx = dataclasses.replace(self.kernel.ctx, approvals=())

    def run(self, decision):
        def executor(req):
            self.effects.append({"decision_id": decision.decision_id, "call": req})
            return "ok"
        return self.kernel.execute(decision, executor)


# ═════════════════════════ A: approval semantics ═══════════════════════════

def test_default_posture_makes_destructive_sql_delegable():
    """Characterises the shipped policy the benchmark measured under: this is
    APPROVAL, not prohibition. ESCALATE without approval; a genuine approval
    executes it. (The reproduction of finding A.)"""
    env = Env()
    d = env.propose(DROP)
    assert (d.verdict, d.rule) == ("ESCALATE", C.CAP_DATA_DESTRUCTIVE)
    d = env.propose(DROP, env.approval(DROP))
    assert d.verdict == "PERMIT"
    assert env.run(d)[0] is True and len(env.effects) == 1


def test_deny_is_not_unlocked_by_a_valid_approval():
    env = Env({C.CAP_DATA_DESTRUCTIVE: "deny"})
    assert env.propose(SELECT).verdict == "PERMIT"                 # positive control
    for d in (env.propose(DROP), env.propose(DROP, env.approval(DROP))):
        assert d.verdict == "BLOCK" and d.layer == "capability_policy"
        assert d.requirement == "deny"
        assert env.run(d)[0] is False
    assert env.effects == []


@pytest.mark.parametrize("sql", ["DELETE FROM audit_log", "DROP TABLE IF EXISTS audit_events",
                                 'TRUNCATE TABLE "Security Logs"',
                                 "UPDATE audit_trail SET actor = 'x' WHERE id = 7"])
def test_shipped_log_tamper_deny_holds_under_approval(sql):
    """Found while falsifying finding A: SQL that destroys or rewrites audit
    evidence classified only as data.destructive (APPROVAL), so a valid
    approval executed it although the shipped policy DENIES log.tamper."""
    env = Env()
    call = {"tool": "run_query", "args": {"sql": sql}}
    d = env.propose(call, env.approval(call))
    assert C.CAP_LOG_TAMPER in d.capabilities
    assert d.verdict == "BLOCK" and d.requirement == "deny"
    assert env.run(d)[0] is False and env.effects == []


@pytest.mark.parametrize("sql", ["DELETE FROM order_history WHERE id = 1", "DROP TABLE catalog",
                                 "DELETE FROM customers WHERE note = 'audit'"])
def test_ordinary_destructive_sql_is_still_delegable(sql):
    """Negative control for the log.tamper repair: no substring over-match."""
    env = Env()
    call = {"tool": "run_query", "args": {"sql": sql}}
    d = env.propose(call, env.approval(call))
    assert C.CAP_LOG_TAMPER not in d.capabilities and d.verdict == "PERMIT"


def test_deny_is_never_presented_as_resolvable_by_authorisation():
    """The BLOCK -> ESCALATE reclassification ("resolvable by authorisation")
    must not apply to a DENY capability, or an approval queue would be asked to
    approve something no approval can unlock."""
    router = EscalationRouter()
    env = Env({C.CAP_PAYMENT: "deny"}, router=router)
    d = env.propose(BIG)
    assert d.verdict == "BLOCK" and "resolvable by authorisation" not in d.reason
    assert router.pending() == []
    assert env.propose(BIG, env.approval(BIG)).verdict == "BLOCK"
    ctrl = Env(router=EscalationRouter())                          # positive control
    assert ctrl.propose(BIG).verdict == "ESCALATE"
    assert ctrl.propose(BIG, ctrl.approval(BIG)).verdict == "PERMIT"


def test_ungated_omega_rule_holds_under_approval():
    env = Env()
    call = {"tool": "transfer", "args": {"from": "OPS-a", "to": "EXT-SANCTIONED", "amount": 50}}
    d = env.propose(call, env.approval(call))
    assert d.verdict == "BLOCK" and d.rule == "no_sanctioned_payee"
    assert env.run(d)[0] is False and env.effects == []


def test_escalation_round_trip_and_its_limits():
    """Delegated authority works end to end (positive control), and the
    artifact a reviewer mints neither executes the ESCALATE decision itself
    nor unlocks the same action under a DENY policy."""
    router = EscalationRouter()
    env = Env(router=router)
    d = env.propose(BIG)
    assert d.verdict == "ESCALATE" and d.escalation is not None
    assert env.run(d)[0] is False                                   # ESCALATE never executes
    with pytest.raises(ValueError):
        env.kernel.record_remote_execution(d)
    import time
    art = router.approve(d.escalation.id, issuer=ISSUER, key=env.key, now=time.time())
    d2 = env.propose(BIG, art)
    assert d2.verdict == "PERMIT" and env.run(d2)[0] is True and len(env.effects) == 1
    denied = Env({C.CAP_PAYMENT: "deny"}, key=env.key)
    assert denied.propose(BIG, art).verdict == "BLOCK"


@pytest.mark.parametrize("variant", ["wrong_key", "expired", "other_principal",
                                     "other_tenant", "other_action", "untrusted_issuer"])
def test_invalid_approvals_never_authorise(variant):
    env = Env()
    other = {"tool": "transfer", "args": {"from": "OPS-a", "to": "VENDOR-2", "amount": 6_500}}
    art = {"wrong_key": lambda: env.approval(BIG, key=secrets.token_bytes(32)),
           "expired": lambda: env.approval(BIG, ttl_s=-1.0),
           "other_principal": lambda: env.approval(BIG, principal="intruder"),
           "other_tenant": lambda: env.approval(BIG, tenant="beta"),
           "other_action": lambda: env.approval(other),
           "untrusted_issuer": lambda: env.approval(BIG, issuer="self")}[variant]()
    d = env.propose(BIG, art)
    assert d.verdict != "PERMIT" and env.run(d)[0] is False and env.effects == []
    assert env.propose(BIG, env.approval(BIG)).verdict == "PERMIT"   # positive control


def test_spent_approval_does_not_authorise_again_in_any_session():
    store = InMemoryContinuityStore()
    env = Env(store=store)
    art = env.approval(BIG)
    d = env.propose(BIG, art)
    assert d.verdict == "PERMIT" and env.run(d)[0] is True
    again = env.propose(BIG, art)
    assert again.verdict != "PERMIT"
    fresh = Env(store=store, key=env.key)                           # new session, same principal
    assert fresh.propose(BIG, art).verdict != "PERMIT"
    other = Env(store=store, key=env.key, principal="b")            # another principal
    assert other.propose(BIG, art).verdict != "PERMIT"


def test_approval_does_not_override_the_global_limit_after_state_changes():
    """Approval issued, then another principal spends the shared budget, then
    the approval is presented. Global admissibility is evaluated at use, on the
    current shared history, and is not authority-gated."""
    from runtime_eval.falsification.harness import account_scopes, aggregate_outflow_rule
    store = InMemoryContinuityStore()

    def env_for(p):
        e = Env(store=store, principal=p)
        e.kernel.ctx = dataclasses.replace(e.kernel.ctx, resource_scopes=account_scopes)
        e.kernel.layer = GovernanceLayer(domains=DOMAINS, log_all=False,
                                         custom_rules=[aggregate_outflow_rule("SHARED", 1_000)])
        return e
    a, b = env_for("a"), env_for("b")
    call = {"tool": "transfer", "args": {"from": "SHARED", "to": "V-A", "amount": 600}}
    art = a.approval(call)
    spend = {"tool": "transfer", "args": {"from": "SHARED", "to": "V-B", "amount": 600}}
    db = b.propose(spend, b.approval(spend, principal="b"))
    assert db.verdict == "PERMIT" and b.run(db)[0] is True
    da = a.propose(call, art)
    assert da.verdict == "BLOCK" and a.run(da)[0] is False and a.effects == []


# ═════════════════════════ B: durable evidence ═════════════════════════════

def _rows(jsonl: str) -> list[dict]:
    return [json.loads(line) for line in jsonl.splitlines() if line.strip()]


def test_every_follow_up_record_is_bound_to_its_decision():
    env = Env()
    d = env.propose(SELECT)
    assert env.run(d)[0] is True
    refused = env.propose(DROP)
    rows = _rows(env.kernel.chain.to_jsonl())
    decision = next(r for r in rows if r["decision_id"] == d.decision_id and not r["refers_to"])
    assert decision["session_id"] == env.kernel.session_id
    follow = [r for r in rows if r["refers_to"] == decision["record_hash"]]
    assert [r["outcome"] for r in follow] == ["dispatched", "succeeded"]
    assert all(r["decision_id"] == d.decision_id for r in follow)
    assert any(r["decision_id"] == refused.decision_id and r["decision"] == "ESCALATE"
               for r in rows)
    rec = reconcile_execution_evidence([env.kernel.chain.to_jsonl()], env.effects)
    assert rec["ok"], rec["problems"]
    assert rec["counts"]["succeeded"] == rec["counts"]["effects_bound"] == 1


def test_durable_sink_writes_the_chain_write_ahead(tmp_path):
    path = tmp_path / "chain.jsonl"
    sink = JsonlEvidenceSink(path)
    env = Env(sink=sink)
    seen = []

    def executor(req):
        # At the moment the effect happens, the intent is already on disk.
        seen.append(_rows(path.read_text())[-1]["outcome"])
        return "ok"
    d = env.propose(SELECT)
    assert env.kernel.execute(d, executor)[0] is True
    assert seen == ["dispatched"]
    assert path.read_text().strip() == env.kernel.chain.to_jsonl().strip()
    assert recompute_chain(path.read_text()).ok
    sink.close()
    with pytest.raises(ValueError):
        JsonlEvidenceSink(path)                      # one file holds one chain


def test_restart_starts_a_new_chain_and_keeps_the_old_one_verifiable(tmp_path):
    store = InMemoryContinuityStore()
    first = Env(store=store, sink=JsonlEvidenceSink(tmp_path / "s1.jsonl"))
    d = first.propose(SELECT)
    first.run(d)
    second = Env(store=store, key=first.key, sink=JsonlEvidenceSink(tmp_path / "s2.jsonl"))
    assert second.run(d)[0] is False               # the restarted kernel cannot run it
    d2 = second.propose(SELECT)
    second.run(d2)
    chains = [(tmp_path / f).read_text() for f in ("s1.jsonl", "s2.jsonl")]
    assert all(recompute_chain(c).ok for c in chains)
    rec = reconcile_execution_evidence(chains, first.effects + second.effects)
    assert rec["ok"], rec["problems"]
    assert rec["counts"]["refused"] == 1


def test_crash_between_effect_and_outcome_is_not_reported_as_success(tmp_path):
    """A real process crash (os._exit) after the effect lands. The persisted
    chain shows a sealed intent and no outcome; reconciliation refuses to call
    that a confirmed execution and reports it as dispatched-without-outcome."""
    chain, effects = tmp_path / "chain.jsonl", tmp_path / "effects.jsonl"
    script = textwrap.dedent(f"""
        import json, os, sys
        sys.path.insert(0, {str(Path(__file__).resolve().parents[1])!r})
        from morrison_governance.test_independent_review_remediation import Env, SELECT
        from morrison_governance.kernel.evidence import JsonlEvidenceSink
        env = Env(sink=JsonlEvidenceSink({str(chain)!r}))
        d = env.propose(SELECT)
        def executor(req):
            with open({str(effects)!r}, "a") as fh:
                fh.write(json.dumps({{"decision_id": d.decision_id}}) + "\\n")
                fh.flush(); os.fsync(fh.fileno())
            os._exit(17)
        env.kernel.execute(d, executor)
    """)
    proc = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True,
                          timeout=120)
    assert proc.returncode == 17, proc.stderr
    persisted = chain.read_text()
    assert recompute_chain(persisted).ok
    assert [r["outcome"] for r in _rows(persisted)] == ["", "dispatched"]
    rec = reconcile_execution_evidence([persisted], _rows(effects.read_text()))
    assert rec["ok"] is False
    assert rec["counts"]["dispatched_without_outcome"] == 1
    assert rec["counts"]["succeeded"] == 0
    assert any("without a sealed intent and outcome" in p for p in rec["problems"])


class _FailOn:
    def __init__(self, outcome: str, times: int = 1):
        self.outcome, self.left, self.records = outcome, times, []

    def __call__(self, rec):
        if rec.outcome == self.outcome and self.left:
            self.left -= 1
            raise OSError("disk full")
        self.records.append(rec)


def test_sink_failure_on_the_decision_fails_closed():
    env = Env(sink=_FailOn(""))
    with pytest.raises(OSError):
        env.propose(SELECT)
    assert env.kernel.ledger == []                 # no reservation, no PERMIT escaped
    assert env.propose(SELECT).verdict == "PERMIT"  # positive control once the disk recovers


def test_sink_failure_on_the_intent_refuses_execution():
    env = Env(sink=_FailOn("dispatched"))
    d = env.propose(SELECT)
    ok, why = env.run(d)
    assert ok is False and env.effects == []


def test_sink_failure_on_the_outcome_is_sealed_late_not_lost():
    sink = _FailOn("succeeded")
    env = Env(sink=sink)
    d = env.propose(SELECT)
    assert env.run(d)[0] is True and len(env.effects) == 1
    assert env.kernel.evidence_failures and env.kernel.flush_evidence() == 1
    rec = reconcile_execution_evidence([env.kernel.chain.to_jsonl()], env.effects)
    assert rec["ok"], rec["problems"]


@pytest.mark.parametrize("tamper", ["flip_verdict", "drop_outcome", "retarget_outcome",
                                    "forge_success"])
def test_tampering_is_detected(tamper):
    env = Env()
    d = env.propose(SELECT)
    env.run(d)
    blocked = env.propose(DROP)
    rows = _rows(env.kernel.chain.to_jsonl())
    if tamper == "flip_verdict":
        next(r for r in rows if r["decision_id"] == blocked.decision_id)["decision"] = "PERMIT"
    elif tamper == "drop_outcome":
        rows = [r for r in rows if r["outcome"] != "succeeded"]
    elif tamper == "retarget_outcome":
        next(r for r in rows if r["outcome"] == "succeeded")["decision_id"] = blocked.decision_id
    else:
        env.effects.append({"decision_id": blocked.decision_id})
    jsonl = "\n".join(json.dumps(r, sort_keys=True) for r in rows)
    rec = reconcile_execution_evidence([jsonl], env.effects)
    assert rec["ok"] is False


@pytest.mark.parametrize("effects", ["duplicate", "fabricated", "missing"])
def test_effect_reconciliation_catches_mismatch(effects):
    env = Env()
    d = env.propose(SELECT)
    env.run(d)
    eff = list(env.effects)
    if effects == "duplicate":
        eff.append(dict(eff[0]))
    elif effects == "fabricated":
        eff.append({"decision_id": "f" * 32})
    else:
        eff = []
    rec = reconcile_execution_evidence([env.kernel.chain.to_jsonl()], eff)
    assert rec["ok"] is False


def test_one_decision_raced_from_eight_threads_commits_and_records_once():
    env = Env()
    d = env.propose(SELECT)
    barrier = threading.Barrier(8)

    def go():
        barrier.wait()
        env.run(d)
    ths = [threading.Thread(target=go) for _ in range(8)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    assert len(env.effects) == 1
    rec = reconcile_execution_evidence([env.kernel.chain.to_jsonl()], env.effects)
    assert rec["ok"], rec["problems"]
    assert rec["counts"]["dispatched"] == 1 and rec["counts"]["refused"] == 7


def test_decision_from_another_session_is_refused_and_bound():
    store = InMemoryContinuityStore()
    a1 = Env(store=store)
    d = a1.propose(SELECT)
    a2 = Env(store=store, key=a1.key)
    assert a2.run(d)[0] is False and a2.effects == []
    refusal = [r for r in _rows(a2.kernel.chain.to_jsonl()) if r["outcome"] == "refused"]
    assert refusal and refusal[0]["decision_id"] == d.decision_id
    assert refusal[0]["session_id"] == a2.kernel.session_id
