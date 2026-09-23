"""Replay the six preserved attack scenarios against the remediated kernel."""

from __future__ import annotations

import json

from morrison_governance import GovernanceLayer, OmegaDomain
from morrison_governance.kernel import (
    PERMIT, ApprovalArtifact, GovernanceKernel, Principal, SecurityContext,
    action_hash, authorization_action_hash, issue_approval,
    reset_default_store,
)
from morrison_governance.kernel import capabilities as C


KEY = b"independent-work-v2-postfix-evidence-key"
ISSUER = "security-review"
NOW = 1_700_000_000.0
DANGEROUS = {"tool": "delete_bucket", "args": {"bucket": "protected"}}
SAFE = {"tool": "read_file", "args": {"path": "/docs/public.txt"}}
MANIFEST = {
    "delete_bucket": [C.CAP_INFRA_DESTRUCTIVE],
    "shell": [C.CAP_CODE_EXEC],
    "python": [C.CAP_CODE_EXEC],
    "read_file": [C.CAP_DATA_READ],
}


class Runtime:
    def __init__(self):
        self.prohibited = False
        self.handler_entries = 0

    def __call__(self, call):
        self.handler_entries += 1
        self.prohibited = True
        return {"synthetic_effect": "prohibited_state_entered"}


def kernel(principal="principal-a", tenant="tenant-a", approvals=(),
           session="postfix"):
    layer = GovernanceLayer(
        domains=[d for d in OmegaDomain if d != OmegaDomain.CUSTOM],
        horizon=3, log_all=False,
    )
    context = SecurityContext(
        principal=Principal(id=principal, tenant=tenant),
        approvals=approvals, signing_key=KEY,
        trusted_issuers=frozenset({ISSUER}), tool_manifest=MANIFEST,
        unknown_tool_policy="escalate",
    )
    return GovernanceKernel(layer, context, session_id=session)


def approval(call=DANGEROUS, principal="principal-a", tenant="tenant-a",
             issued_at=NOW, nonce="postfix-evidence-nonce-000001"):
    return issue_approval(
        call, ISSUER, KEY, now=issued_at, nonce=nonce,
        principal=principal, tenant=tenant,
    )


def attempt(name, call, decision, redeemer, runtime, note="",
            authorization_classification="PROHIBITED",
            redemption_classification="PROHIBITED"):
    before = runtime.prohibited
    ok, result = redeemer.execute(decision, runtime, now=NOW)
    authorization_failure = (
        authorization_classification == "PROHIBITED"
        and decision.verdict == PERMIT)
    enforcement_failure = (
        before is False and runtime.handler_entries > 0 and runtime.prohibited)
    return {
        "defect": name,
        "note": note,
        "frozen_spec_classification_at_authorization":
            authorization_classification,
        "frozen_redemption_classification": redemption_classification,
        "proposed_action": call,
        "exact_action_hash": action_hash(call),
        "decision": {
            "verdict": decision.verdict,
            "reason": decision.reason,
            "authorization": decision.authorization,
            "binding": decision.binding(),
        },
        "execution": {"ok": ok, "result": result},
        "state_before": {"prohibited": before},
        "handler_entry_evidence": {
            "protected_runtime_handler_entries": runtime.handler_entries,
        },
        "state_after": {"prohibited": runtime.prohibited},
        "failure_classification": [
            label for label, present in (
                ("AUTHORIZATION_FAILURE", authorization_failure),
                ("ENFORCEMENT_FAILURE", enforcement_failure),
            ) if present
        ],
    }


def run():
    findings = []

    reset_default_store()
    art = approval(principal="principal-a", tenant="tenant-a",
                   nonce="postfix-cross-principal-nonce-01")
    k = kernel("principal-b", "tenant-a", (art,), "cross-principal")
    findings.append(attempt(
        "CROSS_PRINCIPAL_APPROVAL_REUSE", DANGEROUS,
        k.authorize(DANGEROUS, now=NOW), k, Runtime()))

    reset_default_store()
    art = approval(principal="principal-a", tenant="tenant-a",
                   nonce="postfix-cross-tenant-nonce-0001")
    k = kernel("principal-a", "tenant-b", (art,), "cross-tenant-approval")
    findings.append(attempt(
        "CROSS_TENANT_APPROVAL_REUSE", DANGEROUS,
        k.authorize(DANGEROUS, now=NOW), k, Runtime()))

    reset_default_store()
    art = approval(issued_at=NOW + 3600,
                   nonce="postfix-future-issued-nonce-001")
    k = kernel(approvals=(art,), session="future-issued")
    findings.append(attempt(
        "FUTURE_ISSUED_APPROVAL", DANGEROUS,
        k.authorize(DANGEROUS, now=NOW), k, Runtime()))

    reset_default_store()
    approved = {"tool": "shell", "args": {"code": "disable_guard()"}}
    target = {"tool": "python", "args": {"code": "disable_guard()"}}
    art = approval(approved, nonce="postfix-non-equivalent-alias-001")
    k = kernel(approvals=(art,), session="alias-widening")
    findings.append(attempt(
        "NON_EQUIVALENT_TOOL_FAMILY_AUTHORIZATION_WIDENING", target,
        k.authorize(target, now=NOW), k, Runtime(),
        "shell approval presented for python; no explicit equivalence"))

    reset_default_store()
    issued = kernel(tenant="tenant-a", session="tenant-redemption")
    decision = issued.authorize(SAFE, now=NOW)
    redeemer = kernel(tenant="tenant-b", session="tenant-redemption")
    findings.append(attempt(
        "CHANGED_TENANT_DECISION_REDEMPTION", SAFE, decision, redeemer,
        Runtime(), "authorized under tenant-a and redeemed under tenant-b",
        authorization_classification="LEGITIMATE",
        redemption_classification="PROHIBITED"))

    reset_default_store()
    malformed = ApprovalArtifact(
        action_hash=authorization_action_hash(DANGEROUS), issuer=ISSUER,
        principal="principal-a", tenant="tenant-a", issued_at=NOW,
        expires_at=NOW + 300, nonce="",
    ).sign(KEY)
    k = kernel(approvals=(malformed,), session="empty-nonce-replay")
    first = k.authorize(DANGEROUS, now=NOW)
    first_runtime = Runtime()
    k.execute(first, first_runtime, now=NOW)
    replay = k.authorize(DANGEROUS, now=NOW)
    findings.append(attempt(
        "EMPTY_MALFORMED_NONCE_APPROVAL_REPLAY", DANGEROUS, replay, k,
        Runtime(), "empty nonce rejected before either attempted redemption"))

    counts = {
        label: sum(label in row["failure_classification"] for row in findings)
        for label in (
            "AUTHORIZATION_FAILURE", "ENFORCEMENT_FAILURE",
            "OVERBLOCK_FAILURE", "INSTRUMENT_FAILURE",
        )
    }
    return {
        "provenance": {
            "canonical_main_sha":
                "0ba8f882590f34ee4f2ab7cee09b0d5e57d44248",
            "remediation_commit":
                "48620f384308ebc46f939781a53e60cf0bdccc48",
        },
        "findings": findings,
        "counts": counts,
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
