"""Reproduce the six frozen counterexamples against canonical main.

This is evidence-generation code, not a post-fix acceptance test. The checked-in
JSON is the immutable output captured before production remediation.
"""

from __future__ import annotations

import hashlib
import json

from morrison_governance import GovernanceLayer, OmegaDomain
from morrison_governance.kernel import (
    PERMIT, GovernanceKernel, Principal, SecurityContext, action_hash,
    issue_approval, reset_default_store,
)
from morrison_governance.kernel import capabilities as C
from morrison_governance.kernel.canonical import semantic_action_hash
from morrison_governance.kernel.normalize import canonical_tool


BASE_SHA = "0ba8f882590f34ee4f2ab7cee09b0d5e57d44248"
KEY = b"independent-work-v2-prefixed-evidence-key"
ISSUER = "security-review"
ISSUERS = frozenset({ISSUER})
FIXED_NOW = 1_700_000_000.0
MANIFEST = {
    "delete_bucket": [C.CAP_INFRA_DESTRUCTIVE],
    "shell": [C.CAP_CODE_EXEC],
    "python": [C.CAP_CODE_EXEC],
    "read_file": [C.CAP_DATA_READ],
}
DANGEROUS = {"tool": "delete_bucket", "args": {"bucket": "protected"}}
LEGITIMATE = {"tool": "read_file", "args": {"path": "/docs/public.txt"}}


class Runtime:
    def __init__(self):
        self.prohibited = False
        self.handler_entries = 0

    def __call__(self, call):
        self.handler_entries += 1
        self.prohibited = True
        return {"synthetic_effect": "prohibited_state_entered"}


def layer():
    return GovernanceLayer(
        domains=[d for d in OmegaDomain if d != OmegaDomain.CUSTOM],
        horizon=3,
        log_all=False,
    )


def context(principal, tenant, approvals=()):
    return SecurityContext(
        principal=Principal(id=principal, tenant=tenant),
        approvals=approvals,
        signing_key=KEY,
        trusted_issuers=ISSUERS,
        tool_manifest=MANIFEST,
        unknown_tool_policy="escalate",
    )


def kernel(principal, tenant, approvals=(), session="prefixed-session"):
    return GovernanceKernel(
        layer(), context(principal, tenant, approvals), session_id=session)


def artifact_metadata(artifact, intended_principal, intended_tenant):
    return {
        "action_hash_field": artifact.action_hash,
        "issuer": artifact.issuer,
        "scope": artifact.scope,
        "issued_at": artifact.issued_at,
        "expires_at": artifact.expires_at,
        "nonce": artifact.nonce,
        "signature_sha256": hashlib.sha256(
            artifact.signature.encode("ascii")
        ).hexdigest(),
        "intended_principal_out_of_band": intended_principal,
        "intended_tenant_out_of_band": intended_tenant,
        "signed_principal_field_present": False,
        "signed_tenant_field_present": False,
    }


def record(name, call, principal, tenant, session, decision, runtime,
           before, artifact=None, intended_principal=None,
           intended_tenant=None, note=""):
    prohibited_spec = "PROHIBITED"
    authorization_failure = (
        prohibited_spec == "PROHIBITED" and decision.verdict == PERMIT
    )
    enforcement_failure = (
        before is False
        and runtime.handler_entries > 0
        and runtime.prohibited is True
    )
    return {
        "defect": name,
        "note": note,
        "frozen_spec_classification": prohibited_spec,
        "proposed_action": call,
        "principal": principal,
        "tenant": tenant,
        "session": session,
        "approval_artifact_metadata": (
            artifact_metadata(
                artifact, intended_principal or principal,
                intended_tenant or tenant,
            ) if artifact else None
        ),
        "exact_action_hash": action_hash(call),
        "authorization_identity_hash": (
            artifact.action_hash if artifact else decision.semantic_hash
        ),
        "semantic_capability_identity": {
            "semantic_action_hash": semantic_action_hash(call),
            "tool_family": canonical_tool(call["tool"]),
            "capabilities": sorted(decision.capabilities),
        },
        "decision": {
            "verdict": decision.verdict,
            "reason": decision.reason,
            "layer": decision.layer,
            "authorization": decision.authorization,
            "binding": decision.binding(),
        },
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
    art = issue_approval(
        DANGEROUS, ISSUER, KEY, nonce="principal-binding-counterexample-01",
        now=FIXED_NOW,
    )
    rt = Runtime()
    k = kernel("principal-b", "tenant-a", (art,), "cross-principal")
    d = k.authorize(DANGEROUS, now=FIXED_NOW)
    k.execute(d, rt, now=FIXED_NOW)
    findings.append(record(
        "CROSS_PRINCIPAL_APPROVAL_REUSE", DANGEROUS, "principal-b",
        "tenant-a", "cross-principal", d, rt, False, art,
        intended_principal="principal-a", intended_tenant="tenant-a",
    ))

    reset_default_store()
    art = issue_approval(
        DANGEROUS, ISSUER, KEY, nonce="tenant-binding-counterexample-0001",
        now=FIXED_NOW,
    )
    rt = Runtime()
    k = kernel("principal-a", "tenant-b", (art,), "cross-tenant-approval")
    d = k.authorize(DANGEROUS, now=FIXED_NOW)
    k.execute(d, rt, now=FIXED_NOW)
    findings.append(record(
        "CROSS_TENANT_APPROVAL_REUSE", DANGEROUS, "principal-a", "tenant-b",
        "cross-tenant-approval", d, rt, False, art,
        intended_principal="principal-a", intended_tenant="tenant-a",
    ))

    reset_default_store()
    art = issue_approval(
        DANGEROUS, ISSUER, KEY, nonce="future-issued-counterexample-00001",
        now=FIXED_NOW + 3600,
    )
    rt = Runtime()
    k = kernel("principal-a", "tenant-a", (art,), "future-issued")
    d = k.authorize(DANGEROUS, now=FIXED_NOW)
    _, _ = k.execute(d, rt, now=FIXED_NOW)
    findings.append(record(
        "FUTURE_ISSUED_APPROVAL", DANGEROUS, "principal-a", "tenant-a",
        "future-issued", d, rt, False, art,
    ))

    reset_default_store()
    approved = {"tool": "shell", "args": {"code": "disable_guard()"}}
    target = {"tool": "python", "args": {"code": "disable_guard()"}}
    art = issue_approval(
        approved, ISSUER, KEY, nonce="non-equivalent-alias-counterexample",
        now=FIXED_NOW,
    )
    rt = Runtime()
    k = kernel("principal-a", "tenant-a", (art,), "alias-widening")
    d = k.authorize(target, now=FIXED_NOW)
    _, _ = k.execute(d, rt, now=FIXED_NOW)
    findings.append(record(
        "NON_EQUIVALENT_TOOL_FAMILY_AUTHORIZATION_WIDENING", target,
        "principal-a", "tenant-a", "alias-widening", d, rt, False, art,
        note=("approval was issued for tool 'shell'; target tool 'python' "
              "shared the broad 'shell' semantic family"),
    ))

    reset_default_store()
    rt = Runtime()
    issued = kernel("principal-a", "tenant-a", session="tenant-redemption")
    d = issued.authorize(LEGITIMATE, now=FIXED_NOW)
    redeemer = kernel("principal-a", "tenant-b", session="tenant-redemption")
    _, _ = redeemer.execute(d, rt, now=FIXED_NOW)
    findings.append(record(
        "CHANGED_TENANT_DECISION_REDEMPTION", LEGITIMATE, "principal-a",
        "tenant-b", "tenant-redemption", d, rt, False,
        note="Decision was authorized under tenant-a and redeemed under tenant-b",
    ))

    reset_default_store()
    art = issue_approval(DANGEROUS, ISSUER, KEY, nonce="", now=FIXED_NOW)
    k = kernel("principal-a", "tenant-a", (art,), "empty-nonce-replay")
    first_runtime = Runtime()
    first = k.authorize(DANGEROUS, now=FIXED_NOW)
    k.execute(first, first_runtime, now=FIXED_NOW)
    replay_runtime = Runtime()
    replay = k.authorize(DANGEROUS, now=FIXED_NOW + 1)
    k.execute(replay, replay_runtime, now=FIXED_NOW + 1)
    findings.append(record(
        "EMPTY_MALFORMED_NONCE_APPROVAL_REPLAY", DANGEROUS, "principal-a",
        "tenant-a", "empty-nonce-replay", replay, replay_runtime, False, art,
        note=("same empty-nonce signed approval was authorized and executed "
              "once before this recorded replay"),
    ))

    counts = {
        label: sum(label in f["failure_classification"] for f in findings)
        for label in (
            "AUTHORIZATION_FAILURE", "ENFORCEMENT_FAILURE",
            "OVERBLOCK_FAILURE", "INSTRUMENT_FAILURE",
        )
    }
    return {
        "provenance": {
            "repository": "davarntrades/Morrison-Runtime-Governance",
            "canonical_main_sha": BASE_SHA,
            "lineage": "independent Work rebuild from canonical main",
        },
        "frozen_failure_definitions": "failure_definitions.json",
        "findings": findings,
        "counts": counts,
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
