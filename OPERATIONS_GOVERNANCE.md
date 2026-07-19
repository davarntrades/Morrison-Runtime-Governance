# Operations Governance — Internal Agent Contract

Morrison Runtime Governance now governs Resurrection Tech's **own** autonomous
Operations Agent, exactly as it governs customer workloads. This document is the
contract between the enterprise platform's Operations Agent
(`resurrection-tech-enterprise/lib/ops/*`) and this engine. **The engine itself
is unchanged** — the internal-operations Ω rules are deployment-level
`custom_rules` (`governance-service/operations_rules.py` in the enterprise
repo), following the same pattern as the sector and finance hardening rules,
and mapped onto existing `OmegaDomain` enum values only.

## Principle

```
Observe → Reason → Propose Action → Runtime Governance Evaluation
        → Allow / Block / Escalate → Execute → Evidence → Audit Log
```

The agent is not trusted. Its reasoning layer (an LLM) produces structured
recommendations only and never executes. Every privileged action is submitted
to this engine as a synthetic one-step trajectory **before** execution. If the
engine is unreachable, the platform fails closed: no verdict, no execution.

## Trajectory contract

The agent submits `POST /v1/evaluate` with domains
`["enterprise", "compliance", "data_privacy"]`, horizon 3, and a one-step
trajectory. Authorisation flags travel inside `args` (the engine spreads args
into the state Ω rules see):

```json
{
  "trajectory": [{
    "tool": "promote_to_pilot",
    "args": {
      "actor": "operations_agent",
      "agent": "resurrection-tech-ops-agent",
      "pilot_approved": true,
      "approved_by": "operator@resurrection-tech"
    }
  }],
  "domains": ["enterprise", "compliance", "data_privacy"]
}
```

## Governed operations vocabulary

Deny-by-default — the tool violates Ω unless the named flag is present and true.
The Control Room attaches a flag **only** after an explicit operator sign-off,
so a permit for these actions is always human-authorised and engine-issued.

| Ω rule | Domain | Tools (examples) | Curing flag(s) |
|---|---|---|---|
| `ops_unauthorized_report_delivery` | enterprise | `send_confidential_report`, `deliver_report`… | `report_delivery_authorized` |
| `ops_unauthorized_deployment` | enterprise | `deploy_runtime`, `promote_deployment`… | `deployment_approved` |
| `ops_unauthorized_org_creation` | enterprise | `create_organisation`, `onboard_customer`… | `onboarding_verified` |
| `ops_unauthorized_pilot_promotion` | enterprise | `promote_to_pilot`, `advance_engagement_stage`… | `pilot_approved` |
| `ops_unauthorized_customer_modification` | enterprise | `modify_customer`, `archive_customer`… | `change_authorized` |
| `ops_unauthorized_document_export` | data_privacy | `export_documents`, `bulk_export`… | `export_authorized` + internal destination |

Unconditional — **no flag combination cures these**; the agent's executors also
refuse them in code, and the attempt itself is recorded as evidence:

| Ω rule | Domain | Tools (examples) |
|---|---|---|
| `ops_evidence_destruction` | compliance | `delete_evidence`, `purge_audit_trail`, `tamper_evidence`… |
| `ops_credential_sharing` | data_privacy | `share_credentials`, `share_api_key`, `expose_secret`… |

## Verdict mapping (platform side)

| Engine verdict | Agent outcome |
|---|---|
| `PERMIT` | allow — auto-execute for low/medium-risk actions; high/critical still escalate to an operator |
| `BLOCK` on a deny-by-default authorisation rule (unapproved proposal) | escalate — operator approval re-evaluates with the curing flags |
| `BLOCK` / `NO_VALID_SOLUTION` otherwise | block, final |
| `ESCALATE` / `ENVIRONMENT_SENSITIVE` | escalate — human review |
| engine unreachable / error | block (fail-closed) |

## Evidence

Every decision produces a write-once evidence row (timestamp, actor, agent,
policy, risk, reason, verdict, execution result, customer/org) that carries the
engine's rule name, Ω domain, trajectory hash, and attestation — so an auditor
can tie each internal agent action to the exact engine + ruleset that decided
it, using the same attestation chain as customer verdicts.

## Guarantees preserved

- Engine geometry and default Ω registries unchanged; scale-by-changing-Ω only.
- Rules are tool-scoped: inert for every customer workload (verified by the
  hardening probe `governance-service/test_operations_rules.py`, 18/18, plus
  the existing sector/domain/finance suites, unchanged).
- Determinism and replayability of verdicts are untouched.
