"""Financial Admissible Operating Envelope (AOE) for invoice collection.

This module does NOT implement an authorization mechanism. It defines the
envelope as Morrison Ω rules (`morrison_governance.domains.OmegaRule`) that the
existing `ReachabilityEvaluator` runs inside `GovernanceKernel.authorize`:

  * LOCAL rules judge one proposed operation against the authoritative
    commercial terms: customer, agreement, service, currency, amount and the
    Stripe destination account.
  * GLOBAL rules judge the operation against the governed trajectory: every
    earlier invoice operation the kernel holds as executed, exported or
    reserved (concurrent in-flight proposals included), plus pre-existing
    collection state observed in Stripe. They enforce duplicate collection,
    cumulative ceilings and invoice-count limits.

The commercial terms and the observed collection state reach the rules only
through `SecurityContext.trusted_facts`, which the kernel injects with TRUSTED
provenance. Rules read it with `ProvenanceState.attested`, so a caller that
writes a field called `collection_envelope` into its own arguments supplies
nothing. Missing trusted state is a violation: the envelope fails closed.

Amounts are integer GBP minor units (pence). The accounting distinguishes
issued (finalised, not void), outstanding (issued and unpaid) and paid
amounts; creating an invoice is never treated as receipt of funds. Ceilings
are enforced against ISSUED exposure, because that is what the agent can
cause.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable, Optional

from morrison_governance import provenance as _prov
from morrison_governance.domains import OmegaDomain, OmegaRule

TOOL = "create_collection_invoice"
FACT = "collection_envelope"

# Arguments every invoice operation must carry. Names deliberately avoid the
# kernel's quarantined authority vocabulary (`limit`, `tenant`, `approved`...)
# and its tenant-key list (`customer_id`, `account_id`), which would otherwise
# strip or reinterpret them.
REQUIRED_ARGS = ("customer", "stripe_customer", "agreement_id",
                 "agreement_version", "service", "amount", "currency",
                 "stripe_account", "billing_reference", "operation_id",
                 "description")


# ─────────────────────────────────────────────────────────────
# Reading the evaluation namespace
# ─────────────────────────────────────────────────────────────

def _envelope(s: dict) -> Optional[dict]:
    """The trusted envelope, or None when no TRUSTED copy exists."""
    env = _prov.coerce(s).attested(FACT, default=None)
    return env if isinstance(env, dict) else None


def _args_of(s: dict) -> dict:
    """The candidate state's own arguments (caller subject matter)."""
    raw = s.get("args")
    if isinstance(raw, str) and raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except ValueError:
            pass
    return {k: s.get(k) for k in REQUIRED_ARGS if k in s}


def _prior_invoice_ops(s: dict) -> list[dict]:
    """Earlier invoice operations in this trajectory, oldest first.

    `TrajectoryExtractor.from_plan` records every earlier step under
    `step_<i>_tool` / `step_<i>_args` (DERIVED provenance: the engine's own
    record of the governed history the kernel supplied as the prefix).
    """
    out = []
    step = s.get("step") or 0
    for i in range(int(step)):
        if s.get(f"step_{i}_tool") != TOOL:
            continue
        args = s.get(f"step_{i}_args")
        if isinstance(args, dict):
            out.append(args)
    return out


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


# ─────────────────────────────────────────────────────────────
# Pure envelope predicates. Each returns a reason string or None.
# ─────────────────────────────────────────────────────────────

def _applies(s: dict) -> bool:
    return str(s.get("tool", "")).strip().lower() == TOOL


def _committed(s: dict, args: dict, env: dict) -> bool:
    """Is this state the ORIGINAL record of an already-dispatched operation?

    Ω rules run over every state of the trajectory, not only the candidate.
    An operation that was admissible when it was authorised and has since
    been dispatched is COUNTED by the global rules (it is an effect that may
    have happened) but is not RE-JUDGED: otherwise a later change (an
    agreement terminated, a ceiling lowered, an invoice voided) would make a
    past step "inadmissible" and refuse every later decision for every
    customer.

    Only the first occurrence of a dispatched operation id is exempt. A new
    proposal that reuses a dispatched operation id has an earlier occurrence
    in its own prefix, so it is judged in full and refused as a duplicate.
    """
    op = args.get("operation_id")
    if not op or op not in set(env.get("dispatched_operations") or ()):
        return False
    return not any(p.get("operation_id") == op for p in _prior_invoice_ops(s))


def local_violation(s: dict) -> Optional[str]:
    """Why this single operation is outside the envelope, or None."""
    if not _applies(s):
        return None
    env = _envelope(s)
    if env is None:
        return "no trusted collection envelope is available (fail closed)"
    a = _args_of(s)
    if _committed(s, a, env):
        return None
    missing = [k for k in REQUIRED_ARGS if a.get(k) in (None, "")]
    if missing:
        return f"proposal is missing required fields {missing}"
    customers = env.get("customers") or {}
    cust = customers.get(a["customer"])
    if not isinstance(cust, dict):
        return f"customer {a['customer']!r} is not an authorized customer"
    if a["stripe_customer"] != cust.get("stripe_customer"):
        return (f"Stripe customer {a['stripe_customer']!r} is not the customer "
                f"record bound to {a['customer']!r}")
    agr = cust.get("agreement") or {}
    if agr.get("status") != "active":
        return (f"agreement {agr.get('agreement_id')!r} for {a['customer']!r} "
                f"is {agr.get('status')!r}, not active")
    if a["agreement_id"] != agr.get("agreement_id"):
        return (f"agreement {a['agreement_id']!r} is not the authorized "
                f"agreement for {a['customer']!r}")
    if a["agreement_version"] != agr.get("version"):
        return (f"agreement version {a['agreement_version']!r} is stale; the "
                f"authoritative version is {agr.get('version')!r}")
    if a["service"] != agr.get("service"):
        return f"service {a['service']!r} is not approved under the agreement"
    if str(a["currency"]).lower() != "gbp" or a["currency"] != agr.get("currency"):
        return f"currency {a['currency']!r} is not the agreement currency 'gbp'"
    if not _is_int(a["amount"]) or a["amount"] <= 0:
        return f"amount {a['amount']!r} is not a positive integer in minor units"
    if a["amount"] not in (agr.get("authorized_amounts_minor") or ()):
        return (f"amount {a['amount']} is not an authorized invoice amount "
                f"under the agreement {agr.get('authorized_amounts_minor')}")
    if a["stripe_account"] != env.get("company_stripe_account"):
        return (f"destination Stripe account {a['stripe_account']!r} is not "
                f"the configured Resurrection Tech Ltd account")
    return None


def _counted(ops: Iterable[dict], customer: str, agreement_id: str,
             voided: set) -> list[dict]:
    return [o for o in ops
            if o.get("customer") == customer
            and o.get("agreement_id") == agreement_id
            and o.get("operation_id") not in voided]


def collection_position(env: dict, customer: str, agreement_id: str,
                        prior_ops: Iterable[dict]) -> dict:
    """Issued exposure for one customer agreement: observed + governed.

    `observed` is what Stripe already holds that was NOT created through this
    kernel (for example an invoice an operator issued by hand). `governed` is
    every invoice operation in the trajectory that has not been voided.
    """
    voided = set(env.get("voided_operations") or ())
    observed = [o for o in (env.get("observed_collections") or {}).get(customer, [])
                if o.get("agreement_id") == agreement_id]
    governed = _counted(prior_ops, customer, agreement_id, voided)
    return {
        "observed_issued_minor": sum(int(o.get("amount_minor") or 0) for o in observed),
        "governed_issued_minor": sum(int(o.get("amount") or 0) for o in governed),
        "count": len(observed) + len(governed),
        "billing_references": [o.get("billing_reference") for o in observed]
                              + [o.get("billing_reference") for o in governed],
        "operation_ids": [o.get("operation_id") for o in governed],
    }


def global_violation(s: dict) -> Optional[str]:
    """Why this operation, admissible on its own, breaks a trajectory limit."""
    if not _applies(s):
        return None
    env = _envelope(s)
    if env is None:
        return "no trusted collection envelope is available (fail closed)"
    a = _args_of(s)
    if _committed(s, a, env):
        return None
    prior = _prior_invoice_ops(s)
    op = a.get("operation_id")
    if op and any(p.get("operation_id") == op for p in prior):
        return f"operation {op!r} was already authorized (duplicate operation id)"
    cust = (env.get("customers") or {}).get(a.get("customer"))
    if not isinstance(cust, dict):
        return None            # the local rule refuses this
    agr = cust.get("agreement") or {}
    pos = collection_position(env, a.get("customer"), agr.get("agreement_id"),
                              prior)
    if a.get("billing_reference") in pos["billing_references"]:
        return (f"duplicate collection: {a.get('customer')!r} has already been "
                f"invoiced for billing reference {a.get('billing_reference')!r}")
    max_invoices = agr.get("max_invoices")
    if _is_int(max_invoices) and pos["count"] + 1 > max_invoices:
        return (f"invoice count {pos['count'] + 1} would exceed the agreement "
                f"maximum of {max_invoices}")
    amount = a.get("amount") if _is_int(a.get("amount")) else 0
    ceiling = agr.get("ceiling_minor")
    issued = pos["observed_issued_minor"] + pos["governed_issued_minor"]
    if not _is_int(ceiling):
        return "agreement has no cumulative collection ceiling (fail closed)"
    if issued + amount > ceiling:
        return (f"cumulative issued collection would be {issued + amount} "
                f"minor units (existing {issued} + proposed {amount}), above "
                f"the agreement ceiling of {ceiling}")
    return None


# ─────────────────────────────────────────────────────────────
# Ω rules
# ─────────────────────────────────────────────────────────────

LOCAL_RULE = "aoe_local_commercial_terms"
GLOBAL_RULE = "aoe_global_collection_limits"


def local_rules() -> list[OmegaRule]:
    return [OmegaRule(
        domain=OmegaDomain.FINANCE, name=LOCAL_RULE,
        description="Invoice operation outside the authorized commercial terms "
                    "(customer, agreement, service, currency, amount, account)",
        check=lambda s: local_violation(s) is not None)]


def global_rules() -> list[OmegaRule]:
    return [OmegaRule(
        domain=OmegaDomain.FINANCE, name=GLOBAL_RULE,
        description="Invoice operation that breaks a trajectory limit "
                    "(duplicate, cumulative ceiling, invoice count)",
        check=lambda s: global_violation(s) is not None)]


def envelope_rules() -> list[OmegaRule]:
    return local_rules() + global_rules()


def agreements_digest(customers: dict, company_account: str) -> str:
    """Digest of the commercial terms. Placed in `policy_values`, which the
    kernel folds into its live ruleset hash: any change to an agreement voids
    every outstanding kernel decision issued under the old terms."""
    raw = json.dumps({"customers": customers, "account": company_account},
                     sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


def resource_scopes(call: dict) -> list[str]:
    """Shared resource a call acts on: the customer's collection position.

    Passed as `SecurityContext.resource_scopes`, so every principal acting on
    the same customer is evaluated against the same history (Morrison G1)."""
    if str(call.get("tool", "")).strip().lower() != TOOL:
        return []
    cust = (call.get("args") or {}).get("customer")
    if not isinstance(cust, str) or not cust.strip():
        raise ValueError("invoice operation names no customer")
    return [f"collection:{cust}"]
