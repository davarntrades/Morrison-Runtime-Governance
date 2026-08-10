"""The LB-0 synthetic world: actions, capabilities, domains, scopes.

This vocabulary is PUBLIC. The discovery layer sees every symbol here, because
every symbol here is something a real governance trace would carry.

Capability names are taken from Morrison's own canonical vocabulary wherever
one exists (`morrison_governance.kernel.capabilities`), which is the point of
the exercise: the baseline ontology is built from the concepts Morrison
actually has, so a structure it cannot express is genuinely outside the current
ontology rather than outside a strawman.

Four capabilities below have NO Morrison equivalent
(`identity.reverify`, `record.write`, `data.aggregate`, `infra.scale`). That is
deliberate and honest: an ontology gap is only interesting if the vocabulary is
allowed to contain concepts the ontology never classified.

NOTHING IN THIS MODULE ENCODES WHICH COMPOSITIONS ARE UNSAFE. Every action
below is individually permitted; the generator assigns `policy_decision:
"allow"` to all of them and the baseline ontology (see `ontology/baseline.py`)
agrees for all but the deliberately known-bad classes.
"""

from __future__ import annotations

from dataclasses import dataclass

from morrison_governance.kernel import capabilities as C

# ── trust boundaries ────────────────────────────────────────────────────
INTERNAL = "internal"
PARTNER = "partner"
EXTERNAL = "external"
TRUST_BOUNDARIES = (INTERNAL, PARTNER, EXTERNAL)

# ── governance domains ──────────────────────────────────────────────────
DOMAIN_CUSTOMER_DATA = "customer_data"
DOMAIN_PAYMENTS = "payments"
DOMAIN_COMMUNICATIONS = "communications"
DOMAIN_IDENTITY = "identity"
DOMAIN_INFRASTRUCTURE = "infrastructure"
DOMAIN_ANALYTICS = "analytics"
DOMAIN_SUPPORT = "support"
DOMAINS = (DOMAIN_CUSTOMER_DATA, DOMAIN_PAYMENTS, DOMAIN_COMMUNICATIONS,
           DOMAIN_IDENTITY, DOMAIN_INFRASTRUCTURE, DOMAIN_ANALYTICS,
           DOMAIN_SUPPORT)

# ── capabilities: Morrison's canonical vocabulary, plus four it lacks ───
CAP_DATA_READ = C.CAP_DATA_READ
CAP_EXTERNAL_MOVE = C.CAP_EXTERNAL_DATA_MOVE
CAP_PAYMENT = C.CAP_PAYMENT
CAP_CREDENTIAL_READ = C.CAP_CREDENTIAL_READ
CAP_IAM_PRIVILEGED = C.CAP_IAM_PRIVILEGED
CAP_INFRA_DESTRUCTIVE = C.CAP_INFRA_DESTRUCTIVE
CAP_CODE_EXEC = C.CAP_CODE_EXEC

CAP_IDENTITY_REVERIFY = "identity.reverify"
CAP_RECORD_WRITE = "record.write"
CAP_DATA_AGGREGATE = "data.aggregate"
CAP_INFRA_SCALE = "infra.scale"

UNMODELLED_CAPABILITIES = frozenset({
    CAP_IDENTITY_REVERIFY, CAP_RECORD_WRITE, CAP_DATA_AGGREGATE, CAP_INFRA_SCALE,
})

# ── permission scope tokens ─────────────────────────────────────────────
SCOPE_CUSTOMER_READ = "customer.read"
SCOPE_CUSTOMER_READ_PII = "customer.read.pii"
SCOPE_PAYMENTS_READ = "payments.read"
SCOPE_PAYMENTS_INSTRUMENT_WRITE = "payments.instrument.write"
SCOPE_COMMS_SEND_INTERNAL = "comms.send.internal"
SCOPE_COMMS_SEND_EXTERNAL = "comms.send.external"
SCOPE_IDENTITY_VERIFY = "identity.verify"
SCOPE_SECRETS_READ = "secrets.read"
SCOPE_IAM_WRITE = "iam.write"
SCOPE_IAM_WILDCARD = "iam.*"
SCOPE_INFRA_WRITE = "infra.write"
SCOPE_SUPPORT_READ = "support.read"
SCOPE_SUPPORT_WRITE = "support.write"
SCOPE_ANALYTICS_READ = "analytics.read"

# Destinations an operator has explicitly forbidden. Used by the KNOWN-BAD
# `prohibited_communication` class, which the existing ontology does cover.
DENYLISTED_DESTINATIONS = frozenset({"blocked-broker", "unvetted-aggregator"})


@dataclass(frozen=True)
class ActionSpec:
    """One executable action in the synthetic world."""

    action: str
    capability: str
    domain: str
    trust_boundary: str
    permission_scope: tuple
    resource_type: str


def _spec(action, capability, domain, boundary, scope, resource_type):
    return ActionSpec(action=action, capability=capability, domain=domain,
                      trust_boundary=boundary, permission_scope=tuple(sorted(scope)),
                      resource_type=resource_type)


CATALOGUE = {s.action: s for s in (
    # ── customer data ──────────────────────────────────────────────────
    _spec("read_customer_profile", CAP_DATA_READ, DOMAIN_CUSTOMER_DATA, INTERNAL,
          (SCOPE_CUSTOMER_READ, SCOPE_CUSTOMER_READ_PII), "customer"),
    _spec("read_account_metadata", CAP_DATA_READ, DOMAIN_CUSTOMER_DATA, INTERNAL,
          (SCOPE_CUSTOMER_READ,), "account"),
    # ── payments ───────────────────────────────────────────────────────
    _spec("update_payee_instrument", CAP_PAYMENT, DOMAIN_PAYMENTS, INTERNAL,
          (SCOPE_PAYMENTS_INSTRUMENT_WRITE,), "payee"),
    _spec("prepare_payment_instruction", CAP_PAYMENT, DOMAIN_PAYMENTS, INTERNAL,
          (SCOPE_PAYMENTS_READ,), "instruction"),
    _spec("read_payment_history", CAP_DATA_READ, DOMAIN_PAYMENTS, INTERNAL,
          (SCOPE_PAYMENTS_READ,), "ledger"),
    # ── communications ─────────────────────────────────────────────────
    _spec("send_crm_update", CAP_EXTERNAL_MOVE, DOMAIN_COMMUNICATIONS, PARTNER,
          (SCOPE_COMMS_SEND_EXTERNAL,), "crm-feed"),
    _spec("post_partner_webhook", CAP_EXTERNAL_MOVE, DOMAIN_COMMUNICATIONS, PARTNER,
          (SCOPE_COMMS_SEND_EXTERNAL,), "partner-feed"),
    _spec("notify_external_processor", CAP_EXTERNAL_MOVE, DOMAIN_COMMUNICATIONS,
          EXTERNAL, (SCOPE_COMMS_SEND_EXTERNAL,), "processor-feed"),
    _spec("send_internal_digest", CAP_EXTERNAL_MOVE, DOMAIN_COMMUNICATIONS, INTERNAL,
          (SCOPE_COMMS_SEND_INTERNAL,), "digest"),
    # ── identity ───────────────────────────────────────────────────────
    _spec("reverify_identity", CAP_IDENTITY_REVERIFY, DOMAIN_IDENTITY, INTERNAL,
          (SCOPE_IDENTITY_VERIFY,), "identity-check"),
    _spec("read_secret_ref", CAP_CREDENTIAL_READ, DOMAIN_IDENTITY, INTERNAL,
          (SCOPE_SECRETS_READ,), "secret"),
    _spec("grant_role_binding", CAP_IAM_PRIVILEGED, DOMAIN_IDENTITY, INTERNAL,
          (SCOPE_IAM_WRITE,), "role"),
    # ── infrastructure ─────────────────────────────────────────────────
    _spec("scale_worker_pool", CAP_INFRA_SCALE, DOMAIN_INFRASTRUCTURE, INTERNAL,
          (SCOPE_INFRA_WRITE,), "worker-pool"),
    _spec("terminate_worker_pool", CAP_INFRA_DESTRUCTIVE, DOMAIN_INFRASTRUCTURE,
          INTERNAL, (SCOPE_INFRA_WRITE,), "worker-pool"),
    # ── analytics / support ────────────────────────────────────────────
    _spec("read_analytics_rollup", CAP_DATA_READ, DOMAIN_ANALYTICS, INTERNAL,
          (SCOPE_ANALYTICS_READ,), "rollup"),
    _spec("aggregate_customer_segment", CAP_DATA_AGGREGATE, DOMAIN_ANALYTICS,
          INTERNAL, (SCOPE_ANALYTICS_READ,), "segment"),
    _spec("list_support_tickets", CAP_DATA_READ, DOMAIN_SUPPORT, INTERNAL,
          (SCOPE_SUPPORT_READ,), "ticket"),
    _spec("write_support_note", CAP_RECORD_WRITE, DOMAIN_SUPPORT, INTERNAL,
          (SCOPE_SUPPORT_WRITE,), "ticket"),
)}

# Actions safe to use as neutral padding inside a composed trajectory. Excludes
# every action that participates in a KNOWN-BAD class, so the hidden
# compositional class and the already-modelled classes stay disjoint and the
# measured "baseline miss" is attributable to one thing.
FILLER_ACTIONS = (
    "read_analytics_rollup", "aggregate_customer_segment", "list_support_tickets",
    "write_support_note", "scale_worker_pool", "read_payment_history",
    "send_internal_digest", "read_account_metadata",
)

KNOWN_BAD_ACTIONS = frozenset({
    "read_secret_ref", "grant_role_binding", "terminate_worker_pool",
})

WORLD_VERSION = "lb0-world-1.0"
