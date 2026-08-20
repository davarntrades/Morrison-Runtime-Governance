# Regulatory / Compliance Exposure Context

The Frontier Containment Lab derives regulatory and control-framework context
from structured runtime evidence. It is an explanatory layer after Morrison's
decision and execution gate. It cannot change a verdict, authorize a tool, or
cause execution.

## Three separate value categories

- **Measured simulated direct exposure** comes only from defensible structured
  action arguments, such as the amount in a simulated transfer.
- **Illustrative downstream impact** uses explicitly labelled demo profiles. It
  is not an observed loss or guaranteed saving.
- **Statutory maximum context** uses versioned deterministic rules from official
  legislation or regulators. It is neither a predicted penalty nor protected
  value, and maxima across regimes are never summed.

## Applicability

Runtime tools, capabilities, resources, trust-boundary decisions and Morrison
rule/layer metadata can make a profile potentially relevant. Legal
applicability is not inferred from prompt wording, model identity, or sector
alone. The status is one of:

- `CONFIRMED_BY_CONFIGURATION`
- `POTENTIALLY_RELEVANT`
- `INSUFFICIENT_INFORMATION`
- `NOT_APPLICABLE`

Confirmation requires explicit operator-controlled organization configuration,
including relevant jurisdictions, entity classifications and data categories.
Annual global turnover is never invented. A missing classification or turnover
causes a deterministic calculation to remain unavailable.

## Profiles and calculations

The initial registry covers EU GDPR, UK GDPR / DPA 2018, the EU AI Act, NIS2,
DORA, PCI DSS, HIPAA / HITECH and UK financial-services governance context.
Only profiles with a bounded, reliable formula expose a monetary statutory
ceiling. DORA, PCI DSS, HIPAA/HITECH and FCA SYSC surface obligation/control
context without inventing a fine number. PCI DSS is explicitly contractual and
assurance context, not a statutory fine regime.

Turnover calculations use only a configured amount in the same currency as the
official profile. The engine performs no exchange-rate inference. The UI and
evidence show the turnover, percentage, fixed ceiling, selected tier and
calculation operator. EU AI Act calculations additionally require explicit SME
status because Article 99 applies different ceiling semantics to undertakings.

## Sources and versioning

Every profile records its authority, official URL, provision/reference,
effective dates, profile version and source-verification date. Historical
session evidence embeds the profile version used for that session; registry
updates do not silently rewrite sealed evidence.

Source data is maintained in `runtime_eval/frontier/regulatory/registry.py` and
must be reviewed against the official publication before changing a formula.
No LLM participates in applicability status, statutory percentages, turnover
calculation, source mapping or penalty ceilings.

## Mode-sensitive language

Shadow Mode reports **regulatory exposure observed** and never claims a loss was
prevented. Guarded Pilot and Enforced modes report **runtime mitigation
recorded** when the runtime evidence supports it. Neither mode claims that a
violation occurred or that a regulator would impose a penalty.

## Legal and product boundary

This feature provides technical and regulatory exposure context from configured
rules and runtime evidence. It does not provide legal advice, determine that a
violation occurred, predict regulator enforcement, or guarantee that any
monetary penalty would have been imposed.
