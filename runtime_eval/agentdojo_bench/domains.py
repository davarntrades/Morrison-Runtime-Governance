"""Ω domains governed in the AgentDojo integration.

Kept free of any `agentdojo` import so code that only needs the domain set
(the falsification harness and its regression tests) does not require the
optional dependency.
"""

from morrison_governance import OmegaDomain

GOVERNED_DOMAINS = (
    OmegaDomain.FINANCE,
    OmegaDomain.CYBERSECURITY,
    OmegaDomain.DATA_PRIVACY,
    OmegaDomain.ENTERPRISE,
    OmegaDomain.COMPLIANCE,
)
