"""Shared fixtures for the round-2 adversarial campaign.

Every executor in this campaign is an INERT RECORDER. No probe performs
network I/O, filesystem mutation, or any real side effect. A "successful
execution" below means only that the kernel handed the call to the recorder.

Run any probe with:

    /opt/homebrew/bin/python3.12 redteam/deepseek_redteam_round2/probe_<id>.py
"""

from __future__ import annotations

import copy
import json
import os
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from morrison_governance import GovernanceLayer, OmegaDomain       # noqa: E402
from morrison_governance.kernel import (                            # noqa: E402
    GovernanceKernel, Principal, SecurityContext,
)
from morrison_governance.kernel import capabilities as C            # noqa: E402
from morrison_governance.kernel.continuity import (                 # noqa: E402
    InMemoryContinuityStore,
)

DOMAINS = [OmegaDomain.CYBERSECURITY, OmegaDomain.DATA_PRIVACY,
           OmegaDomain.FINANCE, OmegaDomain.ENTERPRISE,
           OmegaDomain.COMPLIANCE]

SIGNING_KEY = b"round2-approval-signing-key"
TRUSTED_ISSUERS = frozenset({"security-review"})
INTERNAL_HOSTS = ("acme.internal",)
INTERNAL_EMAILS = ("acme.com",)

DEFAULT_MANIFEST = {
    "read_file": [C.CAP_DATA_READ],
    "summarize": [],
    "http_request": [],
    "get_url": [],
    "upload": [C.CAP_EXTERNAL_DATA_MOVE],
    "transfer": [C.CAP_PAYMENT],
    "delete_bucket": [C.CAP_INFRA_DESTRUCTIVE],
    "apply_config": [C.CAP_SECURITY_CONTROL],
}


class Recorder:
    """Inert executor: records the call it was given, performs nothing."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def __call__(self, call: dict) -> dict:
        self.calls.append(copy.deepcopy(call))
        return {"ok": True, "recorded": len(self.calls)}

    @property
    def executed(self) -> bool:
        return bool(self.calls)

    def last(self) -> dict | None:
        return self.calls[-1] if self.calls else None


def make_context(manifest: dict | None = None, **overrides):
    """A server-side SecurityContext for principal agent@acme."""
    base = dict(
        principal=Principal(id="agent", tenant="acme"),
        signing_key=SIGNING_KEY,
        trusted_issuers=TRUSTED_ISSUERS,
        internal_url_hosts=INTERNAL_HOSTS,
        internal_email_domains=INTERNAL_EMAILS,
        tool_manifest=dict(DEFAULT_MANIFEST if manifest is None else manifest),
        unknown_tool_policy="escalate",
        continuity_store=InMemoryContinuityStore(),
    )
    base.update(overrides)
    return SecurityContext(**base)


_KERNEL_KWARGS = ("session_id", "evidence_key", "require_evidence_key",
                  "decision_ttl_s", "engine_version")


def make_kernel(manifest: dict | None = None, store=None, **overrides):
    """A GovernanceKernel over a fresh layer and context.

    Kernel-only keyword arguments (session_id, evidence_key, ...) are routed
    to GovernanceKernel; everything else goes to SecurityContext.
    """
    if store is not None:
        overrides["continuity_store"] = store
    kernel_kwargs = {name: overrides.pop(name)
                     for name in _KERNEL_KWARGS if name in overrides}
    ctx = make_context(manifest=manifest, **overrides)
    return GovernanceKernel(
        GovernanceLayer(domains=DOMAINS, log_all=False), ctx, **kernel_kwargs)


def verdict(decision) -> str:
    return decision.verdict


def run(decision, kernel, recorder: Recorder):
    """Execute a decision through the kernel, or return a refused tuple."""
    if decision.permitted:
        return kernel.execute(decision, recorder)
    return (False, f"not permitted: {decision.verdict}")


def emit(finding: dict) -> dict:
    """Print a finding as JSON (stable ordering) and return it."""
    print(json.dumps(finding, indent=2, sort_keys=True, default=str))
    return finding


def header(text: str) -> None:
    print(f"\n=== {text} ===")
