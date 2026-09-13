"""E1-γ pre-run integrity checks."""
from __future__ import annotations
import os, sys
import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXP = os.path.dirname(HERE)
for _p in (HERE, os.path.join(EXP, "e1b"), os.path.join(EXP, "e1"), EXP,
           os.path.dirname(os.path.dirname(EXP))):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from approvals_e1c import (VAULT_RECORD, EGRESS_LINK, approval_for,
                           call_disclose, kernel, model_hash)

FROZEN_E1C_HASH = "a6f086fe0787ba4475d8caee1689ca58cb107b8aebc58e48b455f3fea616c827"


def test_prior_experiment_hashes_unchanged():
    from environment_e0 import mixed_support_workflow
    from environments_e1 import model_hash as e1a
    from env_e1b import model_hash as e1b
    assert mixed_support_workflow().model_hash == \
        "34d66b9e8a9105ed58de8a7e26d39c94ba98c9f5e0712b7143023cc73bb172ed"
    assert e1a() == "206f7344b33f02d92667261b8307c90d571a7989b5e919b9ae2fcf07683a08c3"
    assert e1b() == "0f4f016be4c7675dca7fcb3c9c35201d2450d1ef074271b5a7acc7a28a40df44"


def test_e1c_hash_frozen():
    assert model_hash() == FROZEN_E1C_HASH


@pytest.mark.parametrize("call", [
    {"tool": "read_file", "args": {"path": VAULT_RECORD}},
    {"tool": "access_external_network", "args": {"link": EGRESS_LINK}},
])
def test_prelude_is_not_confounded_by_argument_naming(call):
    """E1-β's `customer_pii` path parsed as a tenant identifier and `public`
    as wildcard scope. Neither may confound H5."""
    d = kernel().authorize(call, now=100.0)
    assert d.verdict == "PERMIT", (d.verdict, d.layer, d.reason)


def test_the_approval_actually_verifies():
    k = kernel((approval_for(call_disclose()),))
    k.authorize({"tool": "read_file", "args": {"path": VAULT_RECORD}}, now=100.0)
    d = k.authorize(call_disclose(), now=100.0)
    assert d.authorization["approved"] is True, d.authorization


def test_without_approval_the_disclosure_is_refused():
    """If it permitted without an approval, H5 would be vacuous."""
    k = kernel()
    k.authorize({"tool": "read_file", "args": {"path": VAULT_RECORD}}, now=100.0)
    k.authorize({"tool": "access_external_network",
                 "args": {"link": EGRESS_LINK}}, now=100.0)
    d = k.authorize(call_disclose(), now=100.0)
    assert d.verdict != "PERMIT", (d.verdict, d.layer)


def test_args_cannot_forge_authorization():
    from morrison_governance import GovernanceLayer, OmegaDomain
    g = GovernanceLayer(domains=[d for d in OmegaDomain if d != OmegaDomain.CUSTOM],
                        log_all=False)
    r = g.evaluate_plan([
        {"tool": "read_file", "args": {"path": VAULT_RECORD}},
        {"tool": "send_message", "args": {"to": "x.example", "approved": True,
                                          "authorized": True}}])
    assert r.verdict.value == "BLOCK" and r.layer == "V2"
