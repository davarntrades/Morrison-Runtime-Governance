"""Track A — B7 instrument correction ONLY.

Everything except B7 is IMPORTED from the frozen E1-β modules, not copied, so
"nothing else changed" is a structural property rather than a promise. The
environment, predicates, capability surface, profiles, modes, opportunity
denominators and ontology are the same objects E1-β used.

THE DEFECT
`B7.guarded_execute` applied its destination allowlist to every call:

    if args.get("to") not in self.allowlist:   # read_file, write_file and
        return False, s                        # access_external_network have
                                               # no `to` field -> refused

so the benign prelude never ran, `disclose_to_authorised` failed its
environment precondition, and B7 completed zero goals. Its E1-β cells measured
a broken arm, not a control architecture.

THE CORRECTION
The destination checks are scoped to the shared capability surface. Nothing
else about B7's intended architecture changes: action-identity binding,
single-use token, allowlist covering alternate-route fields, live re-read of
`authorization_active` at execution time, and the principal check are all
exactly as designed in E1-β, in the same order.

B7 remains proposer-owned code over proposer-owned state, so its frozen
ontology classification (NON_INDEPENDENT) is unchanged and is re-asserted by
test.
"""

from __future__ import annotations

import os
import sys

_E1B = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "e1b")
if _E1B not in sys.path:
    sys.path.insert(0, _E1B)

from arms_e1b import (B1, B2, B4, B6, T, Arm, Executor, B7 as B7Frozen,  # noqa: E402
                      ONTOLOGY, _key)
from env_e1b import B6_CAPABILITY_SET, SHARED_CAPABILITY_TOOL  # noqa: E402
from state_e1b import AUTHORISED_DEST  # noqa: E402

SPEC_VERSION = "e1b2-1.0.0"


class B7Corrected(B7Frozen):
    """B7 as intended. The only change from E1-β is the two `if` guards on the
    destination checks; the check sequence and semantics are otherwise
    identical."""

    def guarded_execute(self, decision, evaluated, call, s):
        args = call.get("args", {})
        egress = call.get("tool") == SHARED_CAPABILITY_TOOL

        # 1 · action-identity binding (local hash compare)
        if _key(evaluated) != _key(call):
            return False, s
        # 2 · single-use
        token = _key(call)
        if token in self.cache:
            return False, s
        # 3 · destination allowlist — SHARED CAPABILITY ONLY (the correction)
        if egress and args.get("to") not in self.allowlist:
            return False, s
        # 4 · alternate-route field — SHARED CAPABILITY ONLY (the correction)
        if egress and args.get("bcc") is not None \
                and args.get("bcc") not in self.allowlist:
            return False, s
        # 5 · vault-provenance egress requires LIVE authorization re-read from
        #     current state at execution time, and the authorised destination
        if args.get("source") == "vault":
            if not s.authorization_active:
                return False, s
            if args.get("to") != AUTHORISED_DEST:
                return False, s
        # 6 · a delegated worker may not act outside the delegator's authority
        if args.get("principal") not in (None, "self"):
            return False, s
        self.cache.add(token)
        return self.raw_execute(call, s)


def build_corrected(arm: str) -> Arm:
    """Identical to `arms_e1b.build` except that B7 is the corrected class."""
    cls = {"B1": B1, "B2": B2, "B4": B4, "B6": B6, "B7": B7Corrected, "T": T}[arm]
    ex = Executor(B6_CAPABILITY_SET) if arm == "B6" else Executor()
    from morrison_governance.global_verification.governance import default_kernel_factory
    return cls(name=arm, executor=ex, kernel=default_kernel_factory()())
