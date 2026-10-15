"""Neutral adapter API (SPEC §6).

An adapter connects one system under test (SUT) to the harness. It may translate
formats and policies; it may not add enforcement the SUT does not have. The
harness owns the fixture and the scoring: an adapter commits effects only by
calling the `executor` it is given, and never reads the score.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

Executor = Callable[[dict, str, str, Any], dict]   # (op, principal, decision_ref, token) -> effect


@dataclass
class Outcome:
    status: str                       # executed | refused | deferred | error
    detail: str = ""
    request: Any = None               # opaque handle for approve(), when deferred
    token: Any = None                 # anything the SUT emitted that an interceptor could capture
    decision_ref: str = ""


@dataclass
class Context:
    """Per-operation context from the scripted proposer."""
    step_id: str
    arg_sources: dict = field(default_factory=dict)   # arg -> "request" | "untrusted:<doc>" | "trusted:<doc>"
    approval: Any = None              # adapter-native handle, a reused one, or {"forged": True}


class Adapter:
    name = "abstract"
    #: Mechanisms the ORIGINAL implementation has (informational; SPEC §0.4).
    mechanisms: frozenset = frozenset()

    #: Read-only view of resource state, set by the harness before setup().
    #: Available to every adapter: a SUT whose policies read the environment
    #: (e.g. CaMeL's) may use it; none may write through it.
    observe: Optional[Callable[[], dict]] = None

    def can_run(self, scenario: dict) -> tuple[bool, str]:
        """(False, reason) if the scenario cannot be run against this SUT at all
        (no interface for a required step, or its policy is not expressible)."""
        return True, ""

    def setup(self, scenario: dict, executor: Executor, workdir) -> None:
        raise NotImplementedError

    def submit(self, principal: str, op: dict, ctx: Context) -> Outcome:
        raise NotImplementedError

    def approve(self, request: Any, principal: str, op: dict) -> Any:
        """Obtain the SUT's native approval for a deferred request; None if the
        SUT has no approval path."""
        return None

    def forge_approval(self, principal: str, op: dict) -> Any:
        """A native-format approval NOT issued by the SUT's approver (attacker's
        forgery). None if the SUT has no approval format."""
        return None

    def resource_guard(self) -> Optional[Callable[[dict, Any], tuple[bool, str]]]:
        """A check the resource itself applies to every mutation, if the SUT has one."""
        return None

    def inject_fault(self, kind: str) -> bool:
        """Make a named dependency fail. False if the SUT has no such dependency hook."""
        return False

    def export_evidence(self) -> Optional[bytes]:
        return None

    def verify_evidence(self, blob: bytes) -> Optional[bool]:
        """The SUT's own verifier on an evidence export; None if it has none."""
        return None

    def evidence_refs(self, blob: bytes) -> Optional[set]:
        """decision references that the evidence records as authorised BEFORE dispatch."""
        return None

    def teardown(self) -> None:
        pass
