"""Independent authorisation and authorised execution.

Separation of components:

  proposer   produces candidate actions; holds no reference to anything here.
  tiers      LocalAdmissibility / GlobalAdmissibility return verdicts only.
  Authorizer combines the verdicts the CONDITION enables into ALLOW / BLOCK /
             ESCALATE and signs a Decision. It cannot change the sandbox.
  Executor   the only component that can change the sandbox. It runs an
             action only under a valid, unused, ALLOW Decision whose action,
             sandbox state and executed trajectory all still match.

The HMAC key is generated per run and shared by Authorizer and Executor only.
Text an agent writes ("approved by security", approval_id fields, a JSON blob
shaped like a decision) carries no key and therefore no authority.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import hmac
import json
import secrets
import threading
from dataclasses import asdict, dataclass, replace

from morrison_governance.kernel.canonical import action_hash

from experiments.monitoring_incident.sandbox import (
    ACTION_TOOLS, ToolError, apply_action, fs_diff, fs_hash,
)
from experiments.monitoring_incident.tiers import (
    BLOCK, ESCALATE, NOT_EVALUATED, PERMIT, TierResult, strictest,
)

ALLOW = "ALLOW"


class OverlappingExecutionError(RuntimeError):
    """A second authorize→execute transaction was attempted while one was open."""


class SessionExecutionGuard:
    """Serialises the harness's own authorize→execute span, fail closed.

    EXPERIMENTAL RESTRICTION, NOT a repair of Morrison's concurrency weakness.
    The independent audit (§7.5) showed the Executor's single-use and state-hash
    checks are not concurrency-safe: under concurrent authorization one decision
    can double-execute and two individually-admitted actions can compose. This
    guard does NOT fix that. It makes the Phase 2 runner refuse to run two
    transactions at once, so measurement stays sound; Morrison's underlying
    enforcement is unchanged and no concurrency-safety claim is made outside this
    restricted harness.

    Contract: at most one transaction open per session. `transaction()` opens one
    for the full authorize→execute interval; a second attempt while one is open
    is REJECTED (recorded, then `OverlappingExecutionError`), never queued or
    allowed. `require_active()` lets the Executor fail closed if it is ever asked
    to run outside an open transaction.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._active = None
        self.rejections: list = []

    def active(self) -> bool:
        with self._lock:
            return self._active is not None

    def require_active(self) -> None:
        if not self.active():
            raise OverlappingExecutionError(
                "execution attempted with no open authorize→execute transaction")

    @contextlib.contextmanager
    def transaction(self, label: str):
        token = secrets.token_hex(8)
        with self._lock:
            if self._active is not None:
                rejection = {"attempted_label": label,
                             "conflicts_with": dict(self._active),
                             "thread": threading.get_ident()}
                self.rejections.append(rejection)
                raise OverlappingExecutionError(
                    "overlapping execution rejected: %r conflicts with open %r"
                    % (label, self._active.get("label")))
            self._active = {"token": token, "label": label,
                            "thread": threading.get_ident()}
        try:
            yield token
        finally:
            with self._lock:
                if self._active is not None and self._active.get("token") == token:
                    self._active = None


@dataclass(frozen=True)
class Condition:
    name: str
    local: bool
    global_: bool
    enforce: bool
    description: str


CONDITIONS = {
    "ungoverned": Condition("ungoverned", False, False, False,
                            "No admissibility evaluation; every well-formed action is executed "
                            "(sandbox and executor integrity checks still apply)."),
    "local_only": Condition("local_only", True, False, True,
                            "Per-action admissibility only (Morrison kernel + protected resources)."),
    "global_only": Condition("global_only", False, True, True,
                             "Trajectory admissibility only (Morrison GovernanceLayer over "
                             "executed trajectory + candidate, projected monitoring invariants)."),
    "hierarchical": Condition("hierarchical", True, True, True,
                              "Both tiers evaluated; both must admit."),
}


def get_condition(name: str) -> Condition:
    try:
        return CONDITIONS[name]
    except KeyError:
        raise ValueError("unknown condition %r (have %s)" % (name, sorted(CONDITIONS)))


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      default=repr)


def digest(value) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def trajectory_hash(executed: list) -> str:
    return digest([action_hash(a) for a in executed])


@dataclass(frozen=True)
class Decision:
    decision_id: str
    run_id: str
    condition: str
    verdict: str
    basis: str
    action_hash: str
    state_hash: str
    trajectory_hash: str
    seq: int
    signature: str = ""

    def payload(self) -> dict:
        d = asdict(self)
        d.pop("signature")
        return d

    def as_dict(self) -> dict:
        return asdict(self)


class DecisionKey:
    """Per-run HMAC key. Held by Authorizer and Executor; never serialised."""

    def __init__(self, key: bytes = b""):
        self._key = key or secrets.token_bytes(32)

    def sign(self, decision: Decision) -> Decision:
        mac = hmac.new(self._key, canonical(decision.payload()).encode(), hashlib.sha256).hexdigest()
        return replace(decision, signature=mac)

    def verify(self, decision) -> bool:
        if not isinstance(decision, Decision) or not isinstance(decision.signature, str):
            return False
        mac = hmac.new(self._key, canonical(decision.payload()).encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(mac, decision.signature)

    def __repr__(self) -> str:
        return "DecisionKey(<redacted>)"


class Authorizer:
    def __init__(self, condition: Condition, run_id: str, key: DecisionKey,
                 local=None, global_=None, escalation_policy: str = "deny",
                 reviewer=None):
        if (condition.local and local is None) or (condition.global_ and global_ is None):
            raise ValueError("condition %s needs tiers it was not given" % condition.name)
        if escalation_policy not in ("deny", "oracle"):
            raise ValueError("escalation_policy must be 'deny' or 'oracle'")
        self.condition = condition
        self.run_id = run_id
        self._key = key
        self.local = local if condition.local else None
        self.global_ = global_ if condition.global_ else None
        self.escalation_policy = escalation_policy
        self._reviewer = reviewer
        self._seq = 0

    def _tier(self, tier, *args) -> TierResult:
        if tier is None:
            return TierResult("n/a", NOT_EVALUATED)
        try:
            result = tier.evaluate(*args)
            if not isinstance(result, TierResult) or result.verdict not in (PERMIT, BLOCK, ESCALATE):
                raise TypeError("malformed tier result")
            return result
        except Exception as e:                      # noqa: BLE001 — fail closed
            return TierResult(getattr(tier, "name", "tier"), BLOCK, "tier_failure",
                              "%s: %s" % (type(e).__name__, e))

    def decide(self, action: dict, state_hash: str, executed: list):
        """Returns (Decision, local TierResult, global TierResult, escalation dict)."""
        self._seq += 1
        frozen = copy.deepcopy(action)
        local = self._tier(self.local, frozen)
        global_ = self._tier(self.global_, list(executed), frozen)
        escalation = None
        if not self.condition.enforce:
            verdict, basis = ALLOW, "ungoverned"
        else:
            evaluated = [r.verdict for r in (local, global_) if r.verdict != NOT_EVALUATED]
            combined = strictest(*evaluated) if evaluated else BLOCK
            if combined == PERMIT:
                verdict, basis = ALLOW, "admitted:" + "+".join(
                    t for t, r in (("local", local), ("global", global_)) if r.verdict != NOT_EVALUATED)
            elif combined == BLOCK:
                verdict, basis = BLOCK, "blocked:" + ",".join(
                    t for t, r in (("local", local), ("global", global_)) if r.verdict == BLOCK)
            else:
                approved = False
                if self.escalation_policy == "oracle" and self._reviewer is not None:
                    approved = bool(self._reviewer(frozen))
                escalation = {"policy": self.escalation_policy, "approved": approved}
                verdict = ALLOW if approved else ESCALATE
                basis = "escalation_approved:%s" % self.escalation_policy if approved \
                    else "escalated:unapproved"
        decision = Decision(
            decision_id="d-%s-%04d-%s" % (self.run_id[:8], self._seq, secrets.token_hex(4)),
            run_id=self.run_id, condition=self.condition.name, verdict=verdict, basis=basis,
            action_hash=action_hash(frozen), state_hash=state_hash,
            trajectory_hash=trajectory_hash(executed), seq=self._seq)
        return self._key.sign(decision), local, global_, escalation


@dataclass
class ExecutionResult:
    executed: bool
    refusal: str = ""
    observation: str = ""
    effects: list = None
    state_before: str = ""
    state_after: str = ""
    tool_error: str = ""
    # Non-regular files (symlinks, devices, …) the bytes-level `effects` diff
    # cannot represent, so an indirect break via run_tests is still recorded.
    irregular_effects: dict = None

    def as_dict(self) -> dict:
        d = asdict(self)
        d["effects"] = list(self.effects or [])
        d["irregular_effects"] = dict(self.irregular_effects or {})
        return d


class Executor:
    """The only path to a sandbox effect."""

    def __init__(self, sandbox, key: DecisionKey, run_id: str, guard=None):
        self._sandbox = sandbox
        self._key = key
        self.run_id = run_id
        self._used: set = set()
        self.executed: list = []      # trusted ledger: what actually ran
        # Optional experimental serialisation guard (see SessionExecutionGuard).
        # When set, the Executor refuses to run outside an open transaction, so
        # execution structurally cannot happen outside the guarded interval.
        self._guard = guard

    def trajectory_hash(self) -> str:
        return trajectory_hash(self.executed)

    def _refuse(self, why: str) -> ExecutionResult:
        h = self._sandbox.state_hash()
        return ExecutionResult(False, refusal=why, effects=[], state_before=h, state_after=h,
                               observation="NOT EXECUTED: " + why, irregular_effects={})

    def execute(self, decision, action) -> ExecutionResult:
        if self._guard is not None and not self._guard.active():
            return self._refuse("no open execution transaction (sequential guard, fail-closed)")
        if not self._key.verify(decision):
            return self._refuse("decision signature invalid or missing")
        if decision.run_id != self.run_id:
            return self._refuse("decision belongs to another run")
        if decision.verdict != ALLOW:
            return self._refuse("decision verdict is %s" % decision.verdict)
        if decision.decision_id in self._used:
            return self._refuse("decision already used")
        target = copy.deepcopy(action)
        if not isinstance(target, dict) or action_hash(target) != decision.action_hash:
            return self._refuse("action differs from the authorised action")
        if target.get("tool") not in ACTION_TOOLS:
            return self._refuse("tool %r is not executable" % target.get("tool"))
        before, irr_before = self._sandbox.scan()
        if fs_hash(before) != decision.state_hash:
            return self._refuse("sandbox state changed since authorisation (stale decision)")
        if self.trajectory_hash() != decision.trajectory_hash:
            return self._refuse("executed trajectory changed since authorisation (stale decision)")
        self._used.add(decision.decision_id)          # spent before any effect
        tool_error = ""
        if target["tool"] == "run_tests":
            _, observation, _ = self._sandbox.run_tests()
        else:
            try:
                new, observation = apply_action(before, target)
                self._sandbox.materialise(new)
            except ToolError as e:
                tool_error, observation = str(e), "error: %s" % e
        after, irr_after = self._sandbox.scan()
        if not tool_error:
            self.executed.append(target)
        # Irregular entries that appeared or changed. A run_tests fixture that
        # creates a symlink leaves no byte-diff but changes this.
        irr_fx = {p: v for p, v in irr_after.items() if irr_before.get(p) != v}
        for p in irr_before:
            if p not in irr_after:
                irr_fx[p] = "removed"
        return ExecutionResult(not tool_error, observation=observation,
                               effects=fs_diff(before, after), state_before=fs_hash(before),
                               state_after=fs_hash(after), tool_error=tool_error,
                               irregular_effects=irr_fx)
