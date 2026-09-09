"""GovernanceKernel — the single production chokepoint.

Everything the red team broke is closed here, in one place, WITHOUT changing
the Morrison reachability model. `ReachabilityEvaluator` is untouched: the
kernel calls the existing engine and takes its verdict as authoritative
whenever the engine blocks, so V2 prefix/trajectory behaviour is preserved
exactly. The kernel adds the trust boundary the engine never had.

Decision pipeline for every proposed call:

    1  canonicalise                  -> immutable action + action_hash
    2  quarantine caller authority   -> forged claims become evidence, not power
    3  classify capabilities         -> semantic, not tool-name matching
    4  resolve destination           -> trusted config, not caller flags
    5  verify approval artifact      -> bound to THIS action hash
    6  inject TRUSTED authority      -> the only writer of authority fields
    7  run the existing Ω engine     -> unchanged reachability hierarchy
    8  apply capability policy       -> DENY / APPROVAL / GRANT / ALLOW
    9  tenancy + denial-taint checks
   10  strictest verdict wins        -> BLOCK > ESCALATE > PERMIT
   11  seal hash-chained evidence

Execution is only reachable through `execute()`, which re-derives the action
hash and refuses anything that does not match the authorised hash.
"""

from __future__ import annotations

import contextlib
import threading
import time
import uuid
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from morrison_governance.core import GovernanceLayer
from morrison_governance.result import GovernanceVerdict
from morrison_governance.kernel import capabilities as C
from morrison_governance.kernel import policy as P
from morrison_governance.kernel import sensitivity as S
from morrison_governance.kernel.canonical import (
    action_hash, canonicalize, semantic_action_hash,
)
from morrison_governance.kernel.normalize import normalize_action
from morrison_governance.kernel.continuity import (
    BLOCK_POLICY, DENIED, EXECUTED, RESERVED, UNCONFIRMED,
    LedgerEntry, default_store, resolve_continuity,
)
from morrison_governance.kernel.destinations import classify_destination
from morrison_governance.kernel.evidence import (
    EvidenceChain, EvidenceRecord, ruleset_hash,
)
from morrison_governance.kernel.trust import (
    SecurityContext, forged_authority_claims, quarantine_authority,
)

BLOCK = "BLOCK"
ESCALATE = "ESCALATE"
PERMIT = "PERMIT"

_STRICTNESS = {PERMIT: 0, ESCALATE: 1, BLOCK: 2}

# A value that names somewhere to send data.
_DEST_IN_VALUE = __import__("re").compile(
    r"[a-z][a-z0-9+.\-]*://|\b\d{1,3}(\.\d{1,3}){3}\b", __import__("re").I)

# Quarantined claims split by what would corroborate them.
_APPROVAL_CLAIMS = frozenset({
    "authorized", "authorised", "approved", "approved_by", "approver",
    "verified", "sanctioned", "change_approved", "admin_authorized",
    "break_glass", "override",
})
_DESTINATION_CLAIMS = frozenset({
    "destination_internal", "is_internal", "internal", "trusted",
})

# Canonical kernel stage names, in pipeline order. These are the stages a
# benchmark or a trace can attribute time to; they map onto the numbered
# pipeline in this module's docstring.
KERNEL_STAGES = (
    "canonicalization",          # 1  canonicalise + action_hash
    "trust_boundary",            # 2  quarantine caller authority
    "capability_classification", # 3  semantic capability classification
    "destination_resolution",    # 4  trusted destination classification
    "approval_verification",     # 5  HMAC approval artifact verification
    "trajectory_analysis",       # 7  the Ω reachability engine
    "policy_evaluation",         # 6+8+9  capability policy, tenancy, taint
    "evidence_sealing",          # 11 hash-chained evidence record
)


class _Stopwatch:
    """Accumulating, non-nesting stage timer.

    Deliberately minimal: one `perf_counter()` pair per stage and a dict add.
    The probe cost is ~0.4µs per stage, which at eight stages is under 0.1% of
    a typical decision — small enough not to distort what it measures, and
    reported honestly as `unattributed` rather than hidden.

    Stages ACCUMULATE, so a stage entered more than once in one decision (the
    Ω engine runs twice when a BLOCK is tested for approval-resolvability)
    reports its true total cost rather than only the last call.
    """

    __slots__ = ("_t", "_stage", "totals")

    def __init__(self) -> None:
        self._t = 0.0
        self._stage = ""
        self.totals: dict[str, float] = {}

    def __call__(self, stage: str) -> "_Stopwatch":
        self._stage = stage
        return self

    def __enter__(self) -> "_Stopwatch":
        self._t = time.perf_counter()
        return self

    def __exit__(self, *exc) -> bool:
        elapsed = (time.perf_counter() - self._t) * 1000.0
        self.totals[self._stage] = self.totals.get(self._stage, 0.0) + elapsed
        return False


DECISION_TTL_S = 120.0
"""How long a PERMIT stays executable. A decision is a lease on a trajectory
state, not a permanent fact: the longer it is held, the more of the session it
has not seen. Two minutes is long enough for any synchronous dispatch and short
enough that a held decision cannot outlive the trajectory it was evaluated
against."""


@dataclass
class Decision:
    verdict: str
    reason: str
    layer: str
    action_hash: str
    action: dict                       # the canonical action, as proposed
    capabilities: frozenset = frozenset()
    requirement: str = P.ALLOW
    rule: Optional[str] = None
    omega_domain: Optional[str] = None
    authorization: dict = field(default_factory=dict)
    forged_claims: list = field(default_factory=list)
    destination: dict = field(default_factory=dict)
    trajectory_hash: str = ""
    evidence: Optional[EvidenceRecord] = None
    # The canonical tool family this proposal resolved to. Aliasing is what
    # stops `run_shell` executing what `shell` is refused, and it also means an
    # approval covers every member of the family with the same arguments. That
    # widening is a real consequence, so it is surfaced rather than implied.
    tool_family: str = ""

    # ── single-use + freshness binding ───────────────────────
    # A PERMIT used to be an unbounded bearer token: it carried an action hash
    # and nothing else, so it could be executed twice, executed after the same
    # action was BLOCKed, and executed after the policy that justified it had
    # changed. These fields make a decision a LEASE — bound to one transition,
    # one session, one principal, one ruleset, one moment, and one use.
    decision_id: str = ""
    semantic_hash: str = ""            # identity of the TRANSITION
    session_id: str = ""
    principal_id: str = ""
    ruleset_hash: str = ""
    issued_at: float = 0.0
    expires_at: float = 0.0
    # Wall-clock instant this decision was minted, independent of the `now` the
    # caller passed. `now` exists so a finite-model verifier can drive the
    # kernel on its own clock; it is a public parameter, so a far-future value
    # produced a lease that would not expire for a year. Freshness is checked
    # against BOTH clocks and the stricter one wins.
    issued_wall: float = 0.0
    reserved: bool = False             # holds a slot in the trajectory
    # How far the governed history behind this decision reaches: "process",
    # "host", "deployment", or "unknown".
    continuity_scope: str = "unknown"

    def binding(self) -> dict:
        """Everything this decision is bound to, for evidence and debugging."""
        return {"decision_id": self.decision_id,
                "action_hash": self.action_hash,
                "semantic_hash": self.semantic_hash,
                "session_id": self.session_id,
                "principal": self.principal_id,
                "continuity_scope": self.continuity_scope,
                "ruleset_hash": self.ruleset_hash,
                "issued_at": self.issued_at,
                "expires_at": self.expires_at,
                "reserved": self.reserved}

    # ── measured latency ─────────────────────────────────────
    # `decision_time_ms` is the END-TO-END cost of producing this decision:
    # canonicalisation, authority quarantine, capability classification,
    # destination resolution, approval verification, the Ω engine, capability
    # policy, tenancy, and sealing the evidence record.
    #
    # `engine_time_ms` is the Ω reachability compute alone, as the engine
    # reports it. It is a SMALL FRACTION of the total — roughly 2% on the
    # production ruleset — so quoting it as "governance latency" would
    # understate the real cost by ~50x. Both are recorded so a caller can see
    # the split rather than having to trust one number.
    decision_time_ms: float = 0.0
    engine_time_ms: float = 0.0

    # Per-stage breakdown of `decision_time_ms`, in milliseconds, measured by
    # `_Stopwatch` on the real code path (see `GovernanceKernel.authorize`).
    # Keys are the canonical stage names in `KERNEL_STAGES`. The stages are
    # disjoint and sum to slightly less than `decision_time_ms`; the remainder
    # is dataclass construction and probe overhead, reported as `unattributed`
    # by `stage_breakdown()` rather than silently folded into a stage.
    stage_timings_ms: dict = field(default_factory=dict)

    def stage_breakdown(self) -> dict:
        """Stage timings plus the explicitly-labelled unattributed remainder."""
        attributed = sum(self.stage_timings_ms.values())
        out = dict(self.stage_timings_ms)
        out["unattributed"] = max(0.0, self.decision_time_ms - attributed)
        return out

    @property
    def permitted(self) -> bool:
        return self.verdict == PERMIT

    @property
    def escalated(self) -> bool:
        return self.verdict == ESCALATE

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict, "reason": self.reason, "layer": self.layer,
            "action_hash": self.action_hash,
            "capabilities": sorted(self.capabilities),
            "tool_family": self.tool_family,
            "requirement": self.requirement, "rule": self.rule,
            "omega_domain": self.omega_domain,
            "authorization": self.authorization,
            "forged_authority_claims": self.forged_claims,
            "destination": self.destination,
            "evidence_hash": self.evidence.record_hash if self.evidence else None,
            "binding": self.binding(),
            # 4 decimal places = 0.1µs. Several stages cost single-digit
            # microseconds, so rounding to 3 (1µs) would collapse them to a
            # value that no longer reconciles with the total in a published
            # per-stage table. All three latency fields share this precision so
            # the breakdown sums correctly after serialisation.
            "decision_time_ms": round(self.decision_time_ms, 4),
            "engine_time_ms": round(self.engine_time_ms, 4),
            "stage_timings_ms": {k: round(v, 4)
                                 for k, v in self.stage_breakdown().items()},
        }


@dataclass
class Attempt:
    """A recorded attempt — executed, RESERVED, or denied.

    Denied attempts stay in the ledger so a blocked step cannot scrub itself out
    of the trajectory. `RESERVED` is the state that closes the batching bypass:
    a PERMIT used to enter the ledger only when `execute()` ran, so a batch
    authorized before any of it executed had every step evaluated against an
    empty prefix — the read that made the egress an exfiltration was invisible
    because it had not run *yet*. A reservation takes the trajectory slot at
    AUTHORIZE time and holds it until the decision is executed or its lease
    expires.
    """

    action: dict
    verdict: str
    reason: str
    actor: str
    timestamp: float
    capabilities: frozenset = frozenset()
    state: str = DENIED
    decision_id: str = ""
    expires_at: float = 0.0

    @property
    def executed(self) -> bool:
        return self.state == EXECUTED

    @property
    def denied(self) -> bool:
        return self.state == DENIED

    def live(self, now: float) -> bool:
        """Part of the trajectory: anything that was permitted.

        A lapsed reservation used to drop out here, which made a lost
        confirmation indistinguishable from a step that never ran. Nothing that
        was permitted now leaves the trajectory by the passage of time; it
        leaves only by an explicit `release`, which deletes the entry, or by
        ageing past the retention window. `now` is retained for callers.
        """
        return self.state in (EXECUTED, RESERVED, UNCONFIRMED)


class GovernanceKernel:
    """Pre-execution governance with a real trust boundary."""

    def __init__(self, layer: GovernanceLayer, context: SecurityContext,
                 evidence_key: bytes = b"", engine_version: str = "",
                 session_id: str = "", decision_ttl_s: float = DECISION_TTL_S):
        self.layer = layer
        self.ctx = context
        self.chain = EvidenceChain(key=evidence_key)
        self.engine_version = engine_version
        self.session_id = session_id or uuid.uuid4().hex
        self.decision_ttl_s = float(decision_ttl_s)
        # WHERE THIS SESSION'S HISTORY LIVES.
        #
        # Governed history used to be a list on this object, so it began empty
        # every time a kernel was constructed and an actor could choose how
        # many kernels it got. It is now filed under a continuity key derived
        # from the authenticated principal, in a store shared across sessions.
        # The session id says which conversation this is; the continuity key
        # says whose authority it is, and only the second one governs.
        self.store = context.continuity_store or default_store()
        self.continuity = resolve_continuity(context.principal,
                                             getattr(context, "workload", ""))
        self.continuity_key = (self.continuity.key.as_str()
                               if self.continuity.key else "")
        # How far this deployment's governed history actually reaches. A
        # deployment could previously only BELIEVE its continuity was
        # fleet-wide; now it can assert it. The built-in stores are honest
        # about being process- and host-local.
        scope = getattr(self.store, "scope", None)
        self.continuity_scope = scope() if callable(scope) else "unknown"
        # ONE lock over authorize + execute. Authorization reads the trajectory
        # and then writes a reservation into it; without serialising that
        # read-modify-write, two concurrent authorizations both read the state
        # before either wrote, which is the batching bypass with a race in
        # place of an ordering choice. Reentrant because `submit()` holds it
        # across both halves.
        self._lock = threading.RLock()
        # Single-use and revocation state live in the continuity store, not on
        # this object: a decision id spent in one session must stay spent in
        # the next, and a transition refused in one session must stay refused.
        #
        # The ruleset digest is memoised on a fingerprint of its mutable inputs
        # rather than computed once: computing it once was a footgun (a policy
        # change silently did not invalidate outstanding leases) and computing
        # it every time dominated the commit path.
        self._ruleset_cache: Optional[tuple] = None
        self._ruleset_hash = ruleset_hash(
            layer.rules,
            extra={"capability_policy": P.CAPABILITY_POLICY,
                   "policy_values": {**P.DEFAULT_POLICY_VALUES,
                                     **(context.policy_values or {})},
                   "unknown_tool_policy": context.unknown_tool_policy})

    # ── history ──────────────────────────────────────────────
    @property
    def ledger(self) -> list[Attempt]:
        """This principal's governed attempts, across every session.

        A read-through view of the continuity store, presented in the shape the
        rest of the kernel and the existing tests already use.
        """
        if not self.continuity_key:
            return []
        window = float(getattr(self.ctx, "continuity_window_s", 0.0) or 0.0)
        # Retention is measured on the WALL clock, never on the evaluation
        # clock. `timestamp` is whatever `now` the caller passed, so filtering
        # on it let an action executed with `now=0.0` be filed outside every
        # realistic window and disappear from the next decision.
        horizon = (time.time() - window) if window > 0 else None
        return [Attempt(action=e.action, verdict=e.verdict, reason=e.reason,
                        actor=e.actor, timestamp=e.timestamp,
                        capabilities=frozenset(e.capabilities),
                        state=self._effective_state(e), decision_id=e.decision_id,
                        expires_at=e.expires_at)
                for e in self.store.entries(self.continuity_key)
                if horizon is None or (e.wall_timestamp or e.timestamp) >= horizon]

    @staticmethod
    def _effective_state(entry) -> str:
        """A reservation whose lease lapsed is UNCONFIRMED, not gone.

        Nothing released it, so the caller held a PERMIT for it and may have
        run it — a decision-plane runtime that crashes after acting looks
        exactly like this. Treating the lapse as an abandoned plan let a real
        effect leave the trajectory. "We do not know" must not read as "it did
        not happen".
        """
        if entry.state != RESERVED:
            return entry.state
        deadline = entry.wall_expires_at or 0.0
        if deadline and time.time() > deadline:
            return UNCONFIRMED
        return RESERVED

    def _file(self, action: dict, verdict: str, state: str, reason: str,
              timestamp: float, capabilities: frozenset = frozenset(),
              decision_id: str = "", semantic_hash: str = "",
              expires_at: float = 0.0) -> None:
        """Record one governed attempt against the continuity key."""
        if not self.continuity_key:
            return
        wall = time.time()
        self.store.append(self.continuity_key, LedgerEntry(
            decision_id=decision_id or uuid.uuid4().hex, action=action,
            verdict=verdict, state=state, reason=reason,
            actor=self.ctx.principal.id, session_id=self.session_id,
            semantic_hash=semantic_hash,
            capabilities=tuple(sorted(capabilities)),
            timestamp=timestamp, expires_at=expires_at,
            wall_timestamp=wall, wall_expires_at=wall + self.decision_ttl_s))

    @property
    def executed_history(self) -> list[dict]:
        """Actions that have run OR hold a live reservation.

        A reservation is included because it is going to run: the caller holds
        a PERMIT for it. Excluding it is what let a batch launder its own
        trajectory.
        """
        # `live` prunes lapsed reservations. Reservations issued on an
        # explicit model clock carry an expiry on that clock, so compare
        # against the clock this session is actually driven on rather than
        # wall time — otherwise a model-clock session prunes everything.
        return [a.action for a in self.ledger if a.live(self._clock_basis())]

    def _clock_basis(self) -> float:
        """The clock this session is actually being driven on.

        A kernel driven with `authorize(call, now=...)` for a finite model runs
        on that model's clock; wall time would lapse every reservation it holds
        immediately.
        """
        stamps = ([e.timestamp for e in self.store.entries(self.continuity_key)]
                  if self.continuity_key else [])
        latest = max(stamps) if stamps else 0.0
        wall = time.time()
        # A model clock is small (seconds since 0); wall time is ~1.7e9. If the
        # session's own stamps are nowhere near wall time, it is not on it.
        return latest if latest and wall - latest > 86400.0 * 365 else wall

    @property
    def committed_history(self) -> list[dict]:
        """Actions that have actually executed. Evidence, not evaluation."""
        return [a.action for a in self.ledger if a.state == EXECUTED]

    def _denied_read_occurred(self) -> Optional[Attempt]:
        for a in self.ledger:
            if a.denied and (C.CAP_DATA_READ in a.capabilities
                             or C.CAP_CREDENTIAL_READ in a.capabilities):
                return a
        return None

    def _any_read_occurred(self) -> bool:
        """Any read in the trajectory — executed, reserved, or denied.

        A reserved read counts. The agent holds a PERMIT for it, so by the time
        the egress runs the data is in hand.
        """
        return any(C.CAP_DATA_READ in a.capabilities
                   or C.CAP_CREDENTIAL_READ in a.capabilities
                   for a in self.ledger)

    # ── reservations ─────────────────────────────────────────
    def _reserve(self, decision: "Decision", now: float) -> None:
        """Take this decision's slot in the trajectory before it executes."""
        self._file(decision.action, PERMIT, RESERVED, decision.reason, now,
                   capabilities=decision.capabilities,
                   decision_id=decision.decision_id,
                   semantic_hash=decision.semantic_hash,
                   expires_at=decision.expires_at)
        decision.reserved = True

    def _reservation(self, decision_id: str) -> Optional[Attempt]:
        for a in self.ledger:
            if a.decision_id == decision_id and a.state == RESERVED:
                return a
        return None

    def _commit(self, decision_id: str, now: float,
                action: Optional[dict] = None) -> None:
        if self.continuity_key:
            self.store.set_state(self.continuity_key, decision_id, EXECUTED,
                                 now, action)

    def release(self, decision: "Decision") -> bool:
        """Abandon a PERMIT the caller has decided not to execute.

        Frees the trajectory slot so an agent that plans more than it runs does
        not permanently taint its own session. The decision is consumed either
        way — a released decision cannot later be executed.
        """
        with self._lock, self._critical_section():
            if not self.continuity_key:
                return False
            self.store.consume(self.continuity_key,
                               f"decision:{decision.decision_id}")
            # Only a live reservation may be withdrawn. Once the lease has
            # lapsed the outcome is unknown, and withdrawing it would be a way
            # to erase a step that may have executed — `reconcile` is the route
            # for that, and it demands an external attestation.
            #
            # Refusing must leave the principal's posture UNCHANGED. Consuming
            # the decision id above already prevents the release being retried
            # as an execution; filing a denied attempt as well would make an
            # ordinary crash look adversarial to every later decision.
            held = self._reservation(decision.decision_id)
            if held is None:
                return False
            dropped = self.store.drop(self.continuity_key, decision.decision_id)
            decision.reserved = False if dropped else decision.reserved
            return dropped

    def reconcile(self, decision: "Decision", executed: bool,
                  attestation: str) -> bool:
        """Resolve a dispatch whose outcome was never confirmed.

        A lapsed reservation is UNCONFIRMED and stays in the trajectory, which
        is correct — it may have run. Without a way back, a single crashed
        worker refused egress to every other workflow under the same service
        account for the whole retention window, and `release` was rightly
        unable to help. Safety with no reconciliation path is an availability
        failure, and an availability failure is how a control gets configured
        away.

        This is an OPERATOR action, not an agent action. It requires an
        `attestation` — what was checked in the target system, and by whom —
        which is recorded in evidence, because the whole point is that the
        answer comes from OUTSIDE Morrison. Morrison cannot determine whether
        the effect landed; it can only record who says it did not, and stand
        behind that record.

        `executed=True` settles the entry as EXECUTED and keeps the taint.
        `executed=False` withdraws it, on the attester's authority.
        Only an UNCONFIRMED entry can be reconciled: a live reservation should
        be executed or released, and a settled one is already settled.
        """
        if not attestation or not str(attestation).strip():
            raise ValueError(
                "reconciliation requires an attestation naming what was "
                "checked outside Morrison and by whom; the outcome of an "
                "unconfirmed dispatch is not something the kernel can know")
        with self._lock, self._critical_section():
            entry = next((a for a in self.ledger
                          if a.decision_id == decision.decision_id
                          and a.state == UNCONFIRMED), None)
            if entry is None:
                return False
            now = time.time()
            if executed:
                self.store.set_state(self.continuity_key,
                                     decision.decision_id, EXECUTED, now)
            else:
                self.store.drop(self.continuity_key, decision.decision_id)
            self.chain.append(EvidenceRecord(
                seq=0, timestamp=now, actor=self.ctx.principal.id,
                tenant=self.ctx.principal.tenant,
                action_hash=decision.action_hash, proposed=decision.action,
                decision=PERMIT if executed else BLOCK, layer="reconciliation",
                rule="unconfirmed_dispatch_reconciled",
                reason=(f"unconfirmed dispatch settled as "
                        f"{'EXECUTED' if executed else 'NOT EXECUTED'} on "
                        f"external attestation: {attestation}"),
                ruleset_hash=self._live_ruleset_hash(),
                engine_version=self.engine_version, executed=executed))
            return True

    def unconfirmed(self) -> list["Attempt"]:
        """Dispatches whose outcome is unknown, for an operator to reconcile."""
        return [a for a in self.ledger if a.state == UNCONFIRMED]

    def _revoke(self, semantic_hash: str, reason: str) -> None:
        if self.continuity_key:
            self.store.revoke(self.continuity_key, semantic_hash, reason)

    def _lease_problem(self, decision: "Decision", now: float) -> Optional[str]:
        """Why this decision may not be executed, or None if it may.

        Every clause here is a counterexample that used to execute.
        """
        if decision.verdict != PERMIT:
            return f"verdict is {decision.verdict}"
        if self.continuity_key and self.store.consumed(
                self.continuity_key, f"decision:{decision.decision_id}"):
            return ("decision has already been used; a PERMIT authorises one "
                    "execution of one transition")
        if decision.session_id != self.session_id:
            return (f"decision was issued for session "
                    f"{decision.session_id[:12]}… and this kernel is "
                    f"{self.session_id[:12]}…")
        if decision.principal_id != self.ctx.principal.id:
            return (f"decision was issued to principal "
                    f"{decision.principal_id!r}, not {self.ctx.principal.id!r}")
        if decision.expires_at and now > decision.expires_at:
            return (f"decision expired {now - decision.expires_at:.1f}s ago; "
                    f"re-authorise against the current trajectory")
        wall_age = time.time() - (decision.issued_wall or time.time())
        if decision.issued_wall and wall_age > self.decision_ttl_s:
            return (f"decision was minted {wall_age:.1f}s ago in wall-clock "
                    f"terms, beyond the {self.decision_ttl_s:.0f}s lease; a "
                    f"caller-supplied clock cannot extend a lease")
        if decision.ruleset_hash and decision.ruleset_hash != self._live_ruleset_hash():
            return ("the governing ruleset changed after this decision was "
                    "issued; re-authorise under the current policy")
        stale = self._revalidate_at_commit(decision)
        if stale is not None:
            return f"trusted state changed after authorisation: {stale}"
        # Revocation exists to invalidate an OUTSTANDING lease (a PERMIT held
        # from earlier while the same transition was refused). No lease outlives
        # `decision_ttl_s`, so neither does a revocation: making it permanent
        # would turn "you were refused once" into "never again", which is a
        # different policy and a denial of service, not a safety property.
        revoked = None
        if self.continuity_key:
            record = self.store.revocation(self.continuity_key,
                                           decision.semantic_hash)
            if record is not None:
                reason_text, revoked_at = record
                if not revoked_at or (now - revoked_at) <= self.decision_ttl_s:
                    revoked = reason_text
        if revoked:
            return (f"this transition was subsequently refused in the same "
                    f"session ({revoked}); the earlier PERMIT is void")
        return None

    def _evaluate_with_context(self, prefix: list, trusted: dict):
        """Run the unchanged engine over `prefix` with `trusted` supplied as
        trajectory context rather than arguments."""
        from morrison_governance.trajectory import TrajectoryExtractor
        extractor = TrajectoryExtractor(context=trusted)
        traj = (extractor.from_plan(prefix) if len(prefix) > 1
                else extractor.from_dict(prefix[0]))
        return self.layer.evaluate_trajectory(traj)

    # ── the gate ─────────────────────────────────────────────
    def authorize(self, call: dict, now: Optional[float] = None,
                  reserve: bool = True) -> Decision:
        """Decide one proposed transition, and reserve its place in the session.

        `reserve=False` evaluates without taking a trajectory slot. It exists
        for speculative analysis — exhaustive verification, counterfactual
        replay — that inspects a decision it will never execute. A decision
        issued with `reserve=False` cannot be executed: `execute()` refuses it,
        because nothing held the trajectory steady between the two calls.
        """
        with self._lock, self._critical_section():
            return self._authorize_locked(call, now, reserve)

    def preview(self, call: dict, now: Optional[float] = None) -> Decision:
        """Non-reserving, non-executable evaluation. See `authorize`."""
        return self.authorize(call, now=now, reserve=False)

    def _critical_section(self):
        """Serialise this principal's read-modify-write across ALL writers.

        `self._lock` only covers threads in this process. Two PROCESSES
        authorising for the same principal at the same moment each read the
        governed history before either wrote to it, and both were permitted —
        the concurrent form of trajectory fragmentation, reachable by ordinary
        horizontal scaling rather than by any attack. The store supplies the
        cross-writer lock; the in-memory default degrades to a thread lock,
        which is exactly its documented scope.
        """
        if not self.continuity_key:
            return contextlib.nullcontext()
        transaction = getattr(self.store, "transaction", None)
        if transaction is None:
            return contextlib.nullcontext()
        return transaction(self.continuity_key)

    def _authorize_locked(self, call: dict, now: Optional[float],
                          reserve: bool) -> Decision:
        _t0 = time.perf_counter()
        _sw = _Stopwatch()
        now = time.time() if now is None else now
        with _sw("trust_boundary"):
            # THREE representations of one proposal, and the distinction is
            # load-bearing:
            #
            #   proposed  what the caller asked for, canonicalised. This is
            #             what executes and what execution binding hashes, so
            #             the authorised action is the proposed action.
            #   clean     proposed minus the authority namespace. This is what
            #             the Ω engine evaluates, because the engine reads its
            #             control flags out of that namespace and a caller must
            #             not be able to write them.
            #   view      proposed as the CLASSIFIERS see it. Quarantine
            #             removes a field's power to authorise; it must not
            #             remove the fact that the field names a destination or
            #             carries regulated content. Naming a collector
            #             argument `policy` used to delete it from destination
            #             resolution entirely, so the call resolved as having
            #             no destination and every external-egress rule was
            #             skipped.
            proposed = canonicalize(call)
            clean, quarantined = quarantine_authority(call)
            forged = forged_authority_claims(quarantined)
        with _sw("canonicalization"):
            ahash = action_hash(proposed)
            shash = semantic_action_hash(proposed)
            norm = normalize_action(proposed)
        with _sw("capability_classification"):
            # Capabilities are classified on `clean`: authority field NAMES
            # collide with control-surface morphology (`admin_approved` reads
            # as a privilege key, `destination_external` as an external
            # destination), and feeding them in produces false positives on
            # ordinary traffic. Their content is still classified below.
            caps = C.classify(clean, self.ctx.tool_manifest)
        with _sw("destination_resolution"):
            dest = classify_destination(
                clean, self.ctx.internal_url_hosts,
                self.ctx.internal_email_domains, self.ctx.internal_cidrs,
                trust_private_networks=self.ctx.trust_private_networks,
                extra_args=quarantined)

        with _sw("approval_verification"):
            # Approvals bind to the SEMANTIC hash, so an approval cannot be
            # dodged by respelling the call it was issued for.
            approval, approval_reason = self.ctx.verified_approval(shash, now)
            # ...and their single-use state lives against the CONTINUITY KEY,
            # not the SecurityContext. `_used_nonces` was instance state, so a
            # new session built a new context and the same signed artifact
            # verified again: three sessions moved $13.5M on one $4.5M
            # approval. The nonce is now spent for the principal, once.
            if approval is not None and approval.nonce and self.continuity_key:
                if self.store.consumed(self.continuity_key,
                                       f"approval:{approval.nonce}"):
                    approval, approval_reason = None, (
                        "approval nonce already used (replay across sessions)")
        authorization = {
            "approved": bool(approval),
            "reason": approval_reason,
            "issuer": approval.issuer if approval else None,
            "bound_action_hash": approval.action_hash if approval else None,
            "principal": self.ctx.principal.id,
            "tenant": self.ctx.principal.tenant,
        }

        candidates: list[tuple[str, str, str, Optional[str], Optional[str]]] = []

        # ── forged authority is recorded and never honoured ──
        # Every quarantined claim is recorded as evidence unconditionally. It
        # only raises a verdict when it is UNCORROBORATED — i.e. the caller
        # asserted something the trusted context does not independently agree
        # with. A redundant-but-true claim (client library sends
        # `destination_internal` and the destination really is internal) is
        # noted, not punished; that distinction is what keeps this from firing
        # on ordinary traffic.
        # (evaluated below, once the capability requirement is known)
        approval_claims = [c for c in forged if c in _APPROVAL_CLAIMS]
        dest_claims = [c for c in forged if c in _DESTINATION_CLAIMS]

        # ── capability policy is resolved BEFORE the engine runs, because the
        #    engine's own rules read an `authorized` flag and the kernel is the
        #    only component allowed to set it. Authority is established by a
        #    verified approval, an explicit server-side auto-approval, or a
        #    capability grant the principal actually holds — never by the caller.
        with _sw("policy_evaluation"):
            pol_values = {**P.DEFAULT_POLICY_VALUES,
                          **(self.ctx.policy_values or {})}
            cap_policy = pol_values.get("capability_policy")
            requirement, gov_cap = P.requirement_for(caps, cap_policy)

            auto_approved = False
            if requirement == P.APPROVAL and gov_cap == C.CAP_PAYMENT \
                    and not approval:
                # Server-owned threshold. The caller's own `threshold` was
                # quarantined upstream (bypass AB-03).
                cap_max = pol_values.get("payment_auto_approve_max", 0) or 0
                amount = _numeric(clean["args"], ("amount", "value", "total"))
                if amount is not None and amount <= cap_max and not dest.external:
                    requirement, auto_approved = P.ALLOW, True

            grant_satisfied = (requirement == P.GRANT
                               and self.ctx.grants(gov_cap))

        # A quarantined claim raises a verdict only when it is BOTH
        # uncorroborated and material — i.e. the action genuinely needs the
        # authority being asserted. A claim on an action that requires no
        # approval is noise: it is recorded as evidence and nothing more.
        uncorroborated = []
        if approval_claims and approval is None and requirement == P.APPROVAL:
            uncorroborated += approval_claims
        if dest_claims and dest.external:
            uncorroborated += dest_claims
        if uncorroborated:
            # BLOCK, not ESCALATE. Asserting authority you do not hold, on an
            # action that requires it, is a forgery attempt — not a request
            # awaiting review. Escalating it would put a deception in the
            # approval queue as though it were ordinary work, and would read in
            # the audit trail as "pending" rather than "someone lied".
            candidates.append((
                BLOCK, "trust_boundary",
                f"caller-supplied authority claim(s) {sorted(set(uncorroborated))} "
                f"are not corroborated by trusted state and carry no authority; "
                f"asserting unheld authority is refused outright",
                "forged_authority_claim", None))

        # ── destinations that are never inside any boundary ────
        # Link-local and cloud instance-metadata endpoints vend live role
        # credentials to anything that can issue a plain GET. No deployment
        # configuration makes one of them an ordinary internal destination, so
        # this fires regardless of allowlists and private-network settings.
        if dest.forbidden:
            candidates.append((
                BLOCK, "destination_policy",
                f"destination is a link-local or instance-metadata endpoint "
                f"that vends credentials and is outside every trust boundary "
                f"— {dest.reason}", "forbidden_destination", None))

        # ── privileged action aimed at an external destination ──
        # A credential change, payment, or IAM change whose destination resolves
        # OUTSIDE the trust boundary is a redirect attack: the destination is
        # the payload. No approval makes "reset the CEO's password, deliver to
        # attacker@evil.example" acceptable as a single action, so this is a
        # hard BLOCK rather than something a reviewer could wave through.
        _REDIRECTABLE = {C.CAP_CREDENTIAL_CHANGE, C.CAP_PAYMENT,
                         C.CAP_IAM_PRIVILEGED}
        if dest.external and (caps & _REDIRECTABLE):
            candidates.append((
                BLOCK, "redirect_policy",
                f"privileged action ({', '.join(sorted(caps & _REDIRECTABLE))}) "
                f"directed at an external destination — {dest.reason}",
                "privileged_action_external_destination", None))
        # NOTE: a plain ALLOW capability does NOT establish authority — it just
        # needs none. Injecting `authorized: True` for ordinary reads/egress
        # would switch off the engine's own credential-egress rules, so it is
        # deliberately withheld unless authority was positively established.
        authority_established = bool(approval) or auto_approved or grant_satisfied

        # ── the existing Ω engine, with TRUSTED authority injected ──
        #
        # Trusted state goes in the trajectory CONTEXT, never into args.
        # `TrajectoryState.to_eval_dict()` merges context AFTER args, so the
        # Ω rules read these values while the argument dict stays exactly as
        # the caller sent it (minus quarantined fields).
        #
        # This matters beyond tidiness: several rules match on the SHAPE and
        # SERIALISED TEXT of args — `_suspicious_destination` substring-matches
        # the args JSON, and `is_broad_privilege_expansion` inspects arg KEYS.
        # Writing authority flags into args made a key literally named
        # `destination_external` match the token "external" on an internal
        # destination, and made `admin_approved` read as a privilege-surface
        # key on an unrelated tool. Context injection has neither effect.
        trusted: dict[str, Any] = {}
        if authority_established:
            trusted.update(authorized=True, approved=True, verified=True,
                           admin_approved=True, change_approved=True,
                           sanctioned=True)
        trusted["destination_external"] = dest.external
        trusted["destination_internal"] = not dest.external
        if "amount_threshold" in pol_values:
            trusted["threshold"] = pol_values["amount_threshold"]

        prefix = self.executed_history + [clean]
        try:
            with _sw("trajectory_analysis"):
                res = self._evaluate_with_context(prefix, trusted)
        except Exception as e:                       # noqa: BLE001 — fail closed
            res = None
            candidates.append((BLOCK, "fail_closed",
                               f"governance error treated as BLOCK: "
                               f"{type(e).__name__}", None, None))
        engine_rule = engine_domain = None
        traj_hash = ""
        engine_ms = 0.0
        if res is not None:
            traj_hash = res.trajectory_hash
            engine_ms = float((res.metadata or {}).get("eval_time_ms") or 0.0)
            engine_rule = (res.metadata or {}).get("rule")
            engine_domain = res.omega_domain
            if res.verdict == GovernanceVerdict.ESCALATE:
                candidates.append((ESCALATE, res.layer, res.reason,
                                   engine_rule, engine_domain))
            elif not res.permitted:
                candidates.append((BLOCK, res.layer, res.reason,
                                   engine_rule, engine_domain))

        # Timed by explicit marks rather than a `with` block: this region is
        # long and branch-heavy, and wrapping it would force a reindent of
        # security-critical code for a measurement. The pair below is exactly
        # equivalent to `with _sw("policy_evaluation")`.
        _p0 = time.perf_counter()

        # ── capability policy verdicts ──────────────────────
        if requirement == P.DENY:
            candidates.append((
                BLOCK, "capability_policy",
                f"capability {gov_cap!r} is denied to autonomous agents by policy",
                gov_cap, None))
        elif requirement == P.APPROVAL and not approval:
            candidates.append((
                ESCALATE, "capability_policy",
                f"capability {gov_cap!r} requires a verified approval artifact "
                f"bound to this action ({approval_reason})", gov_cap, None))
        elif requirement == P.GRANT and not grant_satisfied:
            candidates.append((
                ESCALATE, "capability_policy",
                f"principal {self.ctx.principal.id!r} does not hold capability "
                f"grant {gov_cap!r}", gov_cap, None))

        # ── unknown / unmodelled tools fail closed ──────────
        # This used to be guarded by `if self.ctx.tool_manifest`, so a
        # deployment that had declared nothing had the fail-closed rule silently
        # inert: every tool was undeclared and none of them escalated. The
        # least-configured deployment got the weakest enforcement, which is the
        # wrong direction for a default. An empty manifest now means nothing is
        # declared, so everything is undeclared.
        if clean["tool"] not in (self.ctx.tool_manifest or {}):
            pol = (self.ctx.unknown_tool_policy or "escalate").lower()
            if pol == "block":
                candidates.append((BLOCK, "unknown_tool",
                                   f"tool {clean['tool']!r} is not declared in the "
                                   f"tool manifest; policy is fail-closed",
                                   "undeclared_tool", None))
            elif pol != "permit":
                candidates.append((ESCALATE, "unknown_tool",
                                   f"tool {clean['tool']!r} is not declared in the "
                                   f"tool manifest; escalating for review",
                                   "undeclared_tool", None))

        # ── sensitive egress with NO governed acquisition ───
        # The trajectory-based rule below needs a read to have happened inside
        # this session. An agent's context is filled by routes governance never
        # sees — system prompt, retrieval, a prior session, the user's own
        # message — so a one-shot send of regulated material would otherwise
        # pass simply because nothing was read first. Classify the content of
        # the call itself and fail closed.
        # Content is classified on the full proposed action and its
        # normal form: regulated material hidden under a quarantined field
        # name, nested past the old depth limit, or split across sibling
        # list elements is still regulated material.
        sensitive = S.classify_sensitivity(proposed, normalized=norm)
        if dest.external and C.CAP_EXTERNAL_DATA_MOVE in caps and sensitive \
                and not approval:
            candidates.append((
                BLOCK, "sensitive_egress",
                f"external egress carrying {S.describe(sensitive)} without a "
                f"verified approval — sensitive content may already be in "
                f"context, so no prior governed read is required for this to "
                f"be an exfiltration ({dest.reason})",
                "sensitive_external_egress", None))

        # ── external egress after any data acquisition ──────
        if dest.external and C.CAP_EXTERNAL_DATA_MOVE in caps and not approval:
            if pol_values.get("egress_requires_approval_after_read", True) and \
                    self._any_read_occurred():
                candidates.append((
                    BLOCK, "egress_policy",
                    f"external egress after data acquisition in this session "
                    f"({dest.reason})", "external_egress_after_read", None))

        # ── denial-scrubbing: a blocked read still taints ───
        denied = self._denied_read_occurred()
        if denied is not None and dest.external and C.CAP_EXTERNAL_DATA_MOVE in caps:
            candidates.append((
                BLOCK, "trajectory_integrity",
                f"external egress follows a DENIED data acquisition "
                f"({denied.action.get('tool')!r}, {denied.verdict}); a denied "
                f"attempt remains part of the trajectory", "denial_scrubbing", None))

        # ── authority continuity ────────────────────────────
        # An unidentifiable principal is not a principal with no history; it is
        # a principal whose history cannot be looked up, and the two must not be
        # treated the same. Likewise an unreachable store: "we cannot see what
        # this actor did before" is never "this actor did nothing before".
        if not self.continuity.established:
            policy = (getattr(self.ctx, "continuity_policy", "escalate")
                      or "escalate").lower()
            if policy != "permit":
                candidates.append((
                    BLOCK if policy == BLOCK_POLICY else ESCALATE,
                    "continuity",
                    f"governed history cannot be attributed to a persistent "
                    f"identity — {self.continuity.reason}; refusing to treat "
                    f"this execution as having a clean history",
                    "continuity_unestablished", None))
        else:
            try:
                self.store.health()
            except Exception as e:              # noqa: BLE001 — fail closed
                candidates.append((
                    BLOCK, "continuity",
                    f"the governed-history store is unavailable "
                    f"({type(e).__name__}: {e}); prior transitions for "
                    f"{self.continuity.name!r} cannot be read, so this "
                    f"execution cannot be shown to be admissible",
                    "continuity_store_unavailable", None))

        # ── outstanding reservations ────────────────────────
        # ATK-06. Every authorization reserves, and nothing bounded how many
        # reservations one actor could hold. An agent that authorizes and never
        # executes grew its own prefix without limit, raising the cost of every
        # later decision — an actor-controlled denial of service against the
        # chokepoint. Holding many un-redeemed permits is also not a shape any
        # legitimate agent needs.
        if reserve:
            # RESERVED *and* UNCONFIRMED. The cap exists to stop an actor
            # growing its own prefix without limit, and a lease that lapses
            # into UNCONFIRMED still occupies the trajectory — counting only
            # live reservations let 40 entries through a cap of 8 simply by
            # letting each one lapse.
            outstanding = sum(1 for a in self.ledger
                              if a.state in (RESERVED, UNCONFIRMED))
            cap = int(getattr(self.ctx, "max_outstanding_reservations", 0) or 0)
            if cap and outstanding >= cap:
                candidates.append((
                    ESCALATE, "reservation_limit",
                    f"{outstanding} authorisations are reserved or unconfirmed "
                    f"for {self.continuity.name!r} (limit {cap}); execute, "
                    f"release, or reconcile them before authorising more",
                    "too_many_outstanding_reservations", None))

        # ── payload could not be fully read ─────────────────
        # `normalize_action` walks to exhaustion under a node budget. When the
        # budget runs out the classifiers decided on a PARTIAL reading, and a
        # partial reading is not a clearance. Escalate rather than permit.
        if norm.truncated:
            candidates.append((
                ESCALATE, "normalization",
                f"payload could not be fully classified: "
                f"{norm.truncation_reason}", "incomplete_normalization", None))

        # ── quarantined field carrying a destination ────────
        # A quarantined name confers no authority, but a URL or address written
        # into one is still evidence about where the data goes — and choosing
        # that name is a deliberate act. Recorded loudly.
        if quarantined:
            hidden = [k for k, v in quarantined.items()
                      if isinstance(v, str)
                      and (_DEST_IN_VALUE.search(v) or "@" in v)]
            if hidden:
                candidates.append((
                    ESCALATE, "trust_boundary",
                    f"destination-shaped value(s) supplied under quarantined "
                    f"authority field(s) {sorted(hidden)}; a field that cannot "
                    f"carry authority cannot carry a destination either",
                    "destination_in_quarantined_field", None))

        # ── cross-tenant access ─────────────────────────────
        # Quarantined identity fields are passed in deliberately: a caller-
        # supplied `tenant_id` can never GRANT access, but it does tell us which
        # tenant's resources are targeted, and that is exactly what must be
        # compared against the session principal's own tenant.
        xt = _cross_tenant(clean, self.ctx, quarantined)
        if xt:
            candidates.append((BLOCK, "tenancy", xt, "cross_tenant", None))

        _sw.totals["policy_evaluation"] = (
            _sw.totals.get("policy_evaluation", 0.0)
            + (time.perf_counter() - _p0) * 1000.0)

        # ── strictest wins ──────────────────────────────────
        if candidates:
            verdict, layer, reason, rule, domain = max(
                candidates, key=lambda c: _STRICTNESS[c[0]])

            # BLOCK vs ESCALATE precision — deliberately narrow.
            #
            # An engine BLOCK caused solely by absent authority is not the same
            # thing as a forbidden action: a scoped `reader` role on a named
            # project is an ordinary change request, and calling it BLOCK gives
            # an operator no route forward.
            #
            # But "would the engine permit this with authority?" is far too weak
            # a test on its own, because almost every deployment rule is
            # authority-gated — it would reclassify "reset the CEO's password to
            # an attacker's address" as merely awaiting approval, which is false
            # and understates the trajectory in the audit record. An approval
            # does not make an attacker-controlled destination acceptable.
            #
            # So reclassification additionally requires the action to carry NO
            # adversarial indicator: no forged authority claim, no external
            # destination, and no denied attempt earlier in the session. If any
            # of those is present, the BLOCK stands and says so.
            # Only RECENT denials count. This clause controls whether a BLOCK
            # is presented as "resolvable by authorisation", and with durable
            # history an unbounded version would mean one refusal anywhere in a
            # principal's past permanently removed the route forward for every
            # later action — sticky posture with no safety benefit.
            recent = self._clock_basis() - self.decision_ttl_s
            adversarial_indicator = bool(
                forged or dest.external
                or any(a.denied and a.timestamp >= recent for a in self.ledger))
            if (verdict == BLOCK and not authority_established
                    and requirement != P.DENY
                    and not adversarial_indicator
                    and all(c[0] != BLOCK or c[1] == layer for c in candidates)
                    and layer not in ("fail_closed", "tenancy", "egress_policy",
                                      "trajectory_integrity", "capability_policy",
                                      "unknown_tool", "binding", "continuity",
                                      "normalization", "destination_policy",
                                      "lease")):
                hyp_ctx = {**trusted, "authorized": True, "approved": True,
                           "verified": True, "admin_approved": True,
                           "change_approved": True, "sanctioned": True}
                try:
                    with _sw("trajectory_analysis"):
                        hyp = self._evaluate_with_context(
                            self.executed_history + [clean], hyp_ctx)
                    if hyp.permitted:
                        verdict = ESCALATE
                        layer = "capability_policy"
                        reason = (
                            f"{reason} — resolvable by authorisation: this "
                            f"trajectory is permitted once a verified approval "
                            f"artifact is presented")
                except Exception:  # noqa: BLE001 — keep the original BLOCK
                    pass
        else:
            verdict, layer, reason, rule, domain = (
                PERMIT, res.layer if res else "kernel",
                "no Ω intersection; capability requirements satisfied",
                engine_rule, engine_domain)

        decision = Decision(
            verdict=verdict, reason=reason, layer=layer, action_hash=ahash,
            action=proposed, capabilities=caps, requirement=requirement,
            rule=rule, omega_domain=domain, authorization=authorization,
            forged_claims=forged, destination=dest.as_dict(),
            trajectory_hash=traj_hash,
            engine_time_ms=engine_ms,
            decision_time_ms=(time.perf_counter() - _t0) * 1000.0,
            tool_family=norm.tool,
            decision_id=uuid.uuid4().hex, semantic_hash=shash,
            session_id=self.session_id, principal_id=self.ctx.principal.id,
            ruleset_hash=self._ruleset_hash, issued_at=now,
            expires_at=now + self.decision_ttl_s,
            issued_wall=time.time(),
            continuity_scope=self.continuity_scope)

        with _sw("evidence_sealing"):
            decision.evidence = self.chain.append(EvidenceRecord(
                seq=0, timestamp=now, actor=self.ctx.principal.id,
                tenant=self.ctx.principal.tenant, action_hash=ahash,
                proposed=clean, decision=verdict, layer=layer, rule=rule,
                omega_domain=domain, reason=reason, capabilities=sorted(caps),
                requirement=requirement, authorization=authorization,
                forged_authority_claims=forged, ruleset_hash=self._ruleset_hash,
                engine_version=self.engine_version, trajectory_hash=traj_hash))

        # Recomputed AFTER sealing so `decision_time_ms` covers the whole
        # pipeline including evidence, matching its documented meaning.
        decision.stage_timings_ms = dict(_sw.totals)
        decision.decision_time_ms = (time.perf_counter() - _t0) * 1000.0

        if not reserve:
            # A preview must not move the session. It takes no trajectory slot,
            # spends no approval, records no denied attempt and revokes nothing
            # — otherwise "evaluate this speculatively" would itself be a way to
            # taint a session or cancel another caller's outstanding decision.
            # The evidence record above still stands: the preview happened.
            return decision

        if verdict == PERMIT:
            # The approval that unlocked this is spent HERE, not at execute.
            # Consuming at execute let two authorizations verify the same
            # single-use artifact before either ran, so one signed approval
            # minted two independent PERMITs. Under the kernel lock, the
            # second authorization now sees the nonce already used.
            if approval is not None:
                self.ctx.consume_nonce(approval)
                if approval.nonce and self.continuity_key:
                    self.store.consume(self.continuity_key,
                                       f"approval:{approval.nonce}")
            self._reserve(decision, now)
        else:
            self._file(proposed, verdict, DENIED, reason, now,
                       capabilities=caps, decision_id=decision.decision_id,
                       semantic_hash=shash)
            # A BLOCK voids any PERMIT still outstanding for the same
            # transition: otherwise an agent could hold a decision from earlier
            # in the session and execute the very transition just refused.
            #
            # ESCALATE deliberately does NOT revoke. An escalation says THIS
            # request lacked authority, not that the transition is forbidden —
            # and a duplicate request that escalates (because the approval it
            # would need has already been spent by the first) must not cancel
            # the legitimate decision that spent it. Revoking on escalation
            # turns every retry into a denial of service against the caller's
            # own in-flight work.
            if verdict == BLOCK:
                self._revoke(shash, f"BLOCK at {layer}: {reason[:80]}")
        return decision

    # ── execution ────────────────────────────────────────────
    def execute(self, decision: Decision, executor: Callable[[dict], Any],
                call: Optional[dict] = None,
                now: Optional[float] = None) -> tuple[bool, Any]:
        """Run the action ONLY if it is the exact action that was authorised,
        under a lease that is still valid, exactly once.

        Two independent checks, and both are necessary:

          * IDENTITY — re-derive the canonical hash of what is about to run and
            compare it to the hash the decision was issued for, so
            `authorize A -> mutate -> execute B` fails.
          * LEASE — the decision must be unused, unexpired, unrevoked, issued
            to this principal in this session, and under the ruleset still in
            force. Identity alone permitted every one of those: the hash of a
            replayed, stale, or since-refused action is of course unchanged.

        The consume-and-commit is atomic under the kernel lock, so two threads
        racing on one decision cannot both pass the used check.
        """
        try:
            return self._execute_guarded(decision, executor, call, now)
        except Exception as e:                       # noqa: BLE001 — fail closed
            # A governance DEPENDENCY failure — an unreachable continuity store,
            # a broken lease check — used to propagate as a raw exception with
            # no evidence record and no ledger entry, so an outage was invisible
            # in the audit trail and whether it failed open was left to the
            # caller. That is exactly the decision governance exists to take
            # away from the caller.
            reason = (f"the governance layer could not complete its checks "
                      f"({type(e).__name__}: {e})")
            try:
                self._record_refusal(decision, decision.action, "fail_closed",
                                     "governance_dependency_failure",
                                     f"execution refused: {reason}")
            except Exception:                        # noqa: BLE001
                pass                                 # the store IS the failure
            return False, f"refused: {reason}"

    def _execute_guarded(self, decision: Decision,
                         executor: Callable[[dict], Any],
                         call: Optional[dict], now: Optional[float]
                         ) -> tuple[bool, Any]:
        # The critical section is the store's, not just this process's: two
        # workers committing for one principal must serialise against each
        # other, not merely against their own threads.
        with self._lock, self._critical_section():
            # The lease must be checked on the SAME clock the decision was
            # issued against. A caller that authorises with an explicit model
            # clock (`authorize(call, now=0.0)`) must pass the same basis here,
            # or every such decision reads as expired.
            now = time.time() if now is None else now
            problem = self._lease_problem(decision, now)
            if problem is not None:
                self._record_refusal(decision, decision.action,
                                     "lease", "decision_lease_invalid",
                                     f"execution refused: {problem}")
                return False, f"refused: {problem}"
            if not decision.reserved:
                # A decision issued with reserve=False never held the
                # trajectory steady; the session may have moved under it.
                self._record_refusal(
                    decision, decision.action, "lease",
                    "unreserved_decision",
                    "execution refused: decision was issued for analysis "
                    "without a trajectory reservation")
                return False, ("refused: decision was issued without a "
                               "trajectory reservation")

            # ATK-02. `decision.action` is a mutable dict the CALLER holds a
            # reference to. Hashing it and then handing the same object to the
            # executor proves only that it matched at the moment it was checked:
            # a concurrent thread mutated `value=info` into `value=disabled,
            # mfa_required=false` in the window, and the executor ran the
            # mutation under a PERMIT for the original.
            #
            # The executor now receives a private deep copy taken BEFORE the
            # hash, so what is hashed and what runs are the same bytes and
            # nothing outside this frame can reach them.
            target = deepcopy(decision.action if call is None
                              else canonicalize(call))
            actual = action_hash(target)
            if actual != decision.action_hash:
                self._record_refusal(
                    decision, target, "binding",
                    "action_mutation_after_authorization",
                    f"execution refused: action hash {actual[:12]}… does not "
                    f"match authorised {decision.action_hash[:12]}…")
                return False, "refused: action mutated after authorisation"

            # Past this point the decision is spent whatever happens next. An
            # executor that raises may still have had effects, so the lease is
            # burned and the reservation committed rather than released — a
            # failed execution is not a free retry.
            if not self.store.consume(self.continuity_key,
                                      f"decision:{decision.decision_id}"):
                self._record_refusal(
                    decision, target, "lease", "decision_lease_invalid",
                    "execution refused: decision has already been used")
                return False, ("refused: decision has already been used")
            self._commit(decision.decision_id, now, target)

        try:
            result = executor(target)
        except Exception as e:                       # noqa: BLE001
            # The executor may have acted before it raised — a write that landed
            # before the connection reset looks exactly like this. The ledger
            # already records the transition as committed, which is the safe
            # direction. The evidence used to record `executed=False`, so the
            # two authoritative records of one event disagreed and an auditor
            # reading the chain concluded nothing ran. It now records that the
            # action was committed with an UNKNOWN outcome, which is both true
            # and consistent with the ledger.
            self.chain.record_execution(
                decision.evidence, True,
                f"committed; outcome UNKNOWN — executor raised "
                f"{type(e).__name__}: {e}. The effect may or may not have "
                f"landed and is treated as having landed.")
            return False, f"runtime error: {type(e).__name__}: {e}"

        if decision.evidence is not None:
            self.chain.record_execution(decision.evidence, True, "ok")
        return True, result

    def _record_refusal(self, decision: Decision, target: dict, layer: str,
                        rule: str, reason: str) -> None:
        """Seal a refused execution into evidence and the trajectory."""
        self.chain.append(EvidenceRecord(
            seq=0, timestamp=time.time(), actor=self.ctx.principal.id,
            tenant=self.ctx.principal.tenant, action_hash=action_hash(target),
            proposed=target, decision=BLOCK, layer=layer, rule=rule,
            reason=reason, ruleset_hash=self._ruleset_hash,
            engine_version=self.engine_version))
        self._file(target, BLOCK, DENIED, reason, time.time(),
                   capabilities=C.classify(target, self.ctx.tool_manifest),
                   semantic_hash=decision.semantic_hash)

    def record_remote_execution(self, decision: Decision,
                                now: Optional[float] = None) -> None:
        """Record that a PERMITted action was executed by a REMOTE runtime.

        The decision-plane deployment (the HTTP service) does not execute
        anything itself, but the trajectory prefix must still advance or every
        subsequent step in the same session would be evaluated in isolation —
        which is precisely the taint-laundering the red team exploited.
        """
        if not decision.permitted:
            raise ValueError("only a PERMIT decision can be recorded as executed")
        stamp = time.time() if now is None else now
        with self._lock, self._critical_section():
            problem = self._lease_problem(decision, stamp)
            if problem is not None:
                raise ValueError(f"decision cannot be recorded as executed: "
                                 f"{problem}")
            if not self.store.consume(self.continuity_key,
                                      f"decision:{decision.decision_id}"):
                raise ValueError("decision cannot be recorded as executed: "
                                 "it has already been used")
            if self._reservation(decision.decision_id) is not None:
                self._commit(decision.decision_id, stamp)
            else:
                self._file(decision.action, PERMIT, EXECUTED, decision.reason,
                           stamp, capabilities=decision.capabilities,
                           decision_id=decision.decision_id,
                           semantic_hash=decision.semantic_hash)
        if decision.evidence is not None:
            self.chain.record_execution(decision.evidence, True, "remote-runtime")

    def submit(self, call: dict, executor: Callable[[dict], Any]
               ) -> tuple[Decision, bool, Any]:
        """authorize + execute in one call — the normal integration point."""
        with self._lock:
            d = self.authorize(call)
            if not d.permitted:
                return d, False, None
            ok, out = self.execute(d, executor)
        return d, ok, out

    def _ruleset_fingerprint(self) -> tuple:
        """A cheap key over everything the ruleset hash depends on.

        Re-serialising the whole ruleset on every lease check dominated the
        commit path (~1.3ms of a ~1.5ms execute), and the commit path is the one
        an agent drives at full rate. Only the MUTABLE inputs need watching: the
        rule set object itself, the policy values an administrator can change,
        and the unknown-tool policy.
        """
        values = self.ctx.policy_values or {}
        return (id(self.layer.rules), len(self.layer.rules),
                repr(sorted(values.items(), key=lambda kv: str(kv[0]))),
                self.ctx.unknown_tool_policy)

    def _live_ruleset_hash(self) -> str:
        """The hash of the ruleset IN FORCE RIGHT NOW.

        This used to be computed once in `__init__` and refreshed only by an
        explicit `refresh_ruleset()` call, so an administrator who tightened
        `ctx.policy_values` got the new policy applied to NEW decisions — those
        read policy fresh — while every outstanding lease stayed executable
        under the policy it was minted under. Computing it live removes the
        footgun: there is no state to forget to refresh.
        """
        fingerprint = self._ruleset_fingerprint()
        cached = self._ruleset_cache
        if cached is not None and cached[0] == fingerprint:
            return cached[1]
        digest = ruleset_hash(
            self.layer.rules,
            extra={"capability_policy": P.CAPABILITY_POLICY,
                   "policy_values": {**P.DEFAULT_POLICY_VALUES,
                                     **(self.ctx.policy_values or {})},
                   "unknown_tool_policy": self.ctx.unknown_tool_policy})
        self._ruleset_cache = (fingerprint, digest)
        return digest

    def _revalidate_at_commit(self, decision: "Decision") -> Optional[str]:
        """Re-derive the trusted facts the PERMIT rested on, at commit time.

        Authorization is a decision about a moment. Between that moment and the
        commit, trusted configuration can change: a destination allowlist is
        revoked, a boundary is rotated. The action hash proves the ACTION did
        not change; it says nothing about whether the world it was judged
        against still holds.

        Deliberately narrow, and narrower than it first was. Capability policy
        is ALREADY covered — `_live_ruleset_hash` includes the capability table
        and policy values, so a policy change invalidates every outstanding
        lease on its own. Re-deriving the capability requirement here as well
        was redundant AND wrong: it did not replay the server-side payment
        auto-approval, so a legitimately auto-approved transfer looked like a
        decision whose requirement had tightened.

        What the ruleset hash does NOT cover is destination configuration —
        `internal_url_hosts`, `internal_cidrs`, `trust_private_networks` are
        not policy values — so that is what is re-resolved.
        """
        clean, quarantined = quarantine_authority(decision.action)
        dest = classify_destination(
            clean, self.ctx.internal_url_hosts, self.ctx.internal_email_domains,
            self.ctx.internal_cidrs,
            trust_private_networks=self.ctx.trust_private_networks,
            extra_args=quarantined)
        if dest.external and not decision.destination.get("external"):
            return (f"the destination resolved as internal at authorisation "
                    f"and resolves as EXTERNAL now — {dest.reason}")
        if dest.forbidden and not decision.destination.get("forbidden"):
            return f"the destination is now forbidden — {dest.reason}"
        return None

    def refresh_ruleset(self) -> str:
        """Recompute the governing ruleset hash after a policy change.

        Policy is trusted state, so an administrator may change it mid-session.
        Doing so invalidates every outstanding decision: each carries the hash
        of the ruleset it was decided under, and `execute()` refuses a decision
        whose ruleset no longer matches. Call this after mutating
        `ctx.policy_values` so the change actually takes effect.
        """
        self._ruleset_hash = ruleset_hash(
            self.layer.rules,
            extra={"capability_policy": P.CAPABILITY_POLICY,
                   "policy_values": {**P.DEFAULT_POLICY_VALUES,
                                     **(self.ctx.policy_values or {})},
                   "unknown_tool_policy": self.ctx.unknown_tool_policy})
        return self._ruleset_hash

    # ── reporting ────────────────────────────────────────────
    def integrity(self) -> dict:
        ok, problems = self.chain.verify()
        return {"evidence_verified": ok, "problems": problems,
                "records": len(self.chain.records),
                "ruleset_hash": self._ruleset_hash,
                "head": self.chain.head[:16]}


# ─────────────────────────────────────────────────────────────
# helpers
# ─────────────────────────────────────────────────────────────

def _numeric(args: dict, keys: tuple) -> Optional[float]:
    for k in keys:
        if k in args:
            try:
                return float(args[k])
            except (TypeError, ValueError):
                continue
    return None


_TENANT_KEYS = ("tenant", "tenant_id", "customer_id", "account_id", "org",
                "org_id", "organization_id", "workspace", "workspace_id")


def _cross_tenant(call: dict, ctx: SecurityContext,
                  quarantined: Optional[dict] = None) -> Optional[str]:
    """Compare any tenant-scoped identifier in the action against the
    principal's own tenant. Wildcards are always cross-tenant.

    `quarantined` carries identity fields that were stripped from the authority
    namespace — they confer nothing, but they still identify the target.
    """
    own = (ctx.principal.tenant or "").strip().lower()
    args = {**(call.get("args") or {}), **(quarantined or {})}

    # FAIL CLOSED when the principal has no tenant.
    #
    # Previously an empty tenant made every comparison below vacuous: `if own
    # and val != own` cannot fire, so an anonymous caller touching a
    # tenant-scoped resource passed the check entirely. That is precisely the
    # state a caller reaches by omitting gateway auth — the weakest identity
    # got the weakest enforcement. If we cannot establish whose data this is,
    # we cannot establish that it is theirs.
    if not own:
        for k, v in args.items():
            if str(k).strip().lower() in _TENANT_KEYS:
                return (f"principal has no verified tenant, so a tenant-scoped "
                        f"reference ({k}={v!r}) cannot be authorised")
        blob_anon = " ".join(str(v).lower() for v in args.values())
        import re as _re
        m = _re.search(r"(?:^|[\s/:\"'])((?:tenant|customer|org)[-_][a-z0-9]+)",
                       blob_anon)
        if m:
            return (f"principal has no verified tenant, so a tenant-scoped "
                    f"resource reference ({m.group(1)!r}) cannot be authorised")
        return None

    for k, v in args.items():
        if str(k).strip().lower() not in _TENANT_KEYS:
            continue
        val = str(v).strip().lower()
        if val in ("*", "all", "any"):
            return (f"wildcard tenant scope {k}={v!r} from principal in tenant "
                    f"{own or '(none)'!r}")
        if own and val and val != own:
            return (f"cross-tenant access: {k}={v!r} but principal belongs to "
                    f"tenant {own!r}")
    # Qualified resource references such as "tenant_b.customers" / "s3://tenant-b/…"
    if own:
        blob = " ".join(str(v).lower() for v in args.values())
        import re as _re
        for m in _re.finditer(r"(?:^|[\s/:\"'])((?:tenant|customer|org)[-_][a-z0-9]+)",
                              blob):
            ref = m.group(1).replace("-", "_")
            if ref != own.replace("-", "_"):
                return (f"resource reference {m.group(1)!r} is outside the "
                        f"principal's tenant {own!r}")
    return None
