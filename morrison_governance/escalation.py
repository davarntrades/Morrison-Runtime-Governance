"""Escalation routing — giving ESCALATE a destination.

THE GAP THIS CLOSES

ESCALATE was a synchronous refusal with nowhere to go. Adversarial testing
established, and `limits_audit/FINDINGS.md` recorded, that:

  * nothing was persisted — `kernel.unconfirmed()` was empty, the ledger filed
    the attempt as `denied`, and the only artefact was an evidence record;
  * there was no notification target anywhere in `SecurityContext`;
  * the verdict was invariant in elapsed time: t+0 and t+10y both ESCALATE,
    so there was no timeout, no default, and no expiry;
  * an agent could retry forever, 500 rounds costing nothing but ledger growth;
  * every caller-facing boundary treated ESCALATE exactly like BLOCK, so a
    calling agent could not tell "ask a human" from "never".

A deployment reading "ESCALATE" as "a human will be asked" was wrong: nothing
in the system went and asked one.

WHAT THIS ADDS

The smallest real mechanism that makes the verdict actionable:

  1. PERSISTENCE — an escalation is a record in a store, queryable by id, by
     state and by principal. `InMemoryEscalationStore` mirrors
     `InMemoryContinuityStore`; `FileEscalationStore` appends JSONL so it
     survives a restart, mirroring `FileContinuityStore`.
  2. NOTIFICATION — a `notifier` callable invoked once per newly opened
     escalation. In-process by design: a webhook is
     `lambda e: requests.post(url, json=e.as_dict())`, a queue publish is one
     line, and a deployment that wants neither can poll `pending()`. Building
     HTTP in here would add a dependency and a failure mode without adding a
     capability. A notifier that raises never affects the verdict.
  3. TIMEOUT — explicit, configurable, and BLOCK by default.

WHY BLOCK ON TIMEOUT

ESCALATE means "not authorised yet". If nobody answers, the request has not
become authorised — it has merely aged. Auto-approving on timeout would make
the timeout itself the bypass: an agent could obtain any escalated action by
waiting, which is strictly worse than the original gap because it looks like
governance. The default is therefore BLOCK, and `on_timeout="escalate"` is
offered for deployments that want an expired request to stay open for review
rather than being closed against the requester.

WHAT THIS DOES NOT DO

It does not invent a second authority. A resolution mints the SAME
`ApprovalArtifact` the kernel already verifies — HMAC over the semantic action
hash, issuer checked against `trusted_issuers`, single-use nonce, TTL. There is
no path here that authorises anything the existing trust boundary would not.

Deterministic: the only clock is the `now` a caller passes, and ids are derived
from the decision rather than randomly generated, so a replay reproduces them.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, replace
from typing import Any, Callable, Optional

# ── states ──────────────────────────────────────────────────────────────
PENDING = "pending"
APPROVED = "approved"
DENIED = "denied"
EXPIRED = "expired"

#: What an unanswered escalation becomes. See "WHY BLOCK ON TIMEOUT".
TIMEOUT_BLOCK = "block"
TIMEOUT_ESCALATE = "escalate"

DEFAULT_TTL_S = 3600.0


@dataclass(frozen=True)
class Escalation:
    """One request awaiting a human decision."""

    id: str
    semantic_hash: str
    action_hash: str
    tool: str
    action: dict
    principal: str
    tenant: str
    session_id: str
    reason: str
    layer: str = ""
    rule: Optional[str] = None
    capabilities: tuple = ()
    created_at: float = 0.0
    expires_at: float = 0.0
    state: str = PENDING
    resolved_at: Optional[float] = None
    resolved_by: str = ""
    resolution_reason: str = ""
    approval_nonce: str = ""

    @property
    def pending(self) -> bool:
        return self.state == PENDING

    def is_overdue(self, now: float) -> bool:
        return self.state == PENDING and self.expires_at and now > self.expires_at

    def as_dict(self) -> dict:
        d = asdict(self)
        d["capabilities"] = list(self.capabilities)
        return d


# ── stores ──────────────────────────────────────────────────────────────

class InMemoryEscalationStore:
    """Process-wide escalation queue. Thread-safe, not durable.

    Mirrors `InMemoryContinuityStore`: fine within one process, a clean slate
    across a restart. Use `FileEscalationStore` when a pending escalation must
    outlive the worker that opened it — which, for anything a human is meant
    to answer, it must.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._items: dict[str, Escalation] = {}

    @contextmanager
    def transaction(self):
        with self._lock:
            yield

    def open(self, esc: Escalation) -> Escalation:
        """Record a new escalation, or return the one already open for this
        transition. Re-proposing the same refused action does not queue a
        second review — that is how a retry loop becomes a denial of service
        against the reviewer."""
        with self._lock:
            existing = self._items.get(esc.id)
            if existing is not None:
                return existing
            self._items[esc.id] = esc
            return esc

    def get(self, esc_id: str) -> Optional[Escalation]:
        with self._lock:
            return self._items.get(esc_id)

    def put(self, esc: Escalation) -> Escalation:
        with self._lock:
            self._items[esc.id] = esc
            return esc

    def query(self, *, state: Optional[str] = None,
              principal: Optional[str] = None,
              tenant: Optional[str] = None) -> list[Escalation]:
        with self._lock:
            out = list(self._items.values())
        if state is not None:
            out = [e for e in out if e.state == state]
        if principal is not None:
            out = [e for e in out if e.principal == principal]
        if tenant is not None:
            out = [e for e in out if e.tenant == tenant]
        return sorted(out, key=lambda e: (e.created_at, e.id))

    def pending(self, **kw) -> list[Escalation]:
        return self.query(state=PENDING, **kw)


class FileEscalationStore(InMemoryEscalationStore):
    """Durable escalation queue: an append-only JSONL log, replayed on load.

    Append-only rather than rewritten in place for the same reason the evidence
    chain is: the history of a review decision is itself auditable, and a store
    that overwrites cannot show that a request was approved after it had
    already expired.
    """

    def __init__(self, path: str) -> None:
        super().__init__()
        self.path = path
        self._replay()

    def _replay(self) -> None:
        if not os.path.exists(self.path):
            return
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except ValueError:
                    continue
                raw["capabilities"] = tuple(raw.get("capabilities") or ())
                try:
                    esc = Escalation(**raw)
                except TypeError:
                    continue
                self._items[esc.id] = esc

    def _append(self, esc: Escalation) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self.path)) or ".",
                    exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(esc.as_dict(), sort_keys=True) + "\n")

    def open(self, esc: Escalation) -> Escalation:
        with self._lock:
            existing = self._items.get(esc.id)
            if existing is not None:
                return existing
            self._items[esc.id] = esc
            self._append(esc)
            return esc

    def put(self, esc: Escalation) -> Escalation:
        with self._lock:
            self._items[esc.id] = esc
            self._append(esc)
            return esc


def _escalation_id(decision: Any, principal: str, session_id: str) -> str:
    """Stable per (transition, principal, session).

    Derived rather than random so that a retry of the same refused action
    finds the escalation it already opened, and a replay of a recorded run
    reproduces the same ids.
    """
    basis = "|".join([getattr(decision, "semantic_hash", "") or "",
                      principal or "", session_id or ""])
    return "esc-" + hashlib.sha256(basis.encode()).hexdigest()[:20]


# ── router ──────────────────────────────────────────────────────────────

@dataclass
class EscalationRouter:
    """Where an ESCALATE goes.

        store    = FileEscalationStore("/var/lib/morrison/escalations.jsonl")
        router   = EscalationRouter(store=store, notifier=page_the_oncall,
                                    ttl_s=1800)
        kernel   = GovernanceKernel(layer, ctx, escalation_router=router)

    A reviewer then works `router.pending()`, and calls `router.approve(...)`
    or `router.deny(...)`. Approving mints a real `ApprovalArtifact`; the
    caller installs it in the `SecurityContext` and re-proposes, and the
    ordinary trust boundary does the rest.
    """

    store: Any = field(default_factory=InMemoryEscalationStore)
    #: Called once per newly opened escalation. A webhook is a one-line
    #: notifier. Exceptions are swallowed: a paging system being down is not a
    #: reason to change a governance verdict, and the record is already
    #: persisted, so a missed page degrades to polling rather than to silence.
    notifier: Optional[Callable[[Escalation], None]] = None
    ttl_s: float = DEFAULT_TTL_S
    #: BLOCK unless a deployment states otherwise — see the module docstring.
    on_timeout: str = TIMEOUT_BLOCK
    #: Recorded so an auditor can see a notifier failed rather than inferring it.
    notify_failures: list = field(default_factory=list)

    # ---- opening -------------------------------------------------------
    def route(self, decision: Any, *, principal: str, tenant: str,
              session_id: str, now: float) -> Escalation:
        """Persist an ESCALATE and notify. Idempotent per transition."""
        esc_id = _escalation_id(decision, principal, session_id)
        existing = self.store.get(esc_id)
        if existing is not None:
            # Already queued. A retry of the same refused action must not page
            # the reviewer again: 500 retries were measured in the finding, and
            # 500 pages for one decision is a denial of service against the
            # person the escalation exists to reach.
            return existing
        esc = Escalation(
            id=esc_id,
            semantic_hash=getattr(decision, "semantic_hash", "") or "",
            action_hash=getattr(decision, "action_hash", "") or "",
            tool=str((getattr(decision, "action", {}) or {}).get("tool", "")),
            action=dict(getattr(decision, "action", {}) or {}),
            principal=principal, tenant=tenant, session_id=session_id,
            reason=getattr(decision, "reason", ""),
            layer=getattr(decision, "layer", ""),
            rule=getattr(decision, "rule", None),
            capabilities=tuple(sorted(getattr(decision, "capabilities", ()) or ())),
            created_at=now, expires_at=now + float(self.ttl_s),
            state=PENDING)
        opened = self.store.open(esc)
        # `existing is None` above is what makes this the first sighting.
        # Comparing timestamps instead was wrong: retries within the same
        # model instant carry the same `now` as the stored record and paged
        # on every one of them.
        if self.notifier is not None:
            try:
                self.notifier(opened)
            except Exception as exc:                     # noqa: BLE001
                self.notify_failures.append((opened.id, repr(exc)))
        return opened

    # ---- querying ------------------------------------------------------
    def get(self, esc_id: str) -> Optional[Escalation]:
        return self.store.get(esc_id)

    def pending(self, *, now: Optional[float] = None, **kw) -> list[Escalation]:
        """Open escalations. With `now`, overdue ones are swept first so a
        reviewer is never shown a request that has already timed out."""
        if now is not None:
            self.sweep(now)
        return self.store.pending(**kw)

    def query(self, **kw) -> list[Escalation]:
        return self.store.query(**kw)

    # ---- timeout -------------------------------------------------------
    def sweep(self, now: float) -> list[Escalation]:
        """Apply the timeout policy to everything overdue. Returns what changed."""
        changed = []
        with getattr(self.store, "transaction", _null_tx)():
            for esc in self.store.query(state=PENDING):
                if not esc.is_overdue(now):
                    continue
                if self.on_timeout == TIMEOUT_ESCALATE:
                    # Stay open for review, but on the record as overdue.
                    changed.append(self.store.put(replace(
                        esc, resolution_reason=(
                            f"overdue since {esc.expires_at:.0f}; held open by "
                            f"on_timeout={TIMEOUT_ESCALATE}"))))
                    continue
                changed.append(self.store.put(replace(
                    esc, state=EXPIRED, resolved_at=now, resolved_by="timeout",
                    resolution_reason=(
                        f"no reviewer response within {self.ttl_s:.0f}s; "
                        f"default on_timeout={self.on_timeout} applied"))))
        return changed

    def outcome(self, esc_id: str, now: float) -> str:
        """The state an escalation is in, with the timeout applied first.

        EXPIRED is a refusal: an unanswered request did not become authorised,
        it only aged.
        """
        self.sweep(now)
        esc = self.store.get(esc_id)
        return esc.state if esc is not None else PENDING

    # ---- resolution ----------------------------------------------------
    def approve(self, esc_id: str, *, issuer: str, key: bytes,
                now: float, approval_ttl_s: float = 300.0) -> Any:
        """Record a reviewer's approval and mint the artifact that carries it.

        Returns a real `ApprovalArtifact` — the same object a trusted approval
        service would produce, bound to this action's semantic hash. This
        router mints nothing the kernel would not already verify, and an
        approval after expiry is refused rather than quietly honoured.
        """
        from morrison_governance.kernel.trust import issue_approval

        self.sweep(now)
        esc = self.store.get(esc_id)
        if esc is None:
            raise KeyError(f"unknown escalation {esc_id!r}")
        if esc.state == EXPIRED:
            raise ValueError(
                f"escalation {esc_id} expired at {esc.expires_at:.0f}; it "
                f"cannot be approved after the timeout resolved it — re-propose "
                f"the action to open a new review")
        if esc.state != PENDING:
            raise ValueError(f"escalation {esc_id} is already {esc.state}")

        nonce = hashlib.sha256(f"{esc.id}|{issuer}|{now:.0f}".encode()
                               ).hexdigest()[:16]
        artifact = issue_approval(esc.action, issuer=issuer, key=key,
                                  ttl_s=approval_ttl_s, nonce=nonce, now=now)
        self.store.put(replace(
            esc, state=APPROVED, resolved_at=now, resolved_by=issuer,
            resolution_reason="approved by reviewer", approval_nonce=nonce))
        return artifact

    def deny(self, esc_id: str, *, issuer: str, now: float,
             reason: str = "") -> Escalation:
        """Record a reviewer's refusal. The action stays refused."""
        self.sweep(now)
        esc = self.store.get(esc_id)
        if esc is None:
            raise KeyError(f"unknown escalation {esc_id!r}")
        if esc.state not in (PENDING,):
            raise ValueError(f"escalation {esc_id} is already {esc.state}")
        return self.store.put(replace(
            esc, state=DENIED, resolved_at=now, resolved_by=issuer,
            resolution_reason=reason or "denied by reviewer"))


@contextmanager
def _null_tx():
    yield
