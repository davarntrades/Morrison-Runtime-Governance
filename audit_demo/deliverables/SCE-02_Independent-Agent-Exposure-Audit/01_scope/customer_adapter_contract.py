"""The customer adapter contract for the Independent Agent Exposure Audit.

A real engagement cannot start until the customer's environment is wrapped in
an adapter that satisfies this contract. Building it is the main onboarding
task, and whether the 48-hour target is credible depends on it.

The contract is deliberately small. It separates four things the audit must
never confuse:

  declared_tools()        what the customer SAYS the agent can call
  discover_operations()   what the audit OBSERVES the agent can call at runtime
  via_customer_controls() what the customer's own safeguards REPORT for a call
  observe()               what actually CHANGED in external state, read from
                          the systems of record, never from a control's report

Anything observe() cannot see must be listed in unobservable(), so that a
scenario depending on it is reported INCONCLUSIVE rather than prevented.

`direct()` is used only in an authorised, non-production test environment, in
two places: the reachability arm (no control in the path) and, optionally,
as the effector behind a Morrison comparison boundary.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class ControlReport:
    """What the customer's safeguard reported for one call."""

    reported: str                     # "ALLOWED" | "REJECTED" | "ERROR"
    control: str | None = None        # which customer control acted, if any
    reason: str = ""
    detail: dict = field(default_factory=dict)


class CustomerAdapter(ABC):
    environment_id: str
    label: str

    @abstractmethod
    def reset(self) -> None:
        """Restore the agreed initial state (fresh test environment)."""

    @abstractmethod
    def declared_tools(self) -> dict:
        """Customer-supplied inventory: {name: {description, mutates, ...}}."""

    @abstractmethod
    def discover_operations(self) -> dict:
        """Runtime-observed callable operations: {name: {mutates, external, ...}}."""

    @abstractmethod
    def via_customer_controls(self, session: str, principal: str, call: dict) -> ControlReport:
        """Submit a call through the customer's own safeguards."""

    @abstractmethod
    def direct(self, principal: str, call: dict) -> dict:
        """Execute with no control in the path (test environment only)."""

    @abstractmethod
    def observe(self) -> dict:
        """Authoritative external state from the systems of record."""

    @abstractmethod
    def unobservable(self) -> list[str]:
        """State the audit cannot read in this environment."""

    def issue_customer_approval(self, call: dict) -> str:   # pragma: no cover - optional
        """Obtain a genuine approval from the customer's approval system."""
        raise NotImplementedError
