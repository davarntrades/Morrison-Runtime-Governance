"""Mandatory reference baselines (SPEC §8): ungoverned, deny-all, static allowlist.

None of them is a published system. They bound the scorecard: ungoverned shows
whether an attack works at all, deny-all shows what perfect refusal costs in
utility, and the allowlist shows what per-call rules alone achieve.
"""

from __future__ import annotations

from arsb.core.adapter import Adapter, Outcome
from arsb.core.fixture import Refused
from arsb.core.policy import allowed, present


class _Base(Adapter):
    def setup(self, scenario, executor, workdir):
        self.sc, self.exec = scenario, executor
        self.untranslated = present(scenario.get("policy") or {})

    def _run(self, principal, op, ref=""):
        try:
            self.exec(op, principal, ref, None)
            return Outcome("executed")
        except Refused as exc:
            return Outcome("refused", f"resource: {exc}")


class Ungoverned(_Base):
    """Executes every proposal. Exports no evidence."""
    name = "ungoverned"
    mechanisms = frozenset()

    def can_run(self, scenario):
        if scenario.get("evidence_checks"):
            return False, "exports no evidence"
        return True, ""

    def submit(self, principal, op, ctx):
        return self._run(principal, op)


class DenyAll(_Base):
    """Refuses every mutating operation; reads pass (they have no effect)."""
    name = "deny-all"
    mechanisms = frozenset({"pre_execution_veto"})

    def can_run(self, scenario):
        if scenario.get("evidence_checks"):
            return False, "exports no evidence"
        return True, ""

    def submit(self, principal, op, ctx):
        if op["op"] == "read_doc":
            return self._run(principal, op)
        return Outcome("refused", "deny-all")


class Allowlist(_Base):
    """Static per-call allowlist from the policy's `allow` clause. No history,
    no approvals, no tenancy, no provenance."""
    name = "allowlist"
    mechanisms = frozenset({"pre_execution_veto", "per_call_policy"})

    def can_run(self, scenario):
        if scenario.get("evidence_checks"):
            return False, "exports no evidence"
        return True, ""

    def setup(self, scenario, executor, workdir):
        super().setup(scenario, executor, workdir)
        self.untranslated = [c for c in self.untranslated if c != "allow"]

    def submit(self, principal, op, ctx):
        if not allowed(self.sc.get("policy") or {}, op):
            return Outcome("refused", "not on the allowlist")
        return self._run(principal, op)
