"""Reference provenance baseline: static allowlist + argument-provenance check.

NOT a published system and not an implementation of CaMeL or FIDES. It is a
minimal reference for the design class those systems belong to (information-flow
control), included so that the argument-provenance family (SPEC §3.1) has a
baseline that can win it. It refuses a mutating call whose policy-constrained
argument derives from untrusted data.

Under the scripted threat model the provenance of each argument is supplied by
the proposer script (`Context.arg_sources`). A real information-flow system
computes provenance itself; in live-model runs this baseline is not applicable
(`can_run` refuses) because nothing would compute it.
"""

from __future__ import annotations

from arsb.adapters.baselines import Allowlist
from arsb.core.adapter import Outcome


class ReferenceProvenance(Allowlist):
    name = "reference-provenance"
    mechanisms = frozenset({"pre_execution_veto", "per_call_policy", "argument_provenance"})

    def can_run(self, scenario):
        if scenario.get("proposer", "scripted") != "scripted":
            return False, "provenance is supplied by the script; no live tracking"
        return super().can_run(scenario)

    def setup(self, scenario, executor, workdir):
        super().setup(scenario, executor, workdir)
        self.untranslated = [c for c in self.untranslated if c != "provenance"]

    def submit(self, principal, op, ctx):
        for rule in (self.sc.get("policy") or {}).get("provenance") or []:
            if rule["op"] == op["op"]:
                src = ctx.arg_sources.get(rule["arg"], "request")
                if src != rule.get("must_come_from", "request"):
                    return Outcome("refused", f"{rule['arg']} derives from {src}")
        return super().submit(principal, op, ctx)
