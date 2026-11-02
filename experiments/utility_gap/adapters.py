"""Provenance-aware Morrison variants for ARSB, outside the frozen v0 tree.

The frozen adapters (`arsb/adapters/morrison.py`, hash-pinned in
`arsb/FREEZE.json`) are not modified. These subclasses differ in exactly one
respect: they pass ARSB's per-step `Context.arg_sources` to
`GovernanceKernel.authorize(..., argument_provenance=...)`.

Provenance convention (the same one `arsb/adapters/reference_provenance.py`
uses): an argument the script does not label comes from the request. In ARSB
the labels are SUPPLIED BY THE SCRIPT, exactly as for the reference-provenance
baseline; nothing here tracks data flow. CaMeL computes provenance itself.
A deployment would need a runtime that does (see kernel/argflow.py).
"""

from __future__ import annotations

from arsb.adapters.morrison import Morrison, MorrisonMediated


def _labels(op: dict, arg_sources: dict) -> dict:
    return {name: arg_sources.get(name, "request") for name in (op.get("args") or {})}


class _ProvenanceMixin:
    def setup(self, scenario, executor, workdir):
        super().setup(scenario, executor, workdir)
        # Provenance policies are now expressible through the kernel.
        self.untranslated = [c for c in self.untranslated if c != "provenance"]

    def submit(self, principal, op, ctx):
        kernel = self._kernel(principal)
        original = kernel.authorize
        labels = _labels(op, dict(ctx.arg_sources or {}))

        def authorize(call, *args, **kwargs):
            kwargs.setdefault("argument_provenance", labels)
            return original(call, *args, **kwargs)

        kernel.authorize = authorize
        try:
            return super().submit(principal, op, ctx)
        finally:
            del kernel.authorize


class MorrisonProvenance(_ProvenanceMixin, Morrison):
    name = "morrison-provenance"
    mechanisms = Morrison.mechanisms | {"argument_provenance"}


class MorrisonMediatedProvenance(_ProvenanceMixin, MorrisonMediated):
    name = "morrison-mediated-provenance"
    mechanisms = MorrisonMediated.mechanisms | {"argument_provenance"}
