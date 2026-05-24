"""HardeningPipeline — opt-in pre-governance pipeline.

Runs, in order, BEFORE the existing reachability hierarchy:

  1. schema validation          (reject malformed calls fail-closed)
  2. payload decoding           (expose hidden encoded structure)
  3. semantic lifting           (canonical-tool + capability mapping)
  4. recursive-coercion detect  (flatten nested sub-calls into the
                                   trajectory the reachability layer sees)
  5. risk propagation           (per-step + cumulative score on the
                                   executed prefix)

The middleware uses the pipeline's output to:
  - reject early if the call is malformed
  - present a *lifted* call to GovernanceLayer.evaluate_plan
  - inject sub-calls as peer steps in the prefix
  - record lineage on the DecisionRecord

The pipeline is OPT-IN. With `hardening=None` the middleware behaves
exactly as before — the existing 12 runtime_eval tests stay
byte-for-byte unchanged.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Optional

from runtime_eval.governance.payload_decoder import (
    decode_call, DecodeReport,
)
from runtime_eval.governance.recursive_coercion import (
    detect_recursive_coercion, CoercionReport,
)
from runtime_eval.governance.schema_validation import (
    validate as schema_validate, ValidationReport,
)
from runtime_eval.governance.semantic_lifting import lift, LiftReport
from runtime_eval.evaluators.risk_propagation import (
    propagate_risk, RiskReport,
)


@dataclass
class HardeningResult:
    augmented_call: dict
    sub_calls: list = field(default_factory=list)
    schema: Optional[ValidationReport] = None
    decode: Optional[DecodeReport] = None
    lift: Optional[LiftReport] = None
    coercion: Optional[CoercionReport] = None
    risk: Optional[RiskReport] = None
    early_reject: bool = False
    reject_reason: str = ""

    def as_dict(self) -> dict:
        return {
            "augmented_call": dict(self.augmented_call),
            "sub_calls": list(self.sub_calls),
            "schema": self.schema.as_dict() if self.schema else None,
            "decode": self.decode.as_dict() if self.decode else None,
            "lift": self.lift.as_dict() if self.lift else None,
            "coercion": self.coercion.as_dict() if self.coercion else None,
            "risk": self.risk.as_dict() if self.risk else None,
            "early_reject": self.early_reject,
            "reject_reason": self.reject_reason,
        }


@dataclass
class HardeningPipeline:
    enable_schema: bool = True
    enable_decode: bool = True
    enable_lift: bool = True
    enable_coercion: bool = True
    enable_risk: bool = True
    max_decode_depth: int = 4
    max_recursion_depth: int = 4

    def apply(self, call: dict, history: list) -> HardeningResult:
        augmented = copy.deepcopy(call)

        # 1. schema — fail-closed on malformed
        schema_report = None
        if self.enable_schema:
            schema_report = schema_validate(augmented)
            if not schema_report.ok:
                return HardeningResult(
                    augmented_call=augmented,
                    schema=schema_report,
                    early_reject=True,
                    reject_reason="schema_violation: "
                                   + "; ".join(schema_report.violations),
                )

        # 2. recursive decode of encoded payloads
        decode_report = None
        if self.enable_decode:
            augmented, decode_report = decode_call(
                augmented, max_depth=self.max_decode_depth)
            if decode_report.malformed:
                return HardeningResult(
                    augmented_call=augmented,
                    schema=schema_report, decode=decode_report,
                    early_reject=True,
                    reject_reason="payload_malformed")

        # 3. semantic lifting — canonical-tool + capability injection
        lift_report = None
        if self.enable_lift:
            augmented, lift_report = lift(augmented)

        # 4. recursive coercion — flatten sub-calls into a peer list
        sub_calls: list = []
        coercion_report = None
        if self.enable_coercion:
            coercion_report = detect_recursive_coercion(
                augmented, max_depth=self.max_recursion_depth)
            sub_calls = [{"tool": c["tool"], "args": dict(c.get("args") or {})}
                          for c in coercion_report.sub_calls]

        # 5. risk propagation across the executed prefix
        risk_report = None
        if self.enable_risk:
            _graph, risk_report = propagate_risk(
                list(history) + [{"tool": augmented.get("tool"),
                                    "args": augmented.get("args", {})}])

        return HardeningResult(
            augmented_call=augmented,
            sub_calls=sub_calls,
            schema=schema_report,
            decode=decode_report,
            lift=lift_report,
            coercion=coercion_report,
            risk=risk_report,
        )
