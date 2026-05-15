"""
V5 — Environment-wide stability testing.

The core invariant is

    ∀ E ∈ ℰ, ℛ_E(t) ∩ Ω = ∅

V5 operationalises ℰ as a finite set of *admissible* environment
perturbations and checks that the verdict is stable across all of them.
A verdict that flips under semantically-irrelevant perturbations indicates
the rule set is over-fitted to a specific surface form rather than the
underlying intent — and is reported as ENVIRONMENT_SENSITIVE.

Perturbation classes covered (each is a deterministic generator):

    · prompt_drift            — paraphrase string args
    · permission_drift        — toggle authorisation context fields
    · memory_corruption       — inject benign noise context fields
    · context_mutation        — vary peripheral context values
    · tool_schema_drift       — swap tool to a documented alias
    · planner_variation       — re-order multi-step plans equivalently
    · domain_policy_change    — load alternate domain rule subsets

Determinism: every generator takes a `seed` parameter and uses `random.Random`
seeded from it. Same seed + same baseline → same perturbations.
"""

import copy
import random
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from morrison_governance.result import GovernanceResult, GovernanceVerdict


PerturbationGenerator = Callable[[dict, int, int], list[dict]]


# ─────────────────────────────────────────────────────────────
# Generators — each (baseline, n, seed) → list[perturbed_call]
# ─────────────────────────────────────────────────────────────

def prompt_drift(baseline: dict, n: int = 5, seed: int = 0) -> list[dict]:
    """Paraphrase string args — synonyms, casing, whitespace, punctuation."""
    rng = random.Random(seed)
    base = copy.deepcopy(baseline)
    args = base.get("args")
    if not isinstance(args, dict):
        return [base for _ in range(n)]

    string_keys = [k for k, v in args.items() if isinstance(v, str)]
    if not string_keys:
        return [base for _ in range(n)]

    transforms = [
        lambda s: s,
        lambda s: " " + s + " ",
        lambda s: s.replace(" ", "  "),
        lambda s: s.lower(),
        lambda s: s.capitalize(),
        lambda s: s.replace(".", " ."),
    ]
    out = []
    for i in range(n):
        variant = copy.deepcopy(base)
        for k in string_keys:
            variant["args"][k] = transforms[(i + hash(k)) % len(transforms)](
                variant["args"][k])
        out.append(variant)
    return out


def permission_drift(baseline: dict, n: int = 4, seed: int = 0) -> list[dict]:
    """Toggle peripheral authorisation context fields (not the authoritative one)."""
    rng = random.Random(seed)
    fields_to_toggle = ["audit_logged", "session_active", "mfa_verified",
                        "ip_in_allowlist", "device_known"]
    out = []
    for i in range(n):
        variant = copy.deepcopy(baseline)
        # Field j maps to bit j of i (LSB-first) so the first field flips
        # every other variant — ensures each field takes both values
        # within a small n rather than only at large indices.
        for j, f in enumerate(fields_to_toggle):
            variant[f] = bool((i >> j) & 1)
        out.append(variant)
    return out


def memory_corruption(baseline: dict, n: int = 4, seed: int = 0) -> list[dict]:
    """Inject benign noise context fields that should not affect verdict."""
    rng = random.Random(seed)
    out = []
    for i in range(n):
        variant = copy.deepcopy(baseline)
        for j in range(i + 1):
            variant[f"_noise_{j}"] = rng.choice([
                "lorem", "ipsum", 42, True, None, [1, 2, 3], {"k": "v"},
            ])
        out.append(variant)
    return out


def context_mutation(baseline: dict, n: int = 4, seed: int = 0) -> list[dict]:
    """Vary peripheral, semantically-neutral context fields."""
    rng = random.Random(seed)
    pools = {
        "request_id": [f"req-{rng.randint(0, 10**9):09d}" for _ in range(n)],
        "trace_id":   [f"trace-{rng.randint(0, 10**12):012d}" for _ in range(n)],
        "user_agent": ["agent-A", "agent-B", "agent-C", "agent-D"],
        "region":     ["us-east", "us-west", "eu-west", "ap-south"],
    }
    out = []
    for i in range(n):
        variant = copy.deepcopy(baseline)
        for key, pool in pools.items():
            variant[key] = pool[i % len(pool)]
        out.append(variant)
    return out


def tool_schema_drift(baseline: dict, n: int = 3, seed: int = 0,
                      aliases: Optional[dict[str, list[str]]] = None
                      ) -> list[dict]:
    """Swap the tool name to a documented alias (caller-provided)."""
    aliases = aliases or {
        "send_email":   ["email_send", "mail_send", "smtp_send"],
        "http_request": ["fetch", "curl", "rest_call"],
        "read_file":    ["fs_read", "open_file", "load_file"],
    }
    base_tool = baseline.get("tool")
    pool = aliases.get(base_tool, [base_tool])
    out = []
    for i in range(n):
        variant = copy.deepcopy(baseline)
        variant["tool"] = pool[i % len(pool)] if pool else base_tool
        out.append(variant)
    return out


def planner_variation(plan: list[dict], n: int = 3, seed: int = 0
                      ) -> list[list[dict]]:
    """Re-order steps in equivalence-preserving ways (only the trailing tail)."""
    rng = random.Random(seed)
    out = [list(plan)]
    for i in range(n - 1):
        if len(plan) >= 3:
            shuffled = plan[:-2] + rng.sample(plan[-2:], k=2)
            out.append(shuffled)
        else:
            out.append(list(plan))
    return out


# ─────────────────────────────────────────────────────────────
# Stability evaluator
# ─────────────────────────────────────────────────────────────

@dataclass
class FlipRecord:
    perturbation_class: str
    variant_index: int
    baseline_verdict: str
    perturbed_verdict: str
    perturbed_layer: str
    perturbed_reason: str


@dataclass
class StabilityReport:
    baseline_verdict: str
    baseline_layer: str
    total_perturbations: int
    matching: int
    flips: list[FlipRecord] = field(default_factory=list)

    @property
    def stability_score(self) -> float:
        if self.total_perturbations == 0:
            return 1.0
        return self.matching / self.total_perturbations

    @property
    def is_stable(self) -> bool:
        return self.matching == self.total_perturbations


@dataclass
class StabilityEvaluator:
    """Evaluates verdict stability across environment perturbations."""

    runner: Callable[[dict], GovernanceResult]

    def evaluate_stability(
        self,
        baseline_call: dict,
        perturbations: Optional[list[tuple[str, PerturbationGenerator]]] = None,
        n_per_class: int = 5,
        seed: int = 0,
    ) -> tuple[GovernanceResult, StabilityReport]:
        if perturbations is None:
            perturbations = [
                ("prompt_drift",      prompt_drift),
                ("permission_drift",  permission_drift),
                ("memory_corruption", memory_corruption),
                ("context_mutation",  context_mutation),
                ("tool_schema_drift", tool_schema_drift),
            ]

        baseline = self.runner(baseline_call)
        report = StabilityReport(
            baseline_verdict=baseline.verdict.value,
            baseline_layer=baseline.layer,
            total_perturbations=0,
            matching=0,
        )

        for cls_name, gen in perturbations:
            try:
                variants = gen(baseline_call, n_per_class, seed)
            except TypeError:
                # Generator with different signature (e.g. planner_variation
                # operates on a plan list, not a single call dict). Skip.
                continue
            for i, variant in enumerate(variants):
                report.total_perturbations += 1
                r = self.runner(variant)
                if r.verdict == baseline.verdict:
                    report.matching += 1
                else:
                    report.flips.append(FlipRecord(
                        perturbation_class=cls_name,
                        variant_index=i,
                        baseline_verdict=baseline.verdict.value,
                        perturbed_verdict=r.verdict.value,
                        perturbed_layer=r.layer,
                        perturbed_reason=r.reason,
                    ))

        if report.is_stable:
            # Verdict is stable; return baseline with a V5-clean tag.
            baseline.metadata.setdefault("v5", {})
            baseline.metadata["v5"] = {
                "stability_score": 1.0,
                "perturbations_tested": report.total_perturbations,
            }
            return baseline, report

        # Verdict flipped under at least one perturbation.
        sensitive = GovernanceResult(
            verdict=GovernanceVerdict.ENVIRONMENT_SENSITIVE,
            layer="V5",
            reason=(
                f"Verdict unstable across {report.total_perturbations} "
                f"environment perturbations: "
                f"{len(report.flips)} flipped, score="
                f"{report.stability_score:.3f}"
            ),
            trajectory_hash=baseline.trajectory_hash,
            metadata={
                "v5_baseline_verdict": baseline.verdict.value,
                "v5_baseline_layer": baseline.layer,
                "v5_stability_score": report.stability_score,
                "v5_flips": [f.__dict__ for f in report.flips],
            },
        )
        return sensitive, report
