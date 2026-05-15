"""
Perturbation-manifold robustness estimation (V5 upgrade).

Extends V5 from "∀ E ∈ ℰ (finite sampled set)" to bounded-ball robustness:

    ∀ E ∈ B(ℰ, r),  R̂_E(t) ∩ Ω = ∅

ℰ is represented as a union of *perturbation manifolds* ℰ = ⋃ᵢ ℰᵢ, each a
parameterised geometric deformation family rather than a discrete list.
Perturbations are modelled geometrically (a structural distance metric
over call geometry), never semantically.

Outputs:
  - structural perturbation distance metric
  - stability envelope (agreement vs perturbation radius)
  - robustness margin / collapse threshold
  - governance degradation curve
  - cross-domain transfer invariance (geometry fixed, only Ω changes)

Determinism: every family is seeded via random.Random(seed); identical
(call, radius, seed) → identical variants.
"""

import base64
import copy
import random
from dataclasses import dataclass, field
from typing import Callable, Optional

from morrison_governance.forecasting import infer_capabilities

_CAP_ORDER = ("acquire", "egress", "exec", "priv", "defer", "loop", "neutral")
_TAINT_FIELDS = ("destination_external", "destination_internal", "role",
                 "mode", "url", "to", "recipient", "path", "authorized",
                 "amount", "consent_verified", "contains_pii")


# ─────────────────────────────────────────────────────────────
# Geometric structural distance (NOT semantic)
# ─────────────────────────────────────────────────────────────

def _feature(call: dict) -> dict:
    args = call.get("args", {})
    akeys = (frozenset(str(k).lower() for k in args)
             if isinstance(args, dict) else frozenset())
    caps = infer_capabilities(call)
    fields = frozenset(
        f for f in _TAINT_FIELDS
        if (isinstance(args, dict) and f in
            {str(k).lower() for k in args}) or f in call)
    return {"tool": str(call.get("tool", "")).lower(),
            "akeys": akeys, "caps": caps, "fields": fields}


def _jaccard(a: frozenset, b: frozenset) -> float:
    if not a and not b:
        return 1.0
    return len(a & b) / len(a | b) if (a | b) else 1.0


def structural_distance(a: dict, b: dict) -> float:
    """Deterministic geometric distance in [0, 1] between two calls.

    Components: capability-vector Hamming, arg-key Jaccard, tool-token
    normalised edit, taint-relevant field-set Jaccard. No string
    semantics, no embeddings."""
    fa, fb = _feature(a), _feature(b)
    cap_h = sum(1 for c in _CAP_ORDER
                if (c in fa["caps"]) != (c in fb["caps"])) / len(_CAP_ORDER)
    key_d = 1.0 - _jaccard(fa["akeys"], fb["akeys"])
    fld_d = 1.0 - _jaccard(fa["fields"], fb["fields"])
    ta, tb = fa["tool"], fb["tool"]
    if ta == tb:
        tool_d = 0.0
    else:
        # cheap normalised token distance (length-normalised mismatch)
        m = sum(1 for x, y in zip(ta, tb) if x != y) + abs(len(ta) - len(tb))
        tool_d = min(1.0, m / max(1, max(len(ta), len(tb))))
    return round(0.40 * cap_h + 0.25 * key_d + 0.20 * fld_d
                 + 0.15 * tool_d, 6)


# ─────────────────────────────────────────────────────────────
# Perturbation manifold families (geometric deformations)
# ─────────────────────────────────────────────────────────────

def _str_args(call):
    a = call.get("args")
    return a if isinstance(a, dict) else {}


@dataclass
class PerturbationManifold:
    """A parameterised deformation family. `deform(call, intensity, rng)`
    returns a structurally-perturbed call; intensity ∈ [0, 1] scales the
    geometric magnitude of the deformation."""

    name: str
    deform: Callable[[dict, float, random.Random], dict]

    def sample(self, call: dict, radius: float, n: int,
               seed: int = 0) -> list[dict]:
        # radius 0 is the identity anchor: B(ℰ, 0) = {baseline}.
        if radius <= 0.0:
            return [copy.deepcopy(call) for _ in range(n)]
        # Stable, process-independent seed (hash() of str is PYTHONHASHSEED
        # dependent — would break cross-process determinism).
        import hashlib
        h = int(hashlib.sha256(f"{self.name}|{seed}".encode())
                .hexdigest()[:8], 16)
        rng = random.Random(h)
        return [self.deform(copy.deepcopy(call), radius, rng)
                for _ in range(n)]


def _f_prompt(call, t, rng):
    a = _str_args(call)
    for k, v in list(a.items()):
        if isinstance(v, str):
            if t < 0.34:
                a[k] = (" " + v + " ") if rng.random() < 0.5 else v.upper()
            elif t < 0.67:
                a[k] = v.replace(" ", "  ").capitalize()
            else:
                a[k] = v[::-1] if rng.random() < 0.3 else (v + " .")
    return call


def _f_schema(call, t, rng):
    a = _str_args(call)
    if a and t >= 0.34:
        k = sorted(a)[0]
        a[k + ("_v2" if t < 0.67 else "__renamed")] = a.pop(k)
    if t >= 0.67:
        a["_schema_rev"] = int(t * 10)
    call["args"] = a
    return call


def _f_permission(call, t, rng):
    call["authorized"] = rng.random() < (1.0 - t)
    call["role"] = rng.choice(["viewer", "operator", "admin"]) if t > 0.5 \
        else call.get("role", "viewer")
    if t > 0.7:
        call["mfa_verified"] = False
    return call


def _f_memory(call, t, rng):
    for j in range(1 + int(t * 5)):
        call[f"_noise_{j}"] = rng.choice(["x", 1, True, None, [0]])
    return call


def _f_encoding(call, t, rng):
    a = _str_args(call)
    for k, v in list(a.items()):
        if isinstance(v, str) and v:
            if t < 0.34:
                a[k] = v.upper()
            elif t < 0.67:
                a[k] = v.encode().hex()
            else:
                a[k] = base64.b64encode(v.encode()).decode()
    return call


def _f_hidden_tool(call, t, rng):
    tool = str(call.get("tool", ""))
    if t < 0.34:
        call["tool"] = tool.upper()
    elif t < 0.67:
        call["tool"] = tool.replace("_", "-")
    else:
        call["tool"] = tool.replace("e", "е").replace("a", "а")  # homoglyph
    return call


def _f_runtime(call, t, rng):
    call["deployment"] = rng.choice(["prod", "staging", "dev"])
    call["region"] = rng.choice(["us", "eu", "ap"])
    if t > 0.5:
        call["actor_type"] = rng.choice(["human", "agent", "service"])
    return call


def _f_context(call, t, rng):
    call["request_id"] = f"req-{rng.randint(0, 10**6):06d}"
    if t > 0.4:
        call["trace_id"] = f"tr-{rng.randint(0, 10**9):09d}"
    if t > 0.7:
        call["session_epoch"] = rng.randint(0, 9)
    return call


def _f_divergence(call, t, rng):
    # planner-state divergence: combine multiple weak deformations
    call = _f_prompt(call, t, rng)
    call = _f_context(call, t, rng)
    if t > 0.6:
        call = _f_memory(call, t, rng)
    return call


DEFAULT_MANIFOLDS = [
    PerturbationManifold("prompt_mutation", _f_prompt),
    PerturbationManifold("schema_deformation", _f_schema),
    PerturbationManifold("permission_drift", _f_permission),
    PerturbationManifold("memory_corruption", _f_memory),
    PerturbationManifold("adversarial_encoding", _f_encoding),
    PerturbationManifold("hidden_tool_emergence", _f_hidden_tool),
    PerturbationManifold("runtime_mutation", _f_runtime),
    PerturbationManifold("context_poisoning", _f_context),
    PerturbationManifold("planner_divergence", _f_divergence),
]


# ─────────────────────────────────────────────────────────────
# Stability envelope
# ─────────────────────────────────────────────────────────────

@dataclass
class RobustnessReport:
    baseline_verdict: str
    radii: list = field(default_factory=list)
    agreement: list = field(default_factory=list)        # per-radius
    mean_distance: list = field(default_factory=list)     # measured geometry
    omega_prob: list = field(default_factory=list)        # P(verdict flips)
    per_family: dict = field(default_factory=dict)
    total: int = 0

    @property
    def robustness_margin(self) -> float:
        """Largest radius (contiguous from 0) with 100 % verdict agreement."""
        m = 0.0
        for r, ag in zip(self.radii, self.agreement):
            if ag >= 1.0:
                m = r
            else:
                break
        return m

    @property
    def collapse_threshold(self) -> Optional[float]:
        """Smallest radius where agreement drops below 0.5."""
        for r, ag in zip(self.radii, self.agreement):
            if ag < 0.5:
                return r
        return None

    @property
    def degradation_curve(self) -> list:
        return list(zip(self.radii, self.agreement))


@dataclass
class StabilityEnvelopeEstimator:
    """Estimates B(ℰ, r) robustness by sweeping perturbation radius."""

    runner: Callable[[dict], "GovernanceResult"]
    manifolds: list = field(default_factory=lambda: list(DEFAULT_MANIFOLDS))

    def estimate(self, baseline_call: dict,
                 radii=(0.0, 0.2, 0.4, 0.6, 0.8, 1.0),
                 n_per_family: int = 6, seed: int = 0) -> RobustnessReport:
        base = self.runner(baseline_call)
        rep = RobustnessReport(baseline_verdict=base.verdict.value)
        for fam in self.manifolds:
            rep.per_family[fam.name] = []

        for r in radii:
            matches, dists, flips, count = 0, [], 0, 0
            for fam in self.manifolds:
                fam_match = 0
                variants = fam.sample(baseline_call, r, n_per_family, seed)
                for v in variants:
                    count += 1
                    dists.append(structural_distance(baseline_call, v))
                    res = self.runner(v)
                    same = (res.verdict == base.verdict)
                    matches += int(same)
                    fam_match += int(same)
                    flips += int(not same)
                rep.per_family[fam.name].append(
                    round(fam_match / max(1, n_per_family), 4))
            rep.radii.append(r)
            rep.agreement.append(round(matches / max(1, count), 4))
            rep.mean_distance.append(
                round(sum(dists) / max(1, len(dists)), 4))
            rep.omega_prob.append(round(flips / max(1, count), 4))
            rep.total += count
        return rep


# ─────────────────────────────────────────────────────────────
# Cross-domain transfer (geometry invariant, only Ω changes)
# ─────────────────────────────────────────────────────────────

@dataclass
class TransferReport:
    domains: list
    verdict_by_domain: dict           # domain -> verdict
    layer_by_domain: dict             # domain -> layer
    geometry_invariant: bool          # same evaluator structure everywhere
    omega_dependent: bool             # verdicts differ purely by Ω


def cross_domain_transfer(make_layer: Callable[[list], "GovernanceLayer"],
                          call: dict, domain_sets: list) -> TransferReport:
    """Run the SAME middleware geometry against different Ω (domain rule
    sets). Confirms the architecture is invariant while Ω mutates."""
    verdicts, layers, signatures = {}, {}, set()
    for ds in domain_sets:
        gov = make_layer(ds)
        key = "+".join(d.name for d in ds)
        r = gov.evaluate(call)
        verdicts[key] = r.verdict.value
        layers[key] = r.layer
        # geometry signature = the enforcement pipeline shape, Ω-independent
        signatures.add((gov.evaluator.enable_taint,
                        gov.evaluator.enable_forecast,
                        gov.evaluator.forecast_horizon,
                        type(gov.evaluator).__name__))
    return TransferReport(
        domains=[",".join(d.name for d in ds) for ds in domain_sets],
        verdict_by_domain=verdicts,
        layer_by_domain=layers,
        geometry_invariant=(len(signatures) == 1),
        omega_dependent=(len(set(verdicts.values())) > 1),
    )
