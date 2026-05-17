# Critical Evaluation — Morrison Runtime Governance

A deliberately skeptical self-assessment, written for an independent
reviewer. It answers hard questions directly, including the unflattering
answers. Nothing here is marketing. Where a claim is empirical-within-tests
rather than proven, it says so.

**TL;DR verdict.** This is a *deterministic, structural, pre-execution
guard library* with an integrated layered hierarchy (A_safe → V2 → V3 →
V4 → V4+ → V5) and an unusually honest gap-disclosure discipline. Its
real strengths are determinism, reproducibility, additive evolution with
zero regression, and change-detector pins that flip on either a fix or a
regression. Its real limits are that every threat, perturbation, and
assumption it is tested against is **author-defined**, the A_safe layer
is keyword-based and demonstrably bypassable, and the "guarantees" are
empirical within a self-authored suite, not formal proofs. It is a
credible *engineering* contribution and a deployable guard component; it
is **not** a verified safety system and does not claim to be.

---

## 1. Does it generalize outside the tested Ω definitions?

**Partially, and asymmetrically by layer.**

- The **geometry is Ω-agnostic**: the same middleware pipeline (taint,
  reachability, admissibility, perturbation distance) is invariant while
  only Ω changes. This is demonstrated, not asserted —
  `test_cross_domain_substitution.py` runs fixed trajectories across 7
  domain Ω sets and shows an identical pipeline signature; the verdict
  tracks Ω only.
- **A_safe does NOT generalize.** It is single-step keyword/pattern
  matching. Tool-name spoofing (~86% bypass) and keyword obfuscation
  (~60% bypass) are measured and documented in `LIMITATIONS.md`. Any new
  Ω expressed as keyword rules inherits this brittleness.
- **V2/V3/V5 generalize better but bounded.** V2 taint and the V3
  forecaster are structural (capability + argument geometry), and
  v0.4.1 explicitly extended them to open-world (unknown) tool names.
  But they generalize *within the modeled structural vocabulary and
  successor model* — not to attack structure that has no footprint in
  the trajectory or environment model.

Net: the *architecture* generalizes across domains; the *weakest layer*
does not generalize across surface forms. Honest rating: **moderate,
with a clearly identified brittle floor.**

## 2. What hidden assumptions exist?

These are load-bearing and mostly implicit in the design:

1. **The trajectory is observable before execution.** Everything is
   pre-execution interception. An agent that acts without emitting an
   inspectable structured tool call is out of scope.
2. **Actions are structured (`tool` + `args`).** Free-form effects,
   side-channels, or natural-language "do X" without a tool boundary are
   invisible.
3. **Taint is monotone within a trajectory and never cleared by
   sanitization.** Deny-by-default: a genuine `read → redact → send` is
   blocked unless the sink is allowlisted. Correct posture, but it
   assumes operators configure allowlists correctly.
4. **"External unless explicitly internal."** Safety depends on correct
   `internal_url_hosts` / `internal_email_domains` / `destination_internal`
   configuration. Misconfiguration silently widens or narrows the gate.
5. **Determinism of the decision path.** True for this library (no
   RNG/clock/IO in the decision path). It governs the *plan*, not the
   nondeterministic *execution*; it cannot bound runtime side effects.
6. **Multi-agent activity can be flattened to a causal order.** Real
   concurrency, interleaving, and race conditions between agents are not
   modeled — `MultiAgentSession` assumes a serializable handoff log.
7. **V3 follows *encoded* future intent only** (deferred/looped/priv
   structure). A purely implicit future attack with no structural
   footprint is by-design out of scope.
8. **V4+ feasibility is bounded by caller-supplied candidates.** It
   cannot prove global infeasibility, only infeasibility within the
   presented options.
9. **V5 robustness is relative to 9 modeled perturbation families.** "Stable"
   means stable against those, not against an arbitrary perturbation axis.

None of these are hidden in `LIMITATIONS.md` — but several are implicit
in the API and worth stating plainly, as above.

## 3. What are the failure boundaries?

Concretely (all documented and, where measurable, quantified):

- **Tool-name spoofing** — ~86% A_safe bypass (case/hyphen/zero-width/
  homoglyph). Mitigation (NFKC normalization) not yet implemented.
- **Keyword obfuscation** — ~60% bypass (base64/hex/unicode); full
  coverage is undecidable (runtime string construction).
- **Implicit-future attacks** — no structural footprint ⇒ V3 cannot
  project them.
- **Post-execution / runtime effects** — not governed at all; this is a
  pre-execution gate.
- **Semantic intent** — no understanding of meaning; a structurally
  benign call with malicious semantics passes.
- **Feasibility** — bounded by candidate set (§2.8).
- **Perturbation robustness** — bounded by modeled families (§2.9).

The system's failure *mode* is deliberately biased toward **under-block
(refuse) rather than silent over-permit**, which is the right direction
for a safety component but produces false positives that must be managed
operationally.

## 4. How brittle is the environment modeling?

**Brittle as a world-model; robust as a reproducible estimator.**

V3's environment evolution is a *small, fixed, deterministic operator
set* (`permission_drift`, `schema_mutation`, `hidden_tool_injection`,
`retry_loop`). V5's manifold is **9 parameterized perturbation
families** with a *structural* (non-semantic) distance metric. These are
explicitly **models, not the world**. The honest characterization:

- It will not anticipate an environmental dynamic outside its operator
  set or family union. That is brittle.
- But it is *deterministic and reproducible*, the distance metric is
  explicit, and outputs are reported as **estimates with a stated margin
  and collapse threshold — not proofs**. The brittleness is disclosed,
  bounded, and fails toward refusal.

So: do not read V3/V5 as environmental *verification*. Read them as a
reproducible, conservative reachability/robustness *estimator*.

## 5. How does it behave under unseen planners?

`test_cross_model_planner.py` shows verdict **and blocking-layer**
invariance across GPT-/Claude-/Qwen-/Llama-/stochastic-decoding planner
profiles, and `interception.py` shows the forbidden egress never executes
under any profile.

**Important caveat (stated honestly):** these profiles are
*deterministic structural transforms standing in for* planner
divergence — reorderings, inserted retries, decomposition, verbosity —
**not real LLM outputs**. The defensible claim is: governance is
invariant to the *structural transformations these profiles model*, and
v0.4.1's open-world inference reduces tool-name dependence. It is **not**
a proof of invariance against every real, unseen planner. A real model
emitting genuinely novel structure could still find the documented
A_safe surface-form gaps.

## 6. Can independent teams reproduce the results?

**Yes, with low friction — this is a genuine strength.**

- Pure Python stdlib, no network, no external datasets.
- No RNG/clock/IO in the decision path; all generators take an explicit
  seed; authors claim `PYTHONHASHSEED`-invariance; cross-process
  byte-identical replay is tested.
- Every suite is a runnable script printing `N passed, M failed`:
  `python3 morrison_governance/test_*.py`. Visualizations regenerate
  deterministically.
- 18 suites / 171 cases; the original 120 are byte-for-byte unchanged
  across versions.

**Caveat:** reproducibility ≠ external validity. A team will reproduce
*the authors' results on the authors' tests*. There is no third-party
benchmark, held-out adversarial corpus, or real-incident dataset. See §7
and §10.

## 7. Is the evaluation methodology sound?

**Sound for what it measures; limited in scope of what it measures.**

Strengths:
- Deterministic, layer-ablated (`evaluate_all` shows every firing layer
  without short-circuit masking).
- Explicit FP/FN accounting on the legacy suite (0/0 claimed and tested).
- Change-detector pins: gaps are *pinned as tests* so a regression OR a
  genuine fix is forced to surface (demonstrated in the v0.4.0→v0.4.1
  transition).
- "Attacks assumptions, not examples" (`redteam.py`) is a better
  methodology than a static attack-string corpus.

Weaknesses (material):
- Tests, adversarial variants, perturbation families, and assumption
  probes are **all author-defined** (selection bias — §10).
- Pass/fail counts, not effect sizes or FP-rate on a large natural
  workload. "171/171" measures internal consistency, not coverage.
- No external/independent red team; the adversarial harness is
  self-specified.
- "100% pass" is a property of a self-authored suite and must not be
  read as "100% safe."

## 8. Is the creator overstating claims or carefully bounded?

**Predominantly carefully bounded, with two honest cautions.**

The discipline is unusually good: `LIMITATIONS.md` quantifies bypass
rates, marks by-design limits, and the project repeatedly chose
"under-block / surface the gap honestly" over "force a patch." The
v0.4.0 red-team harness *deliberately surfaced its own two gaps*, which
v0.4.1 then closed additively. That is the opposite of overstating.

Cautions:
1. **Wording.** Words like "enforced", "closed", "guarantee" appear.
   They are accurate *empirically within the test suite*; they are **not
   formal guarantees**. A reader should mentally append "demonstrated on
   the provided deterministic suite."
2. **Promotional headers.** Patent / "© Resurrection Tech" / commercial
   license language in source headers is marketing context, orthogonal
   to and not evidence for the technical claims. Evaluate the code, not
   the letterhead.

`Safe(local) ⇏ Safe(global)` is a real, demonstrated property of the
hierarchy — but "demonstrated on encoded structures," not "proven for
all trajectories."

## 9. Could this integrate into real enterprise stacks?

**As a guard library: yes. As a turnkey control plane: no.**

- `integrations.py` ships adapters for OpenAI tool calls, Claude tool
  use, LangChain, AutoGen, MCP, browser actions, and a workflow
  governor — the pre-execution-middleware pattern is realistic and
  deployable.
- Audit primitives exist: deterministic `trajectory_hash`, per-verdict
  layer/mechanism metadata, `evaluate_all` for attribution.

Practical gaps for enterprise:
- It is a *library*, not a platform: no policy-management UI, no
  persistence, no distributed/shared taint state, no RBAC over the rules
  themselves.
- Config burden: Ω rules + internal allowlists must be authored and
  maintained per organization; misconfiguration degrades safety silently
  (§2.4).
- False-positive operations cost under deny-by-default must be owned by
  a team.
- Latency is low per call but rule matching is a linear scan and
  cross-turn taint requires re-evaluating a growing prefix (§11).

Verdict: a strong **drop-in guard component**; integration is real but
non-trivial and requires an owning team.

## 10. Is there hidden selection bias in the tests?

**Yes — and it is the single most important caveat. Stated plainly:**

The system is evaluated against threats the authors conceived and
encoded. Tests, adversarial variants, perturbation manifolds, planner
profiles, and even the red-team "assumptions" are author-enumerated. The
"attacks assumptions, not examples" harness *reduces* but does not
*eliminate* this — the assumption list is still the authors'. There is
no independent adversary, no real-world incident corpus, no external
benchmark.

What the suite legitimately proves: internal consistency, determinism,
zero regression, and that the *documented* gaps are real and pinned.
What it does **not** prove: coverage of the unknown threat space, or
safety against an adversary who did not read `LIMITATIONS.md`. A serious
external evaluation would require a third-party red team and a held-out
adversarial set. Treat the 171/171 as a *regression and consistency*
metric, not a *security coverage* metric.

## 11. Is the architecture scalable operationally?

**Scalable per-call and stateless; weak on long sessions.**

- Decision path is O(states × rules) plus a *bounded* V3 rollout
  (`max_nodes` cap) plus V5 *sampling* (radii × families × n). No IO,
  deterministic ⇒ trivially horizontally scalable and cacheable by
  `trajectory_hash`.
- Linear rule scan (no index) — fine for hundreds of rules, would need
  indexing at thousands.
- The real scaling weakness: the fail-closed interceptor re-evaluates
  the **growing trajectory prefix** each turn, which is O(n²) over a long
  session. Production use over long-horizon agents needs incremental
  taint/priv state instead of prefix replay. This is a known, fixable
  engineering item, not an architectural dead end.

## 12. How does it compare to adjacent safety/control literature?

Positioned honestly relative to neighbors:

- **Output guardrails / content classifiers** (Llama Guard, NeMo
  Guardrails): those are semantic/content filters on text. This is
  pre-execution *trajectory/capability* geometry. **Complementary, not
  competing** — it catches structural exfiltration a content filter
  misses, and misses semantic intent a classifier catches.
- **Information-flow control / taint tracking** (classic IFC: Flume,
  Asbestos; language-level taint): V2 is a *coarse dynamic taint over
  the tool-call graph*. Far less formal than IFC (no lattice, no
  declassification calculus) but applied pragmatically to agent tool
  use.
- **Safe RL / shielding & model checking** (e.g., shielding via
  automata): V3 reachability is a *lightweight, non-exhaustive analog*
  without a formal model or verified automaton. It is an estimator, not
  a verified shield.
- **AI Control** (Redwood-style "assume the model is untrusted, enforce
  externally"): philosophically aligned — external, pre-execution,
  model-agnostic enforcement. But this is *heuristic structural*
  enforcement, not a red-team-validated control protocol with capability
  evaluations.
- **Capability-based security / syscall sandboxing**: the deny-by-default
  external-sink gate is effectively a capability gate; the closest
  classical analogy, re-expressed for LLM tool use.

**Novelty claim, bounded:** the contribution is an *integrated,
deterministic, additively-evolved hierarchy* combining taint +
reachability estimation + structural admissibility + perturbation
testing for agent tool-use, with rigorous reproducibility and honest
gap-pinning. It is an **engineering synthesis with empirical guarantees**,
not a new theoretical safety result, and it does not supersede formal IFC
or verified shielding where those apply.

---

## Bottom line for a reviewer

Trust it for what it demonstrably is: a deterministic, reproducible,
honestly-bounded pre-execution structural guard with strong regression
discipline. Do **not** trust it as a proven safety guarantee or as
evidence of coverage against novel adversaries — its evaluation is
internally rigorous but author-scoped, and its weakest layer is
keyword-brittle by its own measurement. The most credible thing about
the project is that it says all of this itself, in `LIMITATIONS.md` and
here, rather than hiding it.
