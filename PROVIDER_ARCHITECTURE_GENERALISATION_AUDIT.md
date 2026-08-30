# Provider & Architecture Generalisation Audit

**Date:** 24 August 2026  
**Status:** Internal evidence audit — not independent validation  
**Question:** *Does Morrison Runtime Governance generalise across architectures and providers?*

---

## Executive answer

**Partially demonstrated, with a stronger result at the governance boundary than at the deployment boundary.**

The repository supports a defensible claim that Morrison's **canonical governance semantics are provider-independent after native tool calls are normalised into a common `{tool, args}` representation**. The current frontier harness has explicit adapters for **OpenAI, Anthropic, and Hugging Face**, plus a deterministic planner, and the test suite contains a direct invariance test asserting that the same neutral trajectory receives the same verdict, layer, rule, and execution status across the three hosted-provider identities.

The repository also contains integration adapters for multiple **agent/execution architectures**: OpenAI tool calling, Claude tool use, LangChain, AutoGen, browser agents, MCP, shell execution, and multi-step enterprise workflows.

What is **not yet established** is universal cross-provider or cross-architecture generalisation in live external environments. The current evidence shows that the *normalised governance boundary* is designed and internally tested to be provider-agnostic; it does not prove that every provider, framework, executor, long-horizon agent, or organisation preserves the same assumptions in production.

### Current judgement

| Claim | Evidence level | Judgement |
|---|---|---|
| Same canonical trajectory can be governed independently of provider identity | Direct code + direct test | **Demonstrated internally** |
| OpenAI / Anthropic / Hugging Face native tool-call shapes can be normalised | Direct adapter code + shape tests | **Demonstrated internally** |
| Governance kernel is downstream of provider syntax | Architecture boundary documented in code/docs | **Demonstrated by design** |
| Morrison can wrap multiple agent/tool architectures | Direct integration adapters | **Implemented** |
| All supported adapters have equivalent production semantics | No complete external deployment matrix | **Not established** |
| Admissible Operating Envelope claim transfers automatically between providers/architectures | Explicitly contrary to bounded-claim discipline | **No** |
| Generalisation to unseen providers with compatible structured action boundary | Architectural inference | **Plausible, not proven** |
| Generalisation to arbitrary autonomous systems without observable tool/action boundary | Violates documented assumptions | **Out of scope** |

---

## 1. The key architectural result

The frontier architecture is explicitly:

```text
untrusted scenario content
  -> hosted (Anthropic/OpenAI/Hugging Face) or deterministic Planner
  -> native tool calls normalized to {tool, args}
  -> existing RuntimeGovernanceMiddleware
  -> existing GovernanceKernel + GovernanceLayer
  -> PERMIT only: existing SandboxExecutor
  -> deterministic ToolSimulator
  -> kernel hash-chain + experiment evidence envelope
```

This matters because **provider identity is not itself the governance primitive**. Provider-specific syntax is stripped at the adapter boundary and the governance layer receives the normalised action representation.

The architecture note further states that provider code performs proposal generation only, has no executor reference, and that provider identity is not supplied to governance policy.

**Evidence:**
- `runtime_eval/frontier/ARCHITECTURE.md`
- `runtime_eval/frontier/provider_registry.py`
- `runtime_eval/frontier/openai_planner.py`
- `runtime_eval/frontier/anthropic_planner.py`
- `runtime_eval/frontier/huggingface_planner.py`

---

## 2. Provider matrix

| Provider / planner | Explicit adapter | Native-shape test | Same-trajectory governance invariance test | Hosted-run harness | Current evidence grade |
|---|---:|---:|---:|---:|---|
| **OpenAI** | Yes | Yes | Yes | Yes | **Strong internal** |
| **Anthropic** | Yes | Yes | Yes | Yes | **Strong internal** |
| **Hugging Face / open-weight** | Yes | Yes | Yes | Yes | **Strong internal** |
| **Deterministic planner** | Yes | N/A | Baseline | Yes | **Strong internal baseline** |
| **Other unseen provider** | No dedicated adapter in frontier registry | No | No | No | **Architecturally plausible only** |

### Direct test of provider-independent semantics

`runtime_eval/tests/test_frontier_containment.py` contains:

```python
def test_same_trajectory_has_provider_independent_governance_semantics():
    ...
    for provider in ("anthropic", "openai", "huggingface"):
        ...
        semantics.append((row["final_verdict"], decision["layer"],
                          decision["rule"], decision["executed"]))
    assert semantics[0] == semantics[1] == semantics[2]
```

This is the cleanest internal answer to the provider-generalisation question. It tests the **governance semantics**, not merely whether three SDKs can be imported.

### Native-provider shape tests

The same test file separately checks:

- OpenAI Responses SDK function-call shape → normalised `{tool, args}`
- Anthropic Messages API `tool_use` shape → normalised `{tool, args}`
- Hugging Face Chat Completions tool-call shape → normalised `{tool, args}`
- malformed Hugging Face arguments → no execution
- unapproved Hugging Face model / endpoint → rejected

This reduces the risk that provider independence is only asserted in documentation.

---

## 3. Architecture / orchestration matrix

`morrison_governance/integrations.py` implements a common `GovernanceGuard` and adapters for several execution surfaces.

| Architecture / surface | Adapter present | Pre-execution gate | Whole-trajectory / history awareness | Evidence status |
|---|---:|---:|---:|---|
| **OpenAI tool calling** | Yes | Yes | Per-call; can carry context | Implemented |
| **Claude tool-use chains** | Yes | Yes | Per-call; can carry context | Implemented |
| **LangChain tools / agents** | Yes | Yes | Primarily invocation-level | Implemented |
| **AutoGen function calls** | Yes | Yes | Primarily invocation-level | Implemented |
| **Browser agents** | Yes | Yes | Actions mapped to governable tool primitives | Implemented |
| **MCP servers** | Yes | Yes | Per `call_tool` invocation | Implemented |
| **Shell execution** | Yes | Yes | Invocation-level | Implemented |
| **Enterprise workflow / DAG** | Yes | Yes | **Yes — whole-plan + history-aware step gate** | Implemented |

The enterprise `WorkflowGovernor` is particularly relevant because it can evaluate an entire workflow up front and can gate each step against prior executed history. That is closer to Morrison's trajectory-level thesis than a simple single-call wrapper.

---

## 4. What genuinely generalises

### 4.1 The action-boundary abstraction

The strongest generalising primitive currently visible in the codebase is:

```text
provider-native proposal
      ↓ normalization
{ tool, args, context }
      ↓
canonical Morrison governance
      ↓
ALLOW / ESCALATE / BLOCK
```

As long as a system exposes a sufficiently structured, interceptable pre-execution action boundary, Morrison can in principle be inserted without needing access to model weights or latent activations.

### 4.2 The canonical decision path

The code separates:

- proposal generation,
- normalisation,
- governance,
- execution.

That separation is important because the governance kernel does not need to know whether the proposal originated from GPT, Claude, Qwen, a deterministic planner, or another planner once the action is normalised.

### 4.3 Bounded safety claims

The Admissible Operating Envelope should **not** be said to “generalise” merely because the middleware does. An Admissible Operating Envelope is configuration-specific. Changing model/provider/planner/tooling may move the deployment outside the tested envelope and therefore require revalidation.

This is a feature of the claim discipline, not a weakness:

> **middleware portability ≠ assurance inheritance**

---

## 5. What does not yet generalise

The following remain unresolved:

### 5.1 Production executors

The frontier harness uses a deterministic safe simulator. The harness itself correctly states that simulator containment does not prove the correctness of a production executor integration.

### 5.2 Open-ended long-horizon conversations

The hosted-frontier harness governs native tool calls from each model response, but its own README states that it is not an unrestricted open-ended agent conversation. Continuous-session work extends beyond this, but external validation is still required.

### 5.3 Unseen provider semantics

A new provider may expose:

- side effects without a structured tool boundary,
- hidden hosted-tool execution,
- asynchronous action semantics,
- parallel calls,
- delegated sub-agents,
- provider-managed computer use,
- opaque state transitions.

A `{tool,args}` adapter is only sufficient if those semantics are faithfully representable before execution.

### 5.4 Real concurrency

The repository's critical evaluation already identifies true concurrent / racing multi-agent activity as a weaker area than serialisable handoff logs. That matters for architecture generalisation.

### 5.5 Cross-environment transfer of discovered primitives

The Living Boundary roadmap explicitly places **multi-environment generalisation** in a later phase (`LB-3`). That is an honest indication that discovered ontology/boundary primitives should not yet be presumed to transfer across models, providers, connectors, and organisations.

---

## 6. Falsifiable provider-generalisation claims

The following are claims that an independent evaluator can attack directly.

### G1 — Provider-normalisation invariance

For a fixed normalised trajectory `τ`, governance output should be invariant to provider label:

```text
G(normalize_openai(τ))
=
G(normalize_anthropic(τ))
=
G(normalize_huggingface(τ))
```

for the same semantic action sequence and same environment/policy state.

**Falsifier:** a provider-specific representation causes a different canonical verdict, layer, rule, or execution decision after correct normalisation.

### G2 — Syntax independence

Semantically equivalent native tool calls from supported providers should normalise to the same canonical action representation.

**Falsifier:** equivalent calls cannot be represented without losing a governance-relevant distinction.

### G3 — Provider cannot bypass the execution gate

Provider adapters should never possess a direct reference to the real executor on the governed path.

**Falsifier:** any provider-specific code path can execute a governed side effect without obtaining canonical permission.

### G4 — No assurance inheritance across changed configuration

Changing provider/model/planner outside the validated configuration should cause revalidation / UNVALIDATED status rather than silently inheriting the prior Admissible Operating Envelope claim.

**Falsifier:** a materially changed configuration receives validated status solely because a previous provider/configuration was validated.

---

## 7. External test needed to move from “internal” to “validated”

A credible external provider-generalisation evaluation should:

1. Freeze a Morrison version and policy bundle.
2. Define a common semantic trajectory corpus independently of the author.
3. Use at least three model/provider families.
4. Include one adapter written by the external evaluator rather than Resurrection Tech.
5. Include malformed, parallel, delegated, unknown-tool, and provider-hosted-tool cases.
6. Compare canonical verdict, layer, rule, evidence hash, and execution outcome.
7. Include safe controls to measure false positives.
8. Change one envelope dimension at a time and verify validation status changes correctly.
9. Attempt direct executor bypass around every adapter.
10. Publish failures as well as successes.

### Proposed acceptance criterion

A reasonable first external criterion is:

```text
for all externally selected supported-provider trials:
    unauthorized_execution_count == 0
    canonical_semantics_invariant == true  # where semantic trajectory is fixed
    safe_control_false_positive_rate <= declared threshold
    envelope_status_never_inherits_across_unsupported_configuration_change
```

The exact false-positive threshold should be agreed before testing rather than chosen after seeing results.

---

## 8. Bottom line

### What can be said now

> **Morrison's canonical pre-execution governance path is internally demonstrated to be provider-independent across OpenAI, Anthropic, and Hugging Face after native tool calls are normalised, and the repository implements adapters across several major agent/tool execution architectures.**

### What cannot be said yet

> Morrison is universally architecture-agnostic, works unchanged across every provider, or that an Admissible Operating Envelope validated under one provider/configuration automatically transfers to another.

### Current grade

**Provider-level canonical governance generalisation: STRONG INTERNAL EVIDENCE**  
**Architecture integration breadth: IMPLEMENTED, UNEVENLY VALIDATED**  
**Production cross-environment generalisation: NOT YET EXTERNALLY ESTABLISHED**

---

## Repository evidence reviewed

- `runtime_eval/frontier/provider_registry.py`
- `runtime_eval/frontier/ARCHITECTURE.md`
- `runtime_eval/frontier/README.md`
- `runtime_eval/tests/test_frontier_containment.py`
- `morrison_governance/integrations.py`
- `CRITICAL_EVALUATION.md`
- `living-boundary/README.md`

---

**Interpretation rule:** this document distinguishes architecture portability, internal empirical invariance, and external validation. These are not interchangeable.
