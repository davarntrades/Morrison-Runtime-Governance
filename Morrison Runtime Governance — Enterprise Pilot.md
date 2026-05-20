<div align="center">

# Morrison Runtime Governance — Enterprise Pilot

**Structural Safety Assessment for Autonomous AI Systems**

Resurrection Tech Ltd · UK Patents GB2600765.8 · GB2602013.1 · GB2602072.7 · GB2602332.5

</div>

-----

## What We Deliver

A runtime governance layer that intercepts unsafe executable trajectories before tool execution occurs. Deployed as middleware between your LLM planner and tool execution layer. No model retraining. No fine-tuning. No prompt engineering.

```
Your LLM Planner → Morrison Governance Middleware → Tool Execution
```

Unsafe trajectories are blocked. Safe operations proceed. The governance layer is model-agnostic.

-----

## Pilot Scope

|Phase                          |Duration |Deliverable                                                               |
|:------------------------------|:-------:|:-------------------------------------------------------------------------|
|**1. Architecture Assessment** |Week 1   |Map your agent stack, tool definitions, and Ω domain requirements         |
|**2. Ω Configuration**         |Week 2   |Define domain-specific forbidden states for your operational environment  |
|**3. Middleware Integration**  |Weeks 3–5|Deploy governance layer into your agent pipeline (staging)                |
|**4. Validation**              |Weeks 5–7|Run evaluation suite: safe/unsafe separation, attack scenarios, edge cases|
|**5. Report + Production Path**|Week 8   |Full assessment report with production deployment plan                    |

-----

## What You Need to Provide

- Access to your agent architecture documentation (tool definitions, planner outputs)
- A staging environment for middleware integration
- Domain-specific requirements: what must never happen in your system
- An engineering point of contact (1–2 people)

-----

## What You Get Back

- **Governance middleware** configured for your stack (OpenAI / LangChain / AutoGen / MCP / custom)
- **Domain Ω definitions** formalising your operational forbidden states
- **Evaluation report** with exact safe/unsafe separation metrics across your operational scenarios
- **Attack surface analysis** covering chained attacks, delayed intent, privilege escalation, data exfiltration
- **Production deployment plan** with integration architecture and operational recommendations

-----

## Pricing

This is operational assurance infrastructure for autonomous systems. **The
governance layer is priced against the cost of Ω becoming reachable — not the
complexity of the software.** Pricing scales with operational blast radius,
regulatory exposure, infrastructure criticality, and catastrophic downside.

|Pathway                                  |Positioned as                                             |Investment   |
|:----------------------------------------|:---------------------------------------------------------|:------------|
|48-Hour Runtime Governance Audit         |Catastrophic trajectory exposure assessment               |£40K–75K     |
|Structural Safety Pilot (4–8 weeks)      |Staging deployment and operational governance integration |£250K–750K+  |
|Advisory Retainer                        |Ongoing Ω evolution, threat-surface monitoring, runtime governance maintenance, incident review, model/planner revalidation|£35K–100K/mo|

|Enterprise / domain integration          |Investment |
|:----------------------------------------|:----------|
|Finance / Banking Infrastructure         |£1M–5M+    |
|Healthcare / Clinical Systems            |£750K–3M+  |
|Cybersecurity / Infrastructure           |£750K–3M+  |
|Data Privacy / Compliance                |£1M–4M+    |
|Enterprise Autonomous Systems            |£500K–2M+  |
|Insurance / Actuarial Governance         |£750K–3M+  |
|Defence / Sovereign Infrastructure       |£5M–25M+   |

**ARR target:** £500K–2M+ per client annually · **Sovereign / defence
retainers:** £1M–5M+/yr. Full rationale in
[Pricing Strategy.md](Pricing%20Strategy.md).

-----

## Validated Across

- **GPT-4o** — 9,095 evaluations
- **Qwen2.5-0.5B** — 10,000 evaluations
- **Qwen2.5-7B** — 200 evaluations (real planner)
- **Llama-3.1-8B** — 240 hard stress scenarios
- **Total: 129,541 evaluations. 0 false positives. 0 false negatives.**

The governance layer was unchanged across all models.

-----

## Contact

**Davarn Morrison**
Founder — Resurrection Tech Ltd
GitHub: [github.com/davarntrades](https://github.com/davarntrades)

-----

## Licensing

Commercial deployment is subject to licence. Evaluation does not grant
production deployment rights. Evaluation, benchmarking, and academic reference
are permitted for non-commercial purposes; commercial deployment, production
use, resale, sublicensing, or integration into revenue-generating systems
requires a written commercial licence from Resurrection Tech Ltd. Certain
implementations may be covered by granted and/or pending intellectual property
owned by Resurrection Tech Ltd, including **UK Patent GB2600765.8**. Full
terms: [`License.md`](License.md).

-----

<div align="center">

*If your AI systems can execute actions, they can execute catastrophic ones.*
*This layer determines whether those trajectories are reachable before execution occurs.*

© 2026 Davarn Morrison — Intelligence Invariant™ · All Rights Reserved

</div>
