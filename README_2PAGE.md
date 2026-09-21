# Morrison Runtime Governance (Two-Page Brief)

## Runtime control layer for AI systems

Morrison Runtime Governance is a **runtime control layer for AI systems** that **governs tool-using autonomous agents** and **blocks unsafe AI actions before execution**.

It is built for enterprise teams running agents that can move money, access credentials, call APIs, execute shell commands, write files, and coordinate across multi-agent workflows.

---

## What this solves

Before an unsafe action executes, this layer is designed to stop:

- **Unauthorized transfers** (payments/trades/money movement)
- **Credential theft** (`.env`, tokens, secrets, key material)
- **Unsafe shell execution** (injection, destructive commands, privilege abuse)
- **Data exfiltration** (sensitive data sent to external endpoints)
- **Unsafe autonomous workflows** (multi-step or multi-agent paths that become dangerous over time)

---

## Proof snapshot (bounded, reproducible)

- **Evaluations reported in-repo:** 129,857
- **Tested planners/models:** GPT-4o, Qwen, Llama (governance layer unchanged)
- **Observed outcomes in current suites:** zero observed false positives / zero observed false negatives
- **Hardening evidence (reported):** baseline bypasses reduced to zero in the runtime hardening suite
- **Multi-agent evidence (reported):** shared-global + deny-by-default quorum improves collusion detection with zero over-blocks in tested scenarios
- **Reproducibility:** deterministic replay is part of the runtime evidence path

**Bounded-claim caveat:** results are bounded to tested environments, corpora, and configurations in this repository. Independent validation is encouraged before production rollout.

---

## Why existing guardrails fail (operationally)

Most guardrails inspect prompts or generated text. Real incidents often happen in tool execution:

- A reply may look harmless while a tool call initiates a transfer.
- A model can summarize safely while another step reads secrets and posts externally.
- A single step may appear benign, but the full chain reaches a catastrophic outcome.

Example:

- `read_file(".env")` → intermediate processing → `http_post("external", payload=secrets)`

Text moderation can miss this because each message looks acceptable. Runtime governance blocks the **action path** before execution.

---

## Deployment framing (enterprise-first)

This system is designed for teams that need:

- runtime safety controls with deny-by-default behavior
- deterministic audit logs for incident review and compliance
- model/planner independence (planner is treated as untrusted)
- controls that remain effective as model providers change

It is positioned as deployable infrastructure, not a prompt-only policy layer.

---

## 48-hour runtime safety audit (engagement)

For organizations with incidents, near-misses, or visible instability in agent workflows.

**Inputs**

- tool definitions
- planner output format
- domain and runtime context

**Deliverables (within 48 hours)**

1. Executable trajectory analysis
2. Reachable catastrophic-state map
3. Blocked vs permitted path partition (with reasons)
4. Timestamped deterministic audit logs
5. Prioritized risk surface summary
6. Middleware/policy integration recommendations

---

## 90-second architecture view

Operationally, the layer sits between planner output and tool runtime:

1. Planner proposes tool actions
2. Governance evaluates the full executable path
3. Unsafe paths are blocked before execution
4. Safe paths are permitted and logged with attribution

This makes the planner **untrusted by default** and governance the final execution gate.

---

## Technical framing (introduced after risk/evidence)

After deployment framing, the formal view is:

- govern **executable trajectories** rather than text outputs
- maintain safety boundary so catastrophic regions are unreachable under enforced policy
- formal objective commonly represented as **ℛ(t) ∩ Ω = ∅** under configured constraints

Layered hierarchy (deeper controls) includes:

- immediate unsafe-action blocking
- source→sink data-flow / taint protections
- forward reachability checks for delayed-risk chains
- structural/policy validation for tool calls
- no-safe-path refusal behavior
- environment-sensitivity and stability checks

This preserves both practical operations and formal assurance framing.

---

## What it prevents in production

### Financial and operational abuse

- unauthorized transfers, payments, trades
- shell abuse, command injection, privilege escalation
- destructive or unreviewed tool/repo actions

### Data and compliance exposure

- credential/secret extraction and exfiltration
- PII/PHI leakage to external destinations
- cross-domain combinations of acquisition + privilege + egress

### Advanced evasion patterns

- encoded payload hiding (base64/hex/url/unicode escapes)
- semantic renaming of unsafe actions
- nested/delegated sub-actions hidden in wrappers
- delayed multi-step chains where no single step appears catastrophic

### Multi-agent failure modes

- role-split collusion (one agent acquires, another exfiltrates)
- shared-state contamination and staged leakage
- delegation chains obscuring responsibility
- fail-open risk after partial agent failure

---

## Quick reproducibility path

```bash
python3 quickstart.py
python3 quickstart.py --cinematic
```

The quickstart demonstrates permit/block behavior, per-layer attribution, and deterministic replay behavior in the local bounded environment.

---

## Honest scope and trust posture

- Claims are bounded to tested environments and suites in this repository.
- “Zero observed false positives/negatives” refers to current bounded evaluations, not universal guarantees.
- Planner is treated as untrusted; governance is the runtime decision layer.
- Independent validation and red-team testing are encouraged before production-critical deployment.

---

## Where to read deeper evidence

- Main repository context: `README.md`
- Runtime hardening details: `runtime_eval/HARDENING.md`
- Runtime evaluation package: `runtime_eval/README.md`
- Multi-agent evaluation: `multi_agent_eval/README.md`
- Shared-global governance: `global_governance/README.md`
- Additional evidence/context: `CRITICAL_EVALUATION.md`, `RELEASE_NOTES.md`, `48-Hour Runtime Safety Audit.md`
