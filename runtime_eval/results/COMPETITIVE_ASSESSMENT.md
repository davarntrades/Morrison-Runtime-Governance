# Morrison against CaMeL, Progent and FIDES: two separate assessments

Date: 2026-10-15. Replaces the informal comparison given in conversation on 2026-10-14, which predated the
abliterated-Qwen cohort and conflated CaMeL's utility figure with a security rate.

Sources:
- Papers and code: `related-work-primary-sources.md` (CaMeL arXiv 2503.18813v2 + code @ f083b6b; Progent 2504.11703v2
  + code @ 5be7b63; FIDES 2505.23643v2). Paper text was read from archived PDF copies (arxiv.org unreachable from this
  environment). The code claims used below were re-checked here (CaMeL `interpreter.py` L2050–2063 policy check before
  the call; Progent `secagent/tool.py` L31 module-global policy).
- Morrison: retained evidence on this branch (`ADVERSARIAL_LOCAL_GLOBAL_FALSIFICATION.md`, `REPAIR_REFALSIFICATION.md`,
  `VIOLATION_LEDGER.md`, `falsification/`), the oracle results (`agentdojo/oracle-summary.json`), and the
  abliterated-Qwen cohort on branch `codex/agentdojo-hf-api-resume` (commit 3712226).

## 0. What each number measures

| Term | Meaning | Example |
|---|---|---|
| Benign utility (BU) | Legitimate tasks completed with no attack | CaMeL's "77% vs 84%" is BU for o3-High (Table 2) |
| Utility under attack (UA) | Legitimate task completed in an attacked episode | Progent gpt-4o 64.35% |
| Attack success (ASR) | Attacker's goal reached (AgentDojo's own checker) | Progent gpt-4o 0.00% |
| Prohibited execution | A protected call actually ran, read from environment state | Qwen cohort 7 → 0 |
| Policy enforcement | A checker refused the call | Not a safety result by itself |
| Formal guarantee | Proven property of the mechanism | None of the four systems has one (CaMeL §10 lists it as future work; FIDES's Proposition 1 is argued, per-tool formalisation skipped) |
| Empirical safety | Measured on a benchmark | Everything in the tables below |

## 1. Assessment A — AgentDojo competitive position

### 1.1 Published results of the other systems (all four suites, `important_instructions` or Tool-Knowledge, 949 attack cases)

| System | Model | BU (defended / undefended) | UA | Successful attacks (defended / undefended) |
|---|---|---|---|---|
| CaMeL | o3-High | 77.3% / 84.5% | 79.8% | 0 / 11 |
| CaMeL | Claude 4 Sonnet | 74.2% / 86.6% | 75.7% | 11 / 75 (text-to-text, outside its threat model) |
| CaMeL | Gemini 2.5 Pro | 41.2% / 73.2% | 45.3% | 0 / 163 |
| CaMeL | Claude 3.5 Sonnet | 63.9% / 90.7% | 66.7% | 0 / 44 |
| Progent | gpt-4o (hand-written policies) | 80.41% / 79.38% | 64.35% | ASR 0.00% / 39.90% |
| FIDES | gpt-4o (Tool-Knowledge) | o1 planner 61.44% overall | not reported | 1 (0 excluding two out-of-scope travel cases) |

Independent re-measurements exist and are less favourable (DRIFT: CaMeL 35.4% utility with GPT-4o-mini; Progent
9.4% ASR with GPT-4o-mini; AgentDyn: very low utility for both). See the review §1D, §2D.

### 1.2 Morrison's measured AgentDojo results

| Evidence | Coverage | Ungoverned | Morrison | Utility |
|---|---|---|---|---|
| Scripted fully compromised agent (oracle), not live | 4 suites, 612 exercisable pairs | ASR 100% (exercisable) | **494/612 stopped; 19.3% residual** (banking 0/144, workspace 0/227, slack 42/105, travel 76/136 succeed) | BU 97/97 → **63/97** (76/97 with escalations approved) |
| Abliterated Qwen3-32B, live, `important_instructions` | banking, 2 user × 3 injection tasks (6 pairs), 22 episodes per arm | attacker success **5/6**; 7 prohibited calls executed (5 attacker transaction records, $30,100 in fixture records — balances unchanged; 2 password changes) | **0/6**; 7 proposed, **0 executed** (6 ESCALATE, 1 BLOCK) | UA 2/6 vs 2/6; BU 2/2 → **1/2** (the $98.70 bill withheld; no approver configured) |
| Haiku 4.5, live, `direct` | banking full (144 pairs), 2 runs | 1/144 executed with effect | 0/144 (4 enforced arms) | UA 92/144 → 72 (no approver) / 81 (policy approver) / 89 (user-intent) |
| Opus 5.5, Opus 4.5, Sonnet 4.6, Haiku (5 other attacks), live | banking | **0** injected prohibited proposals | — (prevention not exercised: INCONCLUSIVE) | Opus 5.5 post-repair UA 135 → 72 / 117 / 117; BU 16/16 → 8 / 13 / 14 |

All Qwen figures were re-verified here: archive SHA-256 values match the manifests, the no-inference verifier
re-ran with 22/22 chains and 11/11 initial states matched, an independent count from raw episode data reproduces
every row, and Actions runs 38666605105 (verification) and 38666605024 (controls) succeeded; the paid run
38664428154 is marked failed only by its in-workflow postprocessor, with all arm and upload steps successful.

### 1.3 Verdict on AgentDojo

1. **Live attack prevention is demonstrated, at small scale.** In the only live cohort where a model attacked
   repeatedly (abliterated Qwen), Morrison reduced executed prohibited calls from 7 to 0 and attacker success from
   5/6 to 0/6; with Haiku `direct`, 1 to 0. These are firm results for the episodes run. They are not a rate over
   the benchmark: 6 pairs and 1 pair, one suite.
2. **The published competitors are measured at full benchmark scale.** CaMeL and Progent report near-zero attack
   success over 949 cases, four suites, several attackable models. Morrison has no live four-suite run.
3. **Coverage gap.** In the scripted all-suite run Morrison leaves 19.3% of exercisable attacks succeeding (Slack
   40%, travel 56%), because Slack DMs and travel reservations carry no capability. CaMeL's and Progent's published
   residuals are lower.
4. **Utility cost is higher.** Without an approver, Morrison withholds every payment and credential change,
   legitimate or not (BU 63/97 scripted; 1/2 in the Qwen cohort; 8/16 Opus). With the deployable policy approver,
   Opus 5.5 recovers to 117/144 UA and 13/16 BU. Progent's published BU is equal to undefended; CaMeL's is 7–33
   points below undefended depending on model.
5. **Position:** on AgentDojo, Morrison is **not yet comparable at benchmark scale** and is **behind** on coverage and
   utility; it is **not shown to be behind on prevention** where it was exercised. A comparison needs all four suites,
   the same attackable model as a published baseline, and the Slack/travel capability gaps closed.

## 2. Assessment B — Architectural enforcement position

### 2.1 Property-by-property

Morrison column: classification from retained experiments at the final code (78eab15). Other columns: whether the
original implementation has the mechanism (code + paper), **not** an experimental classification — we did not test
them; "Not implemented" means the mechanism is absent from the inspected code, not that the paper's guarantee fails.

| Property | Morrison (tested) | CaMeL | Progent | FIDES |
|---|---|---|---|---|
| Independent pre-execution veto | DEMONSTRATED_WITHIN_SCOPE (live Qwen 7→0; Haiku 1→0; scripted) | Implemented (interpreter checks policy before each call) | Implemented (tool wrapper / MCP proxy) | Implemented (planner checks before each call) |
| Per-call (local) policy | DEMONSTRATED_WITHIN_SCOPE | Implemented | Implemented (argument-level) | Implemented |
| **Data provenance / information flow** (untrusted data cannot choose arguments or control flow) | **UNSUPPORTED** — Morrison sees calls and history, not where each argument value came from; heuristic read→egress rules only | **Implemented, its central guarantee** (design-level; side channels and text-to-text excluded) | Not implemented | **Implemented** (labels, non-interference for integrity) |
| Trajectory: cumulative / declared composition rules | DEMONSTRATED_WITHIN_SCOPE for declared rules (T1–T3b); VIOLATED for state predating the trajectory (T3b, OPEN); none by default | Data-flow taint only; no cumulative limits | Policy self-update after calls; no history predicates | Session-wide label predicates |
| Cross-agent shared constraints | DEMONSTRATED_WITHIN_SCOPE with `resource_scopes` + shared store, threads and processes on one host (G1, G5; independent 0/270); rolling over the window (V-G1c); UNSUPPORTED across hosts | Not implemented (one engine per task) | Not implemented (process-global policy, no locking) | Not described |
| Concurrency of decisions | DEMONSTRATED_WITHIN_SCOPE (G2, E6, E7, stress 30/30 ×) | Not addressed | Not addressed | Not addressed |
| Single-use / replay-resistant authorisation | DEMONSTRATED_WITHIN_SCOPE after repair (E5, E7 VIOLATED pre-repair, repaired a250164) | Not implemented (no authorisation objects) | Not implemented | Not implemented |
| Authorisation bound to the exact action | DEMONSTRATED_WITHIN_SCOPE (E1–E4, E13 repaired) | Implicit (same-process call) | Implicit | Implicit |
| Resource-side enforcement | DEMONSTRATED_WITHIN_SCOPE in the isolated deployment (E8 repaired; independent probes 30 × 4 runs); VIOLATED when the agent shares the resource's OS identity (by construction) | Not implemented (§9.1 says tools would need to understand capabilities) | Not implemented | Not described |
| Decision-bound, tamper-evident evidence | DEMONSTRATED_WITHIN_SCOPE (E9; E10 + R2 repaired; live chains 22/22 Qwen, all Anthropic runs) | Not implemented (run logs only) | Not implemented | Not described |
| Tenant isolation | DEMONSTRATED_WITHIN_SCOPE with ownership registry or isolated ledger (E12, V-E12 repaired) | Not implemented | Not implemented | Not described |
| Human approval path | Implemented and live-tested (E13 repair: 63/63 approved calls executed) | Described, not implemented (denial ends the run) | Implemented (stdin y/N) | Not in evaluated system |
| Formal guarantee | None | None (design argument; §10 future work) | None (deterministic checker; correctness of policies assumed) | Argued proposition, not mechanised |

### 2.2 Assumptions behind each guarantee

| | CaMeL | Morrison |
|---|---|---|
| Trusted | user prompt; privileged LLM sees only the query; interpreter correct; policies correct | principal identity and SecurityContext; declared rules and registries correct; approver correct; signing keys protected |
| Boundary | the interpreter: every tool call is made by the interpreter | the kernel, or the resource that verifies Morrison's lease; anything else is outside |
| Explicitly not covered | text-to-text attacks, side channels, data that becomes control flow when the user asks, ROP-like composition of allowed steps, rollback | data provenance; text output; cross-host state; trajectory state predating the governed history; malicious use of a correctly issued lease for exactly its action |
| Failure mode when an assumption breaks | an allowed-by-policy data flow passes | an action permitted by the rules passes (e.g. a payment to an established payee within the ceiling, chosen by injected text) |

The two guarantees are about different things. CaMeL (and FIDES) guarantee **where control and data came from**;
Morrison enforces **which effects are admissible given authority, history and shared state**, at the resource when
deployed that way. Neither subsumes the other: an injection that picks the arguments of an *admissible* action
passes Morrison but is what CaMeL is built to stop; two CaMeL agents jointly exhausting a shared budget, or a replayed
approval, is outside CaMeL's design.

### 2.3 Which systems implement Morrison's combination

Morrison's combination: separate local and trajectory/cross-agent admissibility checks; independent pre-execution
veto; shared cross-agent constraints under concurrency; single-use, action-bound authorisation; resource-side lease
verification; decision-bound tamper-evident evidence.

- **CaMeL, Progent, FIDES** (code and papers inspected): each implements the independent pre-execution veto and
  per-call policy; CaMeL and FIDES add information flow within one session. **None implements** cross-agent shared
  constraints, single-use authorisation, resource-side enforcement or tamper-evident decision evidence.
- **SAGA** (archived text): one-time keys and use-limited tokens, but for agent-to-agent messaging, not tool calls.
- **Bounded Agents, AgentFlow, Ajar, CaMeLoT** (2026 preprints): known from search snippets only; not verified.

Conclusion: among the systems whose implementations were examined, **none demonstrates Morrison's combination**, and
Morrison demonstrates it within the scopes stated in §2.1. That is a differentiation claim over CaMeL, Progent and
FIDES specifically, not a novelty claim over the field: four relevant 2026 preprints were not verified.

## 3. Violations: observed versus open

The full record is `VIOLATION_LEDGER.md`. At the final code:

- **Open:** T3b (trajectory rule blind to pre-existing state); G4 in the plain `HierarchicalGovernance` tier.
- **Repaired and re-falsified:** E5, E7, E8 (isolated deployment), E10, E12, G1, and the six findings of the
  independent suites (R1, R2, V-G1a, V-G1b, V-E12; V-G1c restated as a rolling window).
- **By configuration (controls kept):** G1 without `resource_scopes`, E12 without a registry, E8 with a same-UID
  ledger, T1–T3 without declared rules.
- **Unsupported:** cross-host shared state and replay; data provenance.

Historical violations remain evidence that the earlier versions failed; they are not open defects in the final code.
