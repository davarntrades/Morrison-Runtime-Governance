# Related work from primary sources: CaMeL, Progent, FIDES and others

Compiled 2026-10-15. Scope: published defences for tool-using LLM agents, compared on AgentDojo results, claimed guarantees and
architecture. Neutral, descriptive. Every claim carries a URL. Items marked **[UNVERIFIED]** could not be checked against a
primary text.

## 0. Provenance and access limits (read first)

- **arxiv.org was unreachable from this environment.** Every arXiv host returned a proxy 403 or a DNS failure: `arxiv.org`,
  `export.arxiv.org`, `ar5iv`, `alphaxiv`, `huggingface.co/papers`, `semanticscholar`, `researchgate`, `openreview`. I could
  not open an arXiv abstract page, its version history, or any PDF directly.
- **Paper texts used.** I read `pdftotext -layout` snapshots of the arXiv PDFs. They are archived in a third-party GitHub repo,
  `lhl/agentic-security` at commit `a390593f`
  (https://github.com/lhl/agentic-security/tree/a390593fa507fab701041e3bb40a7233bfd58b57/references/papers). Each snapshot
  keeps the arXiv margin stamp, which identifies the version read:
  - CaMeL: `arXiv:2503.18813v2 [cs.CR] 24 Jun 2025`
    (https://github.com/lhl/agentic-security/blob/a390593fa507fab701041e3bb40a7233bfd58b57/references/papers/arxiv-2503.18813.md;
    canonical https://arxiv.org/abs/2503.18813)
  - Progent: `arXiv:2504.11703v2 [cs.CR] 30 Aug 2025`
    (https://github.com/lhl/agentic-security/blob/a390593fa507fab701041e3bb40a7233bfd58b57/references/papers/arxiv-2504.11703.md;
    canonical https://arxiv.org/abs/2504.11703)
  - FIDES: `arXiv:2505.23643v2 [cs.CR] 3 Sep 2025`
    (https://github.com/lhl/agentic-security/blob/a390593fa507fab701041e3bb40a7233bfd58b57/references/papers/arxiv-2505.23643.md;
    canonical https://arxiv.org/abs/2505.23643)
  - The snapshots are text extractions. Figure values were read from extracted figure labels, and two-column layouts are
    interleaved. Table values were read from appendix tables wherever they exist.
- **"Latest version" is [UNVERIFIED].** I could not check whether any of the three papers has a version later than the one
  above. A web search did not surface one, but that is not conclusive.
- **Earlier-version figures come from search-engine snippets of arXiv pages, not from the texts [UNVERIFIED].**
  - CaMeL v1 abstract: "67% of tasks with provable security", against "77% ... (compared to 84% with an undefended system)"
    in v2 (https://arxiv.org/abs/2503.18813v1).
  - Progent v1 abstract: AgentDojo attack success rate (ASR) "from 41.2% to 2.2%", against "39.9% to 0%" in v2 body and
    "reduces attack success rates to 0%" in v2 abstract (https://arxiv.org/abs/2504.11703v1).
- **Code read directly by git clone** (anonymous, public):
  - CaMeL: https://github.com/google-research/camel-prompt-injection @ `f083b6b396399d3b3c7f2ddaf613a5945eaf32d8`
    (2025-06-20; only branch `main`).
  - Progent: https://github.com/sunblaze-ucb/progent @ `5be7b63fa96f70bc19b72fbcee81f1c0bcc1a565` (2026-09-24). The README
    links arXiv 2504.11703.
  - FIDES: https://github.com/microsoft/fides @ `669c046c4adbc56ee49c9672fdd30c54937ea062` (2025-05-30; only branch `main`).
  - Ajar: https://github.com/reSHARMA/Ajar @ `b5c737755ef623de01be0927ec1215dd26cb3967`.

Abbreviations: BU = benign utility (no attack); UA = utility under attack; ASR = attack success rate.

---

## 1. CaMeL: "Defeating Prompt Injections by Design" (Debenedetti et al., arXiv 2503.18813v2)

### A. AgentDojo results as published (v2)

**Setup**
- Benchmark: AgentDojo suites banking, slack, travel and workspace. The code pins `get_suite("v1.2", ...)`
  (https://github.com/google-research/camel-prompt-injection/blob/f083b6b396399d3b3c7f2ddaf613a5945eaf32d8/main.py).
- Attack: "AgentDojo's default prompt attack" (v2 §6.3). The code hard-codes `attack_name = "important_instructions"`
  (same `main.py`).
- Total injection cases: 949 (v2 Fig. 9 caption; §6.3).
- Models (v2 §6.1): gemini-2.5-flash-preview-05-20, gemini-2.5-pro-preview-05-06, claude-3-5-haiku, claude-sonnet-4 with
  and without a 16k reasoning budget, gpt-4.1, o4-mini (high), and o3 (high).
- The appendix tables report Claude 4 Sonnet, Claude 4 Sonnet*, Gemini 2.5 Flash, Gemini 2.5 Pro, o3 High and o4 Mini High.

**What the headline "77% (vs 84%)" measures.** It is benign utility: tasks completed with no attack and with policies on. It
matches o3-High in Table 2:

| Model | Native BU | CaMeL BU | Native UA | CaMeL UA | Native attacks | CaMeL (no policies) attacks | CaMeL attacks |
|---|---|---|---|---|---|---|---|
| o3 High | 84.5% ± 7.2 | **77.3%** ± 8.3 | 79.0% | 79.8% | 11 | 1 | 0 |
| o4 Mini High | 79.4% | 76.3% | 81.6% | 76.1% | 2 | 1 | 1 |
| Claude 4 Sonnet | 86.6% | 74.2% | 80.1% | 75.7% | 75 | 13 | 11 |
| Claude 4 Sonnet* (reasoning) | 83.5% | 70.1% | 78.1% | 72.8% | 75 | 10 | 11 |
| Gemini 2.5 Pro | 73.2% | 41.2% | 58.0% | 45.3% | 163 | 0 | 0 |
| Gemini 2.5 Flash | 55.7% | 35.1% | 39.5% | 41.5% | 297 | 1 | 1 |

- Sources: Table 2 (BU), Table 3 (UA) and Table 4 ("Number of successful attacks", out of 949), all in v2 Appendix B
  (https://arxiv.org/abs/2503.18813).
- "Provable security" in the abstract refers to policy enforcement by the interpreter, not to a measured 0 ASR across all
  models.
- Table 4 shows non-zero successful attacks for CaMeL with policies on several models:
  - Travel: one injection makes the agent print a hotel recommendation, a text-to-text outcome outside the threat model.
  - Banking: "Transfer $30,000..." succeeds without policies when the user asks to pay per a document.
  - Both are explained in v2 §6.2.1 and §6.2.2.
- The text cites a Gemini 2.5 Pro attack count of "300 without" CaMeL (§6.2.1). Table 4 gives 163 ± 140.1. The source of the
  difference is not stated.

**Baseline-defence comparison** (Claude 3.5 Sonnet; v2 §6.3, Tables 5–7):

| Defence | BU | UA | Successful attacks / 949 |
|---|---|---|---|
| CaMeL | 63.92% | 66.70% | 0 (no policies: 1) |
| Tool Filter | 73.20% | 72.71% | 8 |
| Spotlighting | 92.78% | 89.36% | 5 |
| Prompt Sandwiching | 89.69% | 84.19% | 24 |
| Undefended | 90.72% | 86.83% | 44 |

- Travel BU under CaMeL with Claude 3.5 Sonnet is 25.00% (Table 5).
- §6.3: GPT-4o-mini with tool calling is "vulnerable to 276 attacks"; with CaMeL, to none (no table given).

**Version change [UNVERIFIED, from search snippet]:** the v1 abstract said 67%, and v2 says 77%. V2 §6.1.1 states that utility
"significantly improved in a second round of experiments where we employed more recent models".

**Code observations** (not stated as such in the paper text I read):
- `main.py --replay-with-policies` replays the P-LLM code recorded in an earlier no-policy run while enforcing policies, and
  stops at the first denial
  (https://github.com/google-research/camel-prompt-injection/blob/f083b6b396399d3b3c7f2ddaf613a5945eaf32d8/src/camel/pipeline_elements/replay_privileged_llm.py,
  `replay_task`, lines 129–195).
- Whether the "CaMeL" (with policies) rows in Tables 2–4 were produced this way is **[UNVERIFIED]**.
- The default interpreter mode is `NORMAL`, not `STRICT` (`main.py` line 36). The mode used for Tables 2–4 is not stated in
  the table captions I read. Table 8 reports policy-trigger rates for both modes.

### B. Security guarantee claimed

**Nature: design-based, not mechanically proven.**
- v2 §10 "Towards formal verification" names formal verification of the interpreter and policies as future work.
- v2 §11: "Our approach is not perfect and does not completely address every potential attack vector."
- An independent formalization paper says CaMeL "includes no formal reasoning or proof" (arXiv 2602.20064v1, §I,
  https://arxiv.org/abs/2602.20064).

**What is claimed**
- Control and data flow are extracted from the trusted query, so "untrusted data retrieved by the LLM can never impact the
  program flow" (abstract).
- Capabilities and security policies are checked before each tool call, and execution halts on violation (§4, Fig. 4; §5.4
  "Enforcing security policies").
- Security is formalized as the PI-SEC game: the adversary wins if the trace contains an action outside Ω_prompt (§4,
  Fig. 3).

**Assumptions and threat model (§3)**
- The user prompt is trusted; the user is not pasting text from an untrusted source.
- Memory, if present, is not compromised.
- Policies are defined by the CaMeL engine (§5.2).
- The P-LLM sees only the user query and the code it generated, never tool outputs (§5.1).

**Explicit non-goals and limits**
- Text-to-text attacks with no data or control-flow consequence, including prompt-injection-induced phishing (§3.1).
- Fully autonomous operation; the user may need to be prompted (§3.1).
- Side channels:
  - indirect-dependency counting leaks;
  - exception-based one-bit leak;
  - timing leaks, with STRICT mode mitigating some (§7, Figs. 14–16).
- "Data requires action" tasks are unsolvable by design (§6.1.2).
- Data flow can become control flow when the user asks the agent to follow instructions found in data (§6.4).
- ROP-like composition of allowed blocks (§9.3).
- Policies must be written and maintained by users, with user fatigue on declassification (§9.2–9.3).
- No atomicity or rollback for partially executed side effects (§5.4 "Error handling").
- Full ecosystem participation is needed for capabilities (§9.1).
- The README warns the "interpreter implementation likely contains bugs ... might not be fully secure"
  (https://github.com/google-research/camel-prompt-injection/blob/f083b6b396399d3b3c7f2ddaf613a5945eaf32d8/README.md).

### C. Architecture (code @ f083b6b)

Base path: `https://github.com/google-research/camel-prompt-injection/blob/f083b6b396399d3b3c7f2ddaf613a5945eaf32d8/`

| # | Property | Status | Evidence |
|---|---|---|---|
| 1 | Pre-execution decision independent of planning model | **Implemented** | The interpreter calls `security_policy_engine.check_policy(...)` before `evaled_fn.call(...)` and raises `SecurityPolicyDeniedError` on `Denied` (`src/camel/interpreter/interpreter.py` L2048–2071). Policies are deterministic Python (`src/camel/security_policy.py`). |
| 2 | Per-call policy checks | **Implemented** | Per-tool policies, e.g. `send_money_policy` (`src/camel/pipeline_elements/security_policies/banking.py` L52). Unmatched tools are denied by default (`security_policy.py` L95). |
| 3 | Trajectory / history-dependent checks in one session | **Implemented for data-flow taint; not implemented for cumulative limits** | Dependencies and capabilities (sources, readers) propagate through the interpreter and persist across P-LLM retries (§5.4). The engine denies a state-changing tool whose dependencies are non-public (`security_policy.py` L90–92). Policies read live environment state via `self._env` (e.g. `security_policies/workspace.py` L183). No counters, budgets or rate limits in the released policies. |
| 4 | Shared / global constraints across agents or principals, incl. concurrency | **Not implemented** | One policy engine per task environment (`pipeline_elements/privileged_llm.py` L261). Paper: "our design allows for a more granular and multi-party model in the future" (§5.2). |
| 5 | Single-use / replay-resistant authorisation | **Not implemented** | No approval or capability-token objects. "Capabilities" are value metadata tags (`src/camel/capabilities/`), not consumable authorisations. |
| 6 | Authorisation bound to the exact action executed | **Not applicable / implicit only** | The checked argument objects are the ones passed to the call in the same process (`interpreter.py` L2050–2071). There is no approval artefact to bind. |
| 7 | Resource-side enforcement | **Not implemented** | Enforcement is only in the interpreter. §9.1: tools and services "must be designed to understand and utilize capabilities". |
| 8 | Tamper-evident / signed decision evidence | **Not implemented** | Only AgentDojo run logs (`main.py` `logdir`). No signing or hash-chaining found. |
| 9 | Human approval / escalation | **Described, not implemented** | §5.4: "In a real-world application, executions that violate security policies will not be blocked, but they will require user confirmation." Code: denial raises an exception and the run ends (`interpreter.py` L2062–2065). No prompt path. |
| 10 | Multi-tenant isolation | **Not implemented** | Single-user AgentDojo setting. `readers` labels model which people may read a value; they are not a tenant boundary. |

### D. Independent evaluations and attacks

- **DRIFT, arXiv 2506.12104v2** (https://arxiv.org/abs/2506.12104). Re-ran CaMeL on AgentDojo with GPT-4o-mini and the
  `important_instructions` attack (§3.1, §3.2):
  - CaMeL: utility 35.4%, ASR 0.0%, 6.09M tokens, against undefended 48.3% / 30.7% (Table 3).
  - 0.0% completion on six open-ended AgentDojo tasks, against 25.7% for the base agent (Table 4).
- **AgentDyn, arXiv 2602.03117v2** (https://arxiv.org/abs/2602.03117). New open-ended benchmark (560 security cases). CaMeL
  scores 0.00 BU, 0.00 UA and 0.00 ASR for GPT-4o, Gemini-2.5 Pro, Qwen3-235B and Llama-3.3-70B (Table 3).
  - The authors used official code and added "Complete all tasks automatically without requesting user confirmation" to the
    system message (§4.1).
- **"Indirect Prompt Injections: Are Firewalls All You Need...", arXiv 2510.05244v1** (https://arxiv.org/abs/2510.05244).
  "We were unable to successfully reproduce their results". They list CaMeL* as a non-replicable baseline with published
  numbers BU 53.6, UA 54.5, ASR 0.00 under GPT-4o (Table 1). Those GPT-4o numbers do not appear in CaMeL v2's tables; their
  origin is not stated.
- **"Operationalizing CaMeL", arXiv 2505.22852** (https://arxiv.org/abs/2505.22852). Position paper with no measurements. It
  lists threat-model gaps (benign-initial-prompt assumption, no output inspection, side channels) and proposes tiered policies
  and formal verification.
- **"The LLMbda Calculus", arXiv 2602.20064v1** (https://arxiv.org/abs/2602.20064). Formalizes the CaMeL pattern in a
  lambda calculus and notes the absence of formal proof in CaMeL.
- **Ajar, arXiv 2609.26900** (https://arxiv.org/abs/2609.26900). Measures "open privilege" (calls a defence would allow that
  the task does not need) for Progent, CaMeL, AC4A, Permission Assistant and Claude Code Auto mode on AgentDojo.
  - **[UNVERIFIED]**: known only from search snippets; the PDF is unreachable.
  - The released repo has no CaMeL or Progent wrapper or results: its README says external defences such as "Progent's
    arg-aware `check_tool_call`" are "seams, not yet implemented" (https://github.com/reSHARMA/Ajar/blob/b5c737755ef623de01be0927ec1215dd26cb3967/ajar/README.md).
- **CaMeLoT, arXiv 2609.18674** (https://arxiv.org/abs/2609.18674). Follow-up adding temporal-logic static verification
  **[UNVERIFIED; title from search result only]**.

---

## 2. Progent: "Programmable Privilege Control for LLM Agents" (Shi et al., arXiv 2504.11703v2)

### A. AgentDojo results as published (v2)

**Setup**
- Agent LLM: gpt-4o for all of §5 ("For consistency, we use gpt-4o", §5.1).
- Policies: written manually per suite (§5.2 "Use Case I"):
  - read-only tools are allowed;
  - write tools are restricted to a trusted argument list;
  - out-of-list calls are "automatically block[ed] and return a feedback to the agent" instead of prompting the user.
- Attack: not named in the v2 text I searched. The repo script runs `--attack important_instructions`
  (https://github.com/sunblaze-ucb/progent/blob/5be7b63fa96f70bc19b72fbcee81f1c0bcc1a565/agentdojo/run.sh).

**Manual policies (Table 1, appendix; also Fig. 5):**

| Suite | No defence BU / UA / ASR | Progent BU / UA / ASR |
|---|---|---|
| banking | 87.50 / 79.17 / 45.83 | 81.25 / 70.14 / 0.00 |
| slack | 95.24 / 64.76 / 80.00 | 95.24 / 60.00 / 0.00 |
| travel | 75.00 / 49.00 / 16.00 | 80.00 / 63.00 / 0.00 |
| workspace | 70.00 / 36.25 / 28.75 | 72.50 / 63.33 / 0.00 |
| **overall** | **79.38 / 53.99 / 39.90** | **80.41 / 64.35 / 0.00** |

- Same table: tool_filter overall 65.98 / 61.29 / 6.28; repeat_user_prompt 83.50 / 68.42 / 25.13.
- What "0%" measures: AgentDojo injection-task success under these hand-written, suite-wide policies. The paper calls it "a
  provably guaranteed result because Progent uses a set of deterministic security policies" (§5.2).

**Progent-LLM: policies generated and updated by an LLM (§6.1, Fig. 9 and Fig. 10, values read from figure labels)**
- AgentDojo ASR falls from 39.9% to 1.0% with gpt-4o as the policy LLM.
- With other policy LLMs: claude-sonnet-4 2.2%, gemini-2.5-flash 3.0%, gpt-4.1 4.1%.
- BU with gpt-4o policies is 76.3%, against 79.4% with no defence. UA ranges 60.8–63.8% across policy models, against 54.0%.
- Five adaptive attacks against the update step "only marginally increase the ASR" (Fig. 11, §6.1).
- Appendix D.1: other agent LLMs give ASR as low as 0.3–0.5% with Progent-LLM.

**Version change [UNVERIFIED, from search snippet]:** v1 abstract reported AgentDojo ASR "from 41.2% to 2.2%".

**Repo note:** the shipped `run.sh` runs the LLM-generated-policy mode (`SECAGENT_UPDATE=True`, policy model
gpt-4o-2024-08-06), not the manual-policy configuration of Table 1. The repo's agentdojo README says Slack injection task 5
results were "manually checked ... and corrected" because blocked calls still appear in the trace
(https://github.com/sunblaze-ucb/progent/blob/5be7b63fa96f70bc19b72fbcee81f1c0bcc1a565/agentdojo/README.md).

### B. Security guarantee claimed

**Nature**
- "The framework operates deterministically at runtime, providing provable security guarantees" (abstract).
- Runtime enforcement "is a deterministic procedure, and guarantees the security properties expressed by the policies" (§4.2).
- No formal theorem appears in the v2 text I read. The guarantee is that a deterministic checker enforces the written policy.
- §7, "Writing Correct Policies": the guarantees "rely on correct policies written by agent developers and users".
- §7, "Completeness of Policies": "security guarantees are directly tied to the comprehensiveness of its policies".
- Progent-LLM, where policies are generated or updated by an LLM, is evaluated empirically and its claims are empirical.
  §6: the update step reads tool results, "there is a risk where the LLM incorporates malicious instructions".

**Threat model (§3.2)**
- The attacker controls external data, i.e. any observation after the user query, and may add malicious tools.
- The attacker cannot modify agent internals.
- The user and the initial query are benign.

**Out of scope (§3.2 "Defense Scope")**
- Attacks "within the least privilege" of the task, e.g. preference manipulation.
- Attacks targeting text outputs rather than tool calls.
- §7: multimodal actions.

**Tooling:** a type checker and a Z3-based overlap analyzer help policy authors (§4.1;
https://github.com/sunblaze-ucb/progent/blob/5be7b63fa96f70bc19b72fbcee81f1c0bcc1a565/secagent/policy_analysis.py).

### C. Architecture (code @ 5be7b63, `secagent/`)

Base path: `https://github.com/sunblaze-ucb/progent/blob/5be7b63fa96f70bc19b72fbcee81f1c0bcc1a565/`

| # | Property | Status | Evidence |
|---|---|---|---|
| 1 | Pre-execution decision independent of planning model | **Implemented** | `secure_tool_wrapper` runs `check_tool_call(...)` before `tool(*args, **kwargs)` (`secagent/tool.py` L718–760). MCP variant: `ToolCallFilterMiddleware.on_call_tool` runs the check before `call_next` (`secagent/mcp_proxy.py` L31–37; `secagent/progent_proxy.py` L293). In Progent-LLM the policy itself comes from a separate policy LLM (`generate_security_policy`, L375; `generate_update_security_policy`, L435). |
| 2 | Per-call policy checks | **Implemented** | Argument restrictions as JSON Schema, regex or callable (`check_arg`, `tool.py` L508–518). Priority and allow/forbid ordering in `_check_tool_call` (L521–570). |
| 3 | Trajectory / history-dependent checks | **Partial** | Policies may carry an `update` that changes the policy set after a matching call (Alg. 2 line 7, §4.2; `need_update_policies`, `tool.py` L521–591). Progent-LLM updates policies from tool results (`agentdojo/src/agentdojo/agent_pipeline/tool_execution.py` L121–123). No data-flow taint and no built-in cumulative counters. |
| 4 | Shared / global constraints across agents or principals, incl. concurrency | **Not implemented** | Policy state is one module-level global, `security_policy = None` (`tool.py` L31). It is shared by everything in the process and has no locking or per-principal scoping. The MCP proxy keeps a single global `USER_INPUT` / `USER_INPUT_SET` (`progent_proxy.py` L33–35). |
| 5 | Single-use / replay-resistant authorisation | **Not implemented** | No approval tokens. |
| 6 | Authorisation bound to the exact action | **Implicit only** | The wrapper checks `bound_args.arguments` and then calls the tool with the same in-process arguments (`tool.py` L753–757). The user-confirm prompt shows `tool_name` and `kwargs` for that call; no artefact is issued. |
| 7 | Resource-side enforcement | **Not implemented** | Enforcement sits in the in-process tool wrapper or in an MCP proxy in front of the server (`mcp_proxy.py`). Tools and servers verify nothing issued by Progent. |
| 8 | Tamper-evident decision evidence | **Not implemented** | Decisions are printed to stderr only (e.g. `tool.py` L85, L118). |
| 9 | Human approval / escalation | **Implemented (minimal)** | Fallback `2` prompts on stdin "Do you want to allow it?[y/N]" (`tool.py` L556–560, L565–569). DSL fallback "request user inspection" (Fig. 4). The paper's AgentDojo evaluation auto-blocks instead (§5.2). Code defect: the deny branch builds `ValidationError(..., file=sys.stderr)`, which raises `TypeError`; the outer handler still converts it to a denial. |
| 10 | Multi-tenant isolation | **Not implemented** | Process-global policy state (see #4). |

### D. Independent evaluations and attacks

- **DRIFT, arXiv 2506.12104v2** (https://arxiv.org/abs/2506.12104). On AgentDojo with GPT-4o-mini, Progent ("w/ update")
  scored utility 45.6% and ASR 9.4% (Table 3). Further results (Table 5):

  | Setting | BU | UA | ASR |
  |---|---|---|---|
  | AgentDojo, GPT-4o | 76.30 | 61.20 | 2.20 |
  | AgentDojo, GPT-4o-mini | 54.66 | 45.58 | 9.39 |
  | ASB, GPT-4o-mini | — | — | 15.75 |

- **AgentDyn, arXiv 2602.03117v2** (https://arxiv.org/abs/2602.03117), Table 3 (BU / UA / ASR):

  | Model | BU | UA | ASR |
  |---|---|---|---|
  | GPT-4o | 6.67 | 5.83 | 1.69 |
  | Gemini-2.5 Pro | 25.00 | 16.06 | 1.59 |
  | Qwen3-235B | 8.33 | 2.19 | 13.59 |
  | Llama-3.3-70B | 3.33 | 2.28 | 0.52 |

  The authors report that with larger toolsets, Progent "struggles to assign accurate tool access privileges ... eventually
  blocking almost all useful tools" (§4.2).
- **Ajar, arXiv 2609.26900.** Evaluates Progent's open privilege **[UNVERIFIED]**; see §1.D.

---

## 3. FIDES: "Securing AI Agents with Information-Flow Control" (Costa et al., Microsoft, arXiv 2505.23643v2)

### A. AgentDojo results as published (v2)

**Setup**
- Attack: "Tool Knowledge attack, the most powerful instance of the Important Instructions baseline attack" (§7.2).
- Scale: all 949 attacks, averaged over 5 runs (§7.2, §8.1).
- Models: gpt-4o, o1, o3, o4-mini (high reasoning effort) and grok-3 (non-reasoning) (§7.2).
- Policies: two generic ones, P-T (trusted action) and P-F (permitted flow), assigned per tool (Table 3).
- Labels:
  - integrity "untrusted" covers every field targeted by any AgentDojo injection task (§7.1);
  - confidentiality labels are inferred from the task data.

**Successful injections, total out of 949** (Table 1 / Table 4). Values in parentheses exclude two injection tasks the authors
do not count against the policy: Travel inj. 6, which is text-to-text, and Travel inj. 2, a calendar event with no
participants.

| Model | Basic (no policy) | Tool Filter | FIDES (no policy) | Basic★ | FIDES★ |
|---|---|---|---|---|---|
| gpt-4o | 163 (156) | 28 (23) | 24 (23) | 9 (0) | **1 (0)** |
| o1 | 144 (133) | 15 (13) | 71 (68) | 12 (0) | 6 (0) |
| o3 | 15 (12) | 4 (2) | 16 (11) | 3 (0) | 4 (0) |
| o4-mini | 5 (5) | 2 (2) | 7 (5) | 0 (0) | 1 (0) |
| grok-3 | 368 (347) | 59 (50) | 8 (5) | 22 (0) | 3 (0) |

**Task completion rate (BU), overall, no attack** (Table 7; ★ = policy checks on):

| Model | Basic | Basic★ | FIDES | FIDES★ |
|---|---|---|---|---|
| gpt-4o | 83.30 | 43.30 | 59.79 | 50.31 |
| o1 | 80.82 | 44.74 | 78.76 | **61.44** |
| o3 | 80.82 | 41.03 | 82.47 | 56.91 |
| o4-mini | 78.56 | 43.51 | 80.00 | 55.67 |
| grok-3 | 81.96 | 43.81 | 68.56 | 59.54 |

**What the headline numbers measure**
- "Completes on average about 16% more tasks than a basic planner" (§1) compares FIDES★ with Basic★ on the reasoning models,
  in percentage points, e.g. o1 61.44 vs 44.74 (Finding 3, §8.2).
- "Rises to 24%" with prompt tuning (§1; Table 8).
- "With policy checks enabled, FIDES stops all prompt injection attacks in AgentDojo" (§1) refers to the parenthesized
  counts.
- Utility under attack: no UA figure is reported in the v2 text. A search for "under attack" found only the Fig. 3 caption,
  "when not under attack".

### B. Security guarantee claimed

**Nature: formal statement, proof not written out.**
- Proposition 1 (§4.4): "Algorithm 5 with policies P-T and P-F correctly applied to every tool, guarantees non-interference
  for the integrity of tool calls and data, and explicit secrecy for the confidentiality of data."
- The paper forgoes the per-tool formalization as "straightforward" (§4.4). An external paper characterizes FIDES as proving
  that one planning loop satisfies these properties (arXiv 2602.20064v1, related-work subsection "G. Closest related work: FIDES, OPAL, Quasar").

**What it guarantees**
- Integrity non-interference: untrusted data cannot influence consequential tool calls, including through control flow.
- Confidentiality as explicit secrecy only. Implicit flows through which or how many tools are called are not prevented
  (§4.3 "P-F ... does not attempt to hide whether data has been sent"; §4.4).

**Assumptions (§2.1, §4.4)**
- Agent configuration is trusted: system message, tool descriptions and LLMs.
- The adversary can tamper with tool-returned data and observe effects of some tool calls, but not LLM queries.
- The formal results assume the model semantics ⟦M⟧ is a deterministic function.
- Labels must be assigned correctly by tool wrappers. Policies must be "correctly applied to every tool".

**Not covered**
- Text-to-text attacks on the final response: "we only enforce policies upon tool calls" (§8.1).
- Implicit confidentiality flows (§4.3–4.4).
- Correctness of developer labels and policies.

### C. Architecture

The public repo is a **tutorial notebook only** (`Tutorial.ipynb`, tested with GPT-4o/4.1 on Azure OpenAI per the README).
The AgentDojo implementation evaluated in the paper is not in the repository at `669c046`
(https://github.com/microsoft/fides/tree/669c046c4adbc56ee49c9672fdd30c54937ea062). The statuses below therefore rest on the
paper, with the tutorial where it shows the mechanism.

| # | Property | Status | Evidence |
|---|---|---|---|
| 1 | Pre-execution decision independent of planning model | **Implemented (paper + tutorial)** | Policies checked by the planning loop before executing a tool call (§4.3; Algorithm 5). Tutorial `LabeledPlanningLoop.loop` appends `(action, label)` to the trace and calls `self.policy(trace)`, which may raise `PolicyViolation`, before dispatching (notebook cell "Dynamic Taint-Tracking", https://github.com/microsoft/fides/blob/669c046c4adbc56ee49c9672fdd30c54937ea062/Tutorial.ipynb). |
| 2 | Per-call policy checks | **Implemented** | P-T / P-F per tool (Table 3). Tutorial `policy_no_untrusted_url`, `policy_no_untrusted_declassification`. |
| 3 | Trajectory / history-dependent checks | **Implemented (taint); trace predicates possible** | Context label is the join of all labels seen in the session (§4.2). Tutorial policy type is `Callable[[list[tuple[Action, Lattice]]], None]` over the whole labelled trace. Paper: evaluated policies use "the most recent action", and trace-based policies are "straightforward" to add (§4.3). No cumulative limits evaluated. |
| 4 | Shared / global constraints across agents or principals | **Not described / not implemented** | Single planner loop. |
| 5 | Single-use / replay-resistant authorisation | **Not described** | — |
| 6 | Authorisation bound to exact action | **Not described** | No approval artefact. |
| 7 | Resource-side enforcement | **Not implemented** | Labels attached by tool wrappers, enforcement in the planner (§7.1). |
| 8 | Tamper-evident decision evidence | **Not described** | — |
| 9 | Human approval / escalation | **Not part of evaluated system** | §1 cites human-in-the-loop prompts as leading to "confirmation fatigue". No approval path in the evaluated planner (not exhaustively verified). |
| 10 | Multi-tenant isolation | **Not described** | Readers-lattice labels model per-recipient confidentiality within one user's agent. |

### D. Independent evaluations

- No independent re-measurement of FIDES was found in the sources available to me.
- arXiv 2602.20064v1 (https://arxiv.org/abs/2602.20064) discusses FIDES's formal properties (explicit secrecy and integrity
  non-interference), but does not re-measure them.

---

## 4. Other systems relevant to multi-agent, shared-constraint, token, resource-side or logging properties

Brief entries. Primary text was read where a mirror snapshot existed; otherwise the entry is marked.

**Bounded Agents: Delegation Security for Multi-Agent AI Systems** (Muruaga, arXiv 2608.15888, https://arxiv.org/abs/2608.15888)
**[UNVERIFIED: search-engine abstract only]**
- Claims an "Agentic Principal Chain" tracking delegated authority across agents.
- Each request is checked against accumulated session state, with enforcement outside the model.
- Claims proofs of "Blast Radius Monotonicity" and "Composition Soundness". Per the snippet, the latter holds only for
  prohibited combinations under a complete restriction set and serialized admission.
- Reported AgentDojo exfiltration falls from 75–100% to 0%; also InjecAgent and ASB results.

**AgentFlow: A Flow-Centric Policy Language and Framework** (Shivakumar, Priya, Gao, arXiv 2608.22868,
https://arxiv.org/abs/2608.22868) **[UNVERIFIED: search-engine abstract only]**
- Policies over labelled runtime edges between tools, sinks and delegated agents.
- A runtime reference monitor enforces them, with a bounded SMT verifier for a policy fragment.
- Reports compromise falling from 73.5% to 0.0% on 200 AgentDyn Dailylife cases.

**Ajar: Measuring Open Privilege in Agent Defenses** (Sharma, Jiang, Chen, Lin, arXiv 2609.26900,
https://arxiv.org/abs/2609.26900) **[paper UNVERIFIED; code read]**
- Measures defences, not a defence itself. Defines over-privilege leakage, sufficiency, over-restriction and attack admission.
- A defence implements "given a proposed call and the calls already executed, allow it or deny it"
  (https://github.com/reSHARMA/Ajar/blob/b5c737755ef623de01be0927ec1215dd26cb3967/README.md).
- Per snippets it evaluates Progent, CaMeL, AC4A, Permission Assistant and Claude Code Auto mode. Those wrappers and results
  are not in the public repo (see §1.D).

**SAGA: A Security Architecture for Governing AI Agentic Systems** (Syros et al., arXiv 2504.21034v2,
https://arxiv.org/abs/2504.21034; mirror text read)
- Multi-agent identity, registration and inter-agent access control.
- A Provider issues one-time keys (OTKs) with per-initiating-agent quotas.
- Receiving agents derive encrypted **access control tokens** that expire or hit a use limit, after which a new OTK is needed.
- The threat model includes "replay" (§ threat model). Protocol analysed with ProVerif.
- This is inter-agent communication authorisation. It is not per-tool-call policy, and there is no AgentDojo evaluation.

**SEAgent (MAC framework)**, "Taming Various Privilege Escalation in LLM-Based Agent Systems" (Ji et al., arXiv 2601.11893v1,
https://arxiv.org/abs/2601.11893; mirror text read)
- Mandatory access control based on entity attributes.
- Targets privilege escalation including multi-agent confused-deputy variants (abstract).
- Detailed evaluation numbers not extracted.

**MELON** (Zhu et al., arXiv 2502.05174v4, https://arxiv.org/abs/2502.05174; mirror text read)
- Re-executes the trajectory with a masked user prompt and flags tool calls that recur.
- Reports AgentDojo ASR 0.24% (MELON) and 0.32% (MELON-Aug) on GPT-4o. The 68.72% figure is MELON-Aug utility under
  attack at 0.32% ASR (§ results and main results table).
- Independent attack: "The Attacker Moves Second" (arXiv 2510.09023v1, https://arxiv.org/abs/2510.09023) reports 76% ASR
  against MELON on Llama-3.3-70B with a search-based attack, without knowledge of the defence (§ on MELON).

**AgentSpec** (Wang, Poskitt, Sun, arXiv 2503.18666v3, https://arxiv.org/abs/2503.18666; mirror text read)
- DSL rules of the form trigger, predicate, enforcement.
- Enforcement options: `user_inspection`, `llm_self_examine`, `invoke_action`, `stop`.
- Evaluated on code, embodied and autonomous-vehicle agents, not AgentDojo. Reports preventing unsafe code execution in over
  90% of cases.

**ShieldAgent** (Chen, Kang, Li, arXiv 2503.22738v2, https://arxiv.org/abs/2503.22738; mirror text read)
- An LLM-based guardrail agent that checks other agents' action trajectories against policies extracted into probabilistic
  rule circuits.
- Reports +11.3% over prior methods, 90.1% recall. Empirical; not AgentDojo.

**Not examined (no primary text obtained in this session):** GuardAgent, Conseca. Their primary texts were not in the
available mirror and arXiv was unreachable.

---

## 5. Cross-system summary of property C (status per primary source)

| Property | CaMeL (code) | Progent (code) | FIDES (paper / tutorial) |
|---|---|---|---|
| 1 Pre-execution independent veto | Yes | Yes | Yes |
| 2 Per-call checks | Yes | Yes | Yes |
| 3 In-session history / taint | Taint yes; no cumulative limits | Policy self-update only; no taint | Taint yes; trace predicates possible, not evaluated |
| 4 Cross-agent / global shared constraints | No | No (one process-global policy, no locking) | No |
| 5 Single-use / replay-resistant authorisation | No | No | No |
| 6 Approval bound to exact executed action | N/A (no approvals) | Implicit in-process only | N/A |
| 7 Resource-side enforcement | No | No (in-process wrapper or MCP proxy) | No |
| 8 Tamper-evident decision log | No | No | No |
| 9 Human approval path | Described, not implemented | stdin y/N fallback | Not in evaluated system |
| 10 Multi-tenant isolation | No | No | No |

## 6. Could not access or verify

1. Every arxiv.org page and PDF, and every other paper host (alphaxiv, huggingface, semanticscholar, researchgate,
   openreview). The proxy denied them or DNS did not resolve. Paper content comes from third-party `pdftotext` snapshots of
   the arXiv PDFs (version stamps quoted in §0), not from arxiv.org.
2. Whether newer arXiv versions exist beyond CaMeL v2, Progent v2 and FIDES v2.
3. Earlier-version figures (CaMeL v1 "67%", Progent v1 "41.2% → 2.2%"); these come from search snippets only.
4. The attack named in Progent's paper for AgentDojo. Only the repo script (`important_instructions`) was checked.
5. Whether CaMeL's with-policy table rows were produced by the replay mechanism in the code, and which interpreter mode
   (NORMAL or STRICT) produced Tables 2–4.
6. FIDES's AgentDojo implementation, which is not public. The FIDES architecture rows rely on the paper and the tutorial.
7. Bounded Agents (2608.15888), AgentFlow (2608.22868), Ajar (2609.26900, paper) and CaMeLoT (2609.18674): abstract or
   search-level only. Their code was not found, except Ajar's repo, which contains no CaMeL or Progent results.
8. GuardAgent and Conseca: not examined.
9. Exact Progent-LLM figure values. They were read from text-extracted figure labels, not from a table.
