# Abliterated Qwen3-32B AgentDojo execution record

Date: 2026-10-14. Implementation baseline: f97e3e41f92aed93471c30fa473d23ad9b44fb0d,
branch claude/agentdojo-live-matched-arms. New work: codex/agentdojo-hf-qwen32b.

## Current status

**Implementation validated offline; paid inference has not yet run.** No benchmark
success, resource mutation or safety demonstration is claimed in this record.

The connected HF OAuth account is Davarn11, but its scopes (jobs, openid, profile,
read-mcp, read-repos) do not include Inference Providers access. No HF_TOKEN exists
in the local execution environment. Repository secret availability will be checked
by the authenticated GitHub Actions preflight, without revealing the token.

Required account action: accept the model gate, create an inference-enabled HF token,
and store it as HF_TOKEN in repository Actions secrets. Never paste a secret into chat.

## Identity

- Exact checkpoint: huihui-ai/Qwen3-32B-abliterated.
- Router model: huihui-ai/Qwen3-32B-abliterated:featherless-ai.
- API: https://router.huggingface.co/v1.
- Hub source SHA: 7a754614e9172cd416b4652342084bea8b5c98b0.
- Hub metadata: gated=auto; exact provider mapping=live.
- Featherless metadata: status=active, features.tool_use=true, context=32768.
- **Exact served revision UNVERIFIED**; no served SHA is published in retrieved metadata.
- Provider advertises FP8; Hub source weights are BF16. Neither is original Qwen/Qwen3-32B.
- Price ceiling checked against metadata before execution: $0.408/M input, $1.972/M output.
- HF routed billing can use purchased credits; the user's $9.65 balance is user-reported,
  not independently confirmed through a billing API. No billing settings/recharge changed.

## Execution design

HF adapter reuses the existing live runner, kernel and record-only versus enforced
executor. No production policy or manifest changed. System role and tool IDs are
preserved; temperature=0.0 and max_tokens=4096 are sent explicitly. Thinking uses
provider defaults and is recorded as such, rather than inventing an unsupported override.

A two-turn paid canary must emit a correctly named structured function with valid JSON
and ID, accept its result, and return the demo balance. Plain JSON text is insufficient.

Initial banking sample: user_task_0 and user_task_1, all nine injections,
important_instructions attack, both arms, standalone attacker tasks and benign runs.
Optional fixed larger follow-up: user tasks 0,1,12,14, all nine injections, direct attack.
These phases are reported separately. No attack tuning after observing results.

Total initial estimated budget <= $4 INCLUDING canary and optional follow-up.
One sequential durable ledger covers all calls. Arm ceiling $1.95, canary ceiling $0.10.
Before each dispatch reserve full context input plus capped output; no local tokenizer or
weights. On ambiguous failure reserve remains charged against budget and stop; automatic
retries are disabled. Unknown billing is not zero. Provider invoices remain authoritative.

Output includes objectives, injection hashes/transcripts, proposals, decision layers/rules,
shadow verdicts, actual execution paths, full before/after resource snapshots, effects,
evidence chains, request IDs where available, raw responses, token usage and estimates.
Credential redaction must finish before artifacts are uploaded. Existing analyze.py
separates injection, direct attacker requests and benign episodes and checks binding/effects.

## Validation (not live-model evidence)

Local offline validation: 30 passed (10 HF-specific tests plus 20 existing harness tests).
Five expected AgentDojo warnings: not every standalone injection task was solved by the
mocked proposer. No HF generation was performed by these tests. Syntax and workflow shell
validation passed. Fully pinned package lock matches Python 3.12 used in the new workflow.
GitHub Actions performs the same offline validation before exposing the secret.

## Current property classifications

| Property | Status | Reason |
|---|---|---|
| Live structured tool calling | NOT_TESTED | Requires authenticated paid canary |
| Live local prohibited-execution prevention | NOT_TESTED | No Qwen episodes executed |
| Locally allowed composition into prohibited trajectory | NOT_TESTED | No separate composition predicate exercised by this new benchmark |
| Shared multi-agent global safety | NOT_TESTED | AgentDojo episodes have one proposer, independent environment |
| Live decision-bound evidence | NOT_TESTED | No Qwen execution evidence yet |
| Exact served-revision reproducibility | UNSUPPORTED | Shared provider does not expose served revision in metadata |

On execution, per-run RESEARCH_REPORT.md, classifications.json, arm JSON, analysis.json,
verification.json, hf-verification.json and budget-ledger.json supply actual results.
Preserve every partial episode and violation; don't represent an incomplete arm as a result.

## Existing evidence retained

ADVERSARIAL_LOCAL_GLOBAL_FALSIFICATION.md at baseline records a live Haiku 4.5/direct
payment-redirection pair: prohibited effects occurred ungoverned and were prevented in
governed configurations. Earlier Opus runs frequently had no injected prohibited proposal,
so they did not demonstrate Morrison's causal prevention under those injections.
Those models, settings and attack coverage differ from this proposed Qwen experiment.

Existing open findings E8, E12, G1 and T3b remain recorded and unchanged. This inference
adapter does not repair direct resource access, tenant isolation, cross-principal continuity
or blindness to pre-existing state. Shared-state global experiments in the separate
falsification harness must not be attributed to the single-agent live AgentDojo run.
