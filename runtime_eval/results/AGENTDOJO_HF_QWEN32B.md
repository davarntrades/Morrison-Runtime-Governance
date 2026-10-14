# Abliterated Qwen3-32B AgentDojo execution record

Date: 2026-10-14. Implementation baseline: f97e3e41f92aed93471c30fa473d23ad9b44fb0d,
branch claude/agentdojo-live-matched-arms. New work: codex/agentdojo-hf-qwen32b.

## Current status

**HF_TOKEN is now present and authenticates as Davarn11. Live execution is blocked by the exact model's gated access: the account is not on its authorised list. Paid inference has not yet run.** No benchmark
success, resource mutation or safety demonstration is claimed in this record.

The connected HF OAuth account is Davarn11, but its scopes (jobs, openid, profile,
read-mcp, read-repos) do not include Inference Providers access. No HF_TOKEN exists
in the local execution environment. On resumption, GitHub Actions verified the repository secret is present and authenticates (HTTP 200). The earlier absent-secret findings below are preserved as historical results.

Required account action now: sign in to Hugging Face as Davarn11 and request/accept access at https://huggingface.co/huihui-ai/Qwen3-32B-abliterated. The existing HF_TOKEN secret is present; no token value is requested in chat.

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

## GitHub Actions validation

Offline-only run https://github.com/davarntrades/Morrison-Runtime-Governance/actions/runs/38606707948 succeeded at f38806fe1341f3e210107e95cb8d38746dfaf7f6. Authentication/preflight and paid steps were skipped on that push run; it is not a live-model benchmark.

The separate broad Pylint run failed. Three findings in the new files were corrected before workflow registration; pre-existing style findings elsewhere are retained.

## Actual preflight blocker

Run https://github.com/davarntrades/Morrison-Runtime-Governance/actions/runs/38612573001 completed the 30 offline checks, then failed free preflight with key_present=false: repository HF_TOKEN secret required. Paid steps were skipped. Estimated inference spend $0. Preserved artifact: runtime_eval/results/agentdojo-hf/run-38612573001-1/preflight.json. ZIP SHA-256 verified against GitHub: b42f36c2ab8a6967f4e1aec39655c5def596ec91610e8125f4ec5dcfc0d9876c. This is a real GitHub Actions preflight, not a live-model benchmark.

Per-call before/after snapshots and diffs now retain transient mutations that a later action could reverse; the HF classification examines these as well as final state. Executor policy and authority remain unchanged.

## Final implementation verification

Run https://github.com/davarntrades/Morrison-Runtime-Governance/actions/runs/38613196983 succeeded using implementation ffbf856380e262189a4c9fbdabbe8aec37e7dda5, including per-call snapshot/effect assertions. Run 38613133596 also passed offline validation and stopped at unbilled authentication preflight. No paid canary or benchmark has run. Machine-readable status: agentdojo-hf/execution-status.json.

## Workflow enabled

Minimal registration PR https://github.com/davarntrades/Morrison-Runtime-Governance/pull/38 merged at 97979463c6ba2eb619a37e7d5f4c029fcd3b5b56. Main contains only the added registration workflow from this work; it checks out validated experimental code ffbf856380e262189a4c9fbdabbe8aec37e7dda5. The source branch and older evidence are preserved.

To execute from an iPhone: store an inference-enabled token as repository HF_TOKEN, accept the model gate if required, open Actions → AgentDojo HF Abliterated Qwen32B → Run workflow, choose benchmark, and enter RUN-HF-UP-TO-4-USD. Leave expand enabled only to include the fixed follow-up within the same total cap. No local model weights or GPU deployment is required. The GitHub connector lacks workflow_dispatch and the secure browser sign-in did not establish a completed session.

The broader Python application check remained in progress when workflow registration was merged. The dedicated pinned-implementation validation passed; the separate broad Pylint workflow remains failing. No full-repository green status is claimed.

## Resumption after token creation — 14 October 2026

Actual preflight retry: https://github.com/davarntrades/Morrison-Runtime-Governance/actions/runs/38613133596 (attempt 2). The 30 focused tests passed. HF_TOKEN was injected by Actions; authentication passed for Davarn11, but the checkpoint config check returned 403. No paid canary was attempted.

A separate zero-inference access diagnosis ran at https://github.com/davarntrades/Morrison-Runtime-Governance/actions/runs/38627003443. Hugging Face whoami-v2 returned HTTP 200 for Davarn11; both repository auth-check and the revision-pinned config request returned 403. The denial identifies the precise cause: access is restricted and the account is not in the authorised list. This establishes an account-level gate blocker rather than an absent secret or wrong account.

The token's actual Inference Providers request permission and usable inference billing remain untested until access is granted and a canary runs. The model was not substituted. No billing settings, credit purchases, dedicated GPUs or main-branch changes were made on this resumption.

Preserved evidence:
- agentdojo-hf/run-38613133596-2/blocker.json; source ZIP SHA-256 2b34e0421790049d1b61b4d8614fcf4d010fc7035fba9be20657c6484a565b2a.
- agentdojo-hf/run-38627003443-1/access.json; source ZIP SHA-256 5a3fdc8e97295221a0b97c856c356123e4de01029c9f99b749fe70719a7d5cd2.
Both downloaded ZIP hashes matched GitHub's artifact digests. Credential values were never printed or committed.

Paid requests: 0; estimated inference spend for this experiment: $0. No attacker-success, task-completion, resource-mutation or live-chain result exists. Live local, trajectory and global properties remain NOT_TESTED. The served checkpoint revision remains unverified.
