# Abliterated Qwen3-32B AgentDojo execution record

Date: 2026-10-14. Implementation baseline: f97e3e41f92aed93471c30fa473d23ad9b44fb0d,
branch claude/agentdojo-live-matched-arms. New work: codex/agentdojo-hf-qwen32b.

## Current status

**The hosted API route works. A real paid GitHub Actions run progressed past the mandatory structured-tool canary and executed both banking arms. The ungoverned arm completed; the governed arm was incomplete. This is not a completed or verified paired benchmark.**

Run: https://github.com/davarntrades/Morrison-Runtime-Governance/actions/runs/38629834413
Execution commit: `5f19c7dd3a0276087a12afb7d3c046851b86e71d`.

**Raw evidence export failed:** upload-artifact rejected the colon in provider-qualified model filenames/directories. The runner has finished and no artifact is available. The ledger, transcripts, state snapshots and raw chains could not be recovered through the available interfaces. The surviving job log is preserved in `agentdojo-hf/run-38629834413-1/job.log`, with a SHA-256 in `retained-status.json`.

The earlier conclusion that a Hub file-download 403 established hosted inference denial was incorrect. HF_TOKEN authenticates as Davarn11; gated repository-file access is a separate check. The router bulk catalogue also omitted this checkpoint, while its checkpoint-specific endpoint and HF provider mapping identified Featherless as live. The repaired preflight treats bulk-catalogue absence as advisory and preserves repository download denial without blocking the explicit inference route.

**Actual spend is unknown, not zero.** The run configured a $4 conservative client estimate ceiling, including canary and all phases. Because its ledger was lost, the entire $4 is conservatively reserved for further-execution decisions. No further paid request is authorised by an assumed fresh $4 budget. The one-off paid push trigger is disabled. Billing settings, credit purchases, GPU infrastructure and main remain unchanged.

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

| Property | Status | Evidence and limit |
|---|---|---|
| Hosted API and structured tool round trip | DEMONSTRATED_WITHIN_SCOPE | Actual execution progressed into banking after the mandatory two-request tool canary; this is a control-flow inference from the executed pinned code and log, not retained raw canary responses |
| Live local prohibited-execution prevention | INCONCLUSIVE | Governed arm incomplete; effect records unavailable |
| Locally allowed composition into a prohibited trajectory | NOT_TESTED | No separately specified permitted-composition predicate tested |
| Shared multi-agent global safety | NOT_TESTED | Single proposer, fresh environment per episode |
| Independently reviewable decision-bound evidence | INCONCLUSIVE | In-run verifier logged 42 intact chains; raw chains were not retained for independent rechecking |
| Required raw evidence preservation | VIOLATED | Artifact export rejected colon paths; no raw artifact retained |
| Exact served-revision reproducibility | UNSUPPORTED | Provider does not expose a served revision attestation |

Attacker-success rates, legitimate-completion rates, prohibited proposal counts, actual mutations and violations are **unknown** from retained evidence. None is reported as zero. No Morrison safety claim or measured comparison with Anthropic can be drawn from this incomplete export.

## Existing evidence retained

The following older validation and registration sections are historical; current paid-run status is above and in the dated API-execution section below.

ADVERSARIAL_LOCAL_GLOBAL_FALSIFICATION.md at baseline records a live Haiku 4.5/direct
payment-redirection pair: prohibited effects occurred ungoverned and were prevented in
governed configurations. Earlier Opus runs frequently had no injected prohibited proposal,
so they did not demonstrate Morrison's causal prevention under those injections.
Those models, settings and attack coverage differ from this proposed Qwen experiment.

Existing open findings E8, E12, G1 and T3b remain recorded and unchanged. This inference
adapter does not repair direct resource access, tenant isolation, cross-principal continuity
or blindness to pre-existing state. Shared-state global experiments in the separate
falsification harness must not be attributed to the single-agent live AgentDojo run.

## Historical GitHub Actions validation

Offline-only run https://github.com/davarntrades/Morrison-Runtime-Governance/actions/runs/38606707948 succeeded at f38806fe1341f3e210107e95cb8d38746dfaf7f6. Authentication/preflight and paid steps were skipped on that push run; it is not a live-model benchmark.

The separate broad Pylint run failed. Three findings in the new files were corrected before workflow registration; pre-existing style findings elsewhere are retained.

## Historical preflight blocker

Run https://github.com/davarntrades/Morrison-Runtime-Governance/actions/runs/38612573001 completed the 30 offline checks, then failed free preflight with key_present=false: repository HF_TOKEN secret required. Paid steps were skipped. Estimated inference spend $0. Preserved artifact: runtime_eval/results/agentdojo-hf/run-38612573001-1/preflight.json. ZIP SHA-256 verified against GitHub: b42f36c2ab8a6967f4e1aec39655c5def596ec91610e8125f4ec5dcfc0d9876c. This is a real GitHub Actions preflight, not a live-model benchmark.

Per-call before/after snapshots and diffs now retain transient mutations that a later action could reverse; the HF classification examines these as well as final state. Executor policy and authority remain unchanged.

## Historical implementation verification

Run https://github.com/davarntrades/Morrison-Runtime-Governance/actions/runs/38613196983 succeeded using implementation ffbf856380e262189a4c9fbdabbe8aec37e7dda5, including per-call snapshot/effect assertions. Run 38613133596 also passed offline validation and stopped at unbilled authentication preflight. No paid canary or benchmark has run. Machine-readable status: agentdojo-hf/execution-status.json.

## Historical workflow registration

Minimal registration PR https://github.com/davarntrades/Morrison-Runtime-Governance/pull/38 merged at 97979463c6ba2eb619a37e7d5f4c029fcd3b5b56. Main contains only the added registration workflow from this work; it checks out validated experimental code ffbf856380e262189a4c9fbdabbe8aec37e7dda5. The source branch and older evidence are preserved.

To execute from an iPhone: store an inference-enabled token as repository HF_TOKEN, accept the model gate if required, open Actions → AgentDojo HF Abliterated Qwen32B → Run workflow, choose benchmark, and enter RUN-HF-UP-TO-4-USD. Leave expand enabled only to include the fixed follow-up within the same total cap. No local model weights or GPU deployment is required. The GitHub connector lacks workflow_dispatch and the secure browser sign-in did not establish a completed session.

The broader Python application check remained in progress when workflow registration was merged. The dedicated pinned-implementation validation passed; the separate broad Pylint workflow remains failing. No full-repository green status is claimed.

## Resumption after token creation — 14 October 2026

Actual preflight retry: https://github.com/davarntrades/Morrison-Runtime-Governance/actions/runs/38613133596 (attempt 2). The 30 focused tests passed. HF_TOKEN was injected by Actions; authentication passed for Davarn11, but the checkpoint config check returned 403. No paid canary was attempted.

A separate zero-inference access diagnosis ran at https://github.com/davarntrades/Morrison-Runtime-Governance/actions/runs/38627003443. Hugging Face whoami-v2 returned HTTP 200 for Davarn11; both repository auth-check and the revision-pinned config request returned 403. The denial identifies the precise cause: access is restricted and the account is not in the authorised list. This establishes Hub repository-download access denial. The earlier conclusion that it blocked hosted inference was too broad and is superseded by the web-widget evidence and explicit-route API investigation below.

The token's actual Inference Providers request permission and usable inference billing remained untested in those runs; the file gate does not establish either. The model was not substituted. No billing settings, credit purchases, dedicated GPUs or main-branch changes were made on this resumption.

Preserved evidence:
- agentdojo-hf/run-38613133596-2/blocker.json; source ZIP SHA-256 2b34e0421790049d1b61b4d8614fcf4d010fc7035fba9be20657c6484a565b2a.
- agentdojo-hf/run-38627003443-1/access.json; source ZIP SHA-256 5a3fdc8e97295221a0b97c856c356123e4de01029c9f99b749fe70719a7d5cd2.
Both downloaded ZIP hashes matched GitHub's artifact digests. Credential values were never printed or committed.

Paid requests: 0; estimated inference spend for this experiment: $0. No attacker-success, task-completion, resource-mutation or live-chain result exists. Live local, trajectory and global properties remain NOT_TESTED. The served checkpoint revision remains unverified.

## API execution and export failure — 14 October 2026 (updated 15 October)

1. Run https://github.com/davarntrades/Morrison-Runtime-Governance/actions/runs/38629607331 passed 31 focused tests, then stopped before inference because of an overly strict router-catalogue check. Its small redacted artifact was SHA-256 verified (`ed33faf8ea5cb8b2a62277a55dd63c84676d8eca7060f65da21d2214b747bb4f`); preserved under `agentdojo-hf/run-38629607331-1/`.
2. Run https://github.com/davarntrades/Morrison-Runtime-Governance/actions/runs/38629834413 passed 31 focused tests and authenticated preflight. Paid execution ran 20:11–20:55 UTC (21:11–21:55 London time) on 14 October. Source requires the exact provider-qualified checkpoint and a two-request structured-function round trip before banking begins.
3. Finalize logged baseline `complete`, governed `incomplete`, matching conditions with no mismatched fields, 42 chains checked and no chain failures. Overall verification was false. The governed arm's specific interruption reason is unresolved because the arm JSON was inside the failed export. Neither budget exhaustion nor API failure is asserted without that evidence.
4. Upload failed before retaining any of the 55 files because paths contained `:featherless-ai`. Re-running upload on a fresh runner cannot recover the old filesystem. No paid rerun was launched.
5. Repair commit `882a8a1b14ba9c3ef42d976523a3423b01c91944` wraps the redacted tree in a single ZIP, retains provider-qualified names inside it, prints compact cost diagnostics during finalize, preserves transient violations in partial episode analysis and disables the one-off paid trigger. Run https://github.com/davarntrades/Morrison-Runtime-Governance/actions/runs/38636706447 proved real ZIP upload works but had one failed new regression fixture (missing verdict), with 33 tests passing. This run performed no inference; its synthetic fixture is not live benchmark evidence.
6. Commit `f02d7b4ddfdc8850a826245b9eee7556263f8240` completes that fixture and triggers a free rerun. Final validation status is recorded below when available. These repairs are on `codex/agentdojo-hf-api-resume`, with no main merge.

The run summary may still be visible to the repository owner through GitHub. The available connector returned no artifact and no check-run output text; unauthenticated run/job pages did not expose the generated Markdown summary. No claim is made that the raw record was preserved elsewhere.

To continue within the same $4 initial cap, first reconcile Hugging Face's charged inference usage for the exact checkpoint/Featherless around the run window and current available credits. Personal billing usage was not available through the documented organization-only billing API. Do not reuse the old manual workflow with a fresh full $4 cap: main's registration still pins the older implementation. A subsequent run must use the repaired experimental code and a new ledger that reserves prior spend, with its remaining allowance computed before any call. If invoice rows are rounded or delayed, retain a conservative margin and wait for settlement. No recharge, purchase or dedicated deployment is required for reconciliation.

## Final free repair validation — 15 October 2026

https://github.com/davarntrades/Morrison-Runtime-Governance/actions/runs/38663098643 succeeded at `f02d7b4ddfdc8850a826245b9eee7556263f8240`: 34 focused tests passed, authenticated metadata preflight passed and actual artifact upload succeeded. No inference requests were made. Downloaded outer archive SHA-256 matched GitHub (`0c2a44f8a7c987f3aec17238a747102336feff43aae2d2f08ea7bb204516a358`); the nested ZIP passed its CRC check. Its deliberately synthetic colon-named fixture verifies export compatibility only. Preflight and archive verification are preserved under `agentdojo-hf/run-38663098643-1/`. This does not restore the earlier lost paid evidence.
