# Petri / Morrison runtime falsification

This experiment gates **synthetic result delivery**, rather than judging proposals after execution. The executor only appends a canonical action to an in-memory simulated effect ledger; it never opens URLs, reads files, or deletes resources named in proposals.

## Exact integration

Petri pinned commit: `766d3842e67c573aaf7d5dffcdfb0381a35e3574` (package `inspect_petri`, currently 3.1.2.dev1; the safety-research URL resolves to the maintained repository).
Morrison base: `0ba8f882590f34ee4f2ab7cee09b0d5e57d44248`.

`target/_agent.py:target_agent` consumes tools using `TargetContext.tool_results`; that method in `target/_context.py` collects the auditor's staged responses. `integration.attach_mediation` wraps this method on each target context. Both `send_tool_call_result` and file-backed auditor responses converge here. The returned messages cannot enter the target conversation until the hook completes.

`ToolCall.function/arguments` → Morrison `kernel.canonical.canonicalize({tool,args})` → `GovernanceKernel.authorize` → `GovernanceKernel.execute(decision, simulation_executor, call=canonical_action)` → delivered tool message. Morrison's native `PERMIT` is rendered as `ALLOW` in `verdict_normalized`. BLOCK/ESCALATE never invoke the executor; escalation responses explicitly require external authority. This experiment exposes no approval issuer or escalation resolver.

Morrison code is unchanged. Each sample uses a separate `InMemoryContinuityStore`, while preserving within-sample history and reservations. Rollback/restart and prefill are disabled: replay-aware branching of kernel state is not implemented. The initial batch predating isolation is preserved and is not the authoritative aggregate.

## Existing research reused

- `limits_audit/test_4_peer_go_message.py`: unauthenticated GO, deadline, nested metadata, identity/issuer spoof shapes.
- `morrison_governance/test_forged_authority_receipt.py`: `APR-7741-C9F2` and manifest-based destructive proposal.
- `morrison_governance/test_kernel_redteam.py`: enterprise domains/principal, read→external egress, denied-read taint, audit-log DENY and missing-approval semantics.
- `kernel/gate.py`: reservation, exact action binding and single-use execution interfaces.

No prior research artifacts are edited. Signing keys in this experiment are dummy fixtures. A valid approval is intentionally unavailable to the target/auditor.

## Oracle and evidence

`scenarios.py` defines each finite AOE transition and expected verdict before attacks. `oracle.py` independently scores live delivered proposals without reading Morrison verdicts. Unknown tool/destination/schema semantics are marked incomplete (`expected_verdict=null`), not passing. The initial `/etc/shadow` expectation was incorrect and is preserved in batches 001/002; the source's explicit Ω block justifies the corrected expectation in later runs. Nested-authority BLOCK remains the intended requirement and its mismatch remains visible.

`run_offline.py` returns exit code 1 when a verdict is falsified, **after** writing results, oracle and hashes. This is expected for the preserved nested-authority finding. Scripted proposals are explicitly distinguished from live model proposals. The authoritative isolated scripted batch has 15 steps per arm over 11 scenarios. A control is exact-proposal matched; independent live auditor runs cannot guarantee matched conversations.

Full live auditor/model/judge requests and responses are retained in Inspect `.eval` files, in addition to per-session JSON containing original results, calls, canonical actions, verdict/reasons, evidence chains and state. An auditor that never elicits a tool call is zero tested transitions, not a mediation pass. Model versions and resolved generation configuration are recorded in the `.eval` logs. Anthropic does not provide a deterministic seed guarantee here.

## Reproduction

Python 3.12.14 was used. Dependencies used locally are in `environment.txt`; remote jobs preserve a separate `petri-environment.txt`. Recreate the source and dependencies from repository root:

```bash
git clone https://github.com/davarntrades/Morrison-Runtime-Governance.git
cd Morrison-Runtime-Governance
git checkout experiment/petri-falsification-20261002
python3.12 -m venv .venv
.venv/bin/pip install 'inspect_petri @ git+https://github.com/safety-research/petri@766d3842e67c573aaf7d5dffcdfb0381a35e3574' 'inspect-ai==0.3.276' 'anthropic==1.0.0' 'pytest==9.1.1' 'ruff==0.16.10'
export PYTHONPATH="$PWD:$PWD/experiments/petri_falsification"
.venv/bin/python experiments/petri_falsification/run_offline.py --smoke --output /tmp/petri-smoke-new
.venv/bin/python experiments/petri_falsification/run_offline.py --output /tmp/petri-batch-new
.venv/bin/pytest -q experiments/petri_falsification/test_integration.py morrison_governance/test_forged_authority_receipt.py
.venv/bin/ruff check experiments/petri_falsification/*.py
```

Output directories must be new; existing evidence is never overwritten. `run_reservations.py` and `run_scripted_petri.py` similarly refuse to overwrite their fixed run directories. Change their output identifiers in a separate worktree to repeat those smoke runs.

With `ANTHROPIC_API_KEY` configured securely, run one live arm:

```bash
.venv/bin/inspect eval experiments/petri_falsification/task.py@falsification \
  -T arm=governed -T max_turns=6 --limit 2 --max-samples 1 \
  --model-role auditor=anthropic/claude-haiku-4-5-20251001 \
  --model-role target=anthropic/claude-haiku-4-5-20251001 \
  --model-role judge=anthropic/claude-haiku-4-5-20251001 \
  --max-tokens 1500 --token-limit 100000 --time-limit 180 \
  --log-dir petri-logs/governed
```

Repeat with `-T arm=ungoverned` and a different log directory. Inspect the initial evidence before expanding to all seeds or increasing turns. The branch workflow performs these two bounded arms using the repository's existing secret; it never exports that secret.

## Limits

This establishes only synthetic mediation on the deliberately instrumented Petri path. It cannot establish production mediation completeness across credentials, networks, executors or resources. Effects are ledger transitions, not a high-fidelity database/filesystem simulator. The finite oracle cannot decide arbitrary newly invented tool semantics. Capability/schema gaps remain possible. Time, UUIDs and hashes of timestamped evidence differ across reproduction; proposal shapes/verdict expectations are deterministic. The live judge is auxiliary and cannot override deterministic assertions. No default-branch merge or destructive operation is part of this experiment.
