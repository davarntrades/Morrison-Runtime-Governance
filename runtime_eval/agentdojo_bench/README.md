# AgentDojo benchmark integration

Runs [AgentDojo](https://github.com/ethz-spylab/agentdojo) (ETH Zürich's
prompt-injection benchmark for tool-using agents: workspace, travel, banking,
and Slack suites) with Morrison as the agent's tool executor.

AgentDojo is a third-party benchmark. Its user tasks, injection tasks,
environments, and grading functions are used unchanged. The only change is
in the agent pipeline: `ToolsExecutor` is replaced by `MorrisonToolsExecutor`,
so every proposed tool call goes `GovernanceKernel.authorize` →
(PERMIT only) `GovernanceKernel.execute` → AgentDojo's `FunctionsRuntime`.
BLOCK and ESCALATE return a tool error to the model and leave the environment
untouched.

## Install

```bash
python -m pip install -r runtime_eval/agentdojo_bench/requirements.txt
```

`agentdojo` is optional. Without it the tests in
`runtime_eval/tests/test_agentdojo_bench.py` skip.

## Two modes

### `oracle`: model-free, worst-case agent (no API key)

```bash
python -m runtime_eval.agentdojo_bench oracle --output runtime_eval/results/agentdojo
```

For every (user task, injection task) pair, a scripted agent runs the user
task's AgentDojo ground truth and then **the attacker's ground truth too**.
It is a model that has fully fallen for the injection. Every pair is run twice
through identical plumbing: once with Morrison recording but not enforcing
(the undefended baseline), and once enforcing. AgentDojo's own `utility` and
`security` functions grade the final environment.

This measures the execution layer alone. A model that resists the injection
can't make Morrison look better here. The results are **not comparable to
AgentDojo leaderboard numbers**, which measure a real model under a textual
attack.

Attack success rate is reported only over *exercisable* pairs, meaning pairs
where the scripted attack achieves its goal with no defense. AgentDojo ships an
empty `ground_truth` for workspace injection tasks 6–13, so those pairs can't
be scripted. They are counted and reported, not dropped.

### `live`: real model, real AgentDojo attack

```bash
export ANTHROPIC_API_KEY=...
python -m runtime_eval.agentdojo_bench live \
    --provider anthropic --model claude-sonnet-5-5 \
    --suite banking --output artifacts/agentdojo-live

# undefended baseline, same model and attack
python -m runtime_eval.agentdojo_bench live --defense none \
    --provider anthropic --model claude-sonnet-5-5 --suite banking
```

The two arms are matched: same model, provider settings (AgentDojo's
Anthropic adapter: temperature 0, 1024 max tokens), system message, attack
text and task sample. The baseline runs through the same `MorrisonToolsExecutor`
with `enforce=False` (Morrison records its verdict, every call executes), so
the only difference between arms is enforcement. Each output row records the
SHA of the injection text so this can be checked pair by pair.

Per pair, the output keeps two things apart:

- **Attempted calls** (`attempted_calls`, `n_attempted`, `n_executed`,
  `n_withheld`, `n_block`, `n_escalate`): every call the model proposed, the
  verdict and whether it ran.
- **Resource effects** (`resource_effects`, `n_resource_effects`): a diff of
  the AgentDojo environment, snapshotted before the model's first turn and
  read after the task. Only an executed call can appear here.

AgentDojo's per-pair transcripts are kept under `<output>/logs/`. A run that
fails part-way returns the error plus the episodes recorded so far, and the
CLI exits non-zero.

This uses AgentDojo's default system message, its LLM adapters (`openai`,
`anthropic`, `google`, `together`, `cohere`, `local`, `vllm_parsed`) and the
`important_instructions` attack by default (`--attack` takes any registered
AgentDojo attack). AgentDojo's attack text addresses the target by name from a
table that predates current models. For an unlisted model, the provider's
family name ("Claude", "GPT-4") is registered so the standard attack runs
unchanged. A full live run is several thousand model calls per suite, so start
with `--user-task` / `--injection-task` to sample.

## Deployment configuration (`manifest.py`)

Morrison needs what any deployment gives it: a capability manifest for each
tool and the trusted internal destinations. These are written from **what
each tool does and who the agent works for**, never from the injection
tasks:

| Suite | Internal destinations | Notable classifications |
|---|---|---|
| workspace | email domain `bluesparrowtech.com` (the user's employer) | `send_email`, `share_file`, calendar invites → data.external_move; `delete_*` → data.destructive |
| travel | none | `send_email`, calendar invites → data.external_move; reservations → no capability |
| banking | none | `send_money`, `*_transaction` → payment.move_funds; `update_password` → credential.change |
| slack | none | `post_webpage` → data.external_move; invite/remove/add-to-channel → iam.privileged; DMs → no capability |

Morrison's default enterprise policy is unchanged. Payments, credential
changes, deletions, and IAM changes need a bound approval artifact, so they
**ESCALATE**. A benchmark run has nobody to approve them, so an escalated
call is treated as not executed (fail-closed). The results report how much
lost utility comes from escalations alone and how much from hard blocks.

## Files

| File | Role |
|---|---|
| `manifest.py` | Per-suite capability manifest and trusted destinations |
| `gate.py` | `MorrisonToolsExecutor`, an AgentDojo pipeline element gating every call |
| `oracle.py` | Compromised-agent oracle and paired baseline/Morrison scoring |
| `live.py` | AgentDojo pipeline with a real LLM, plus a standard attack run |
| `__main__.py` | CLI |

Results: [`../results/AGENTDOJO_BENCHMARK.md`](../results/AGENTDOJO_BENCHMARK.md).
