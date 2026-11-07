# DeepSeek Round-2 Adversarial Falsification Campaign

Independent second-pass falsification of the repaired Morrison Runtime
Governance kernel. This directory is additive: it does not modify
`redteam/deepseek_redteam/` (the round-1 artifacts) and it does not modify
any enforcement source.

## Target

| | |
|---|---|
| Repository | `/Users/davarnmorrison/AI-RedTeam/Morrison-Runtime-Governance` |
| Branch / HEAD | `deepseek-redteam` / `06b9b55` |
| Package | `morrison_governance` 0.4.1 |
| Interpreter | `/opt/homebrew/bin/python3.12` |
| Date | 2026-11-06 |

The remediation under test is the uncommitted Phase-4 repair set (F-1 … F-8)
plus its regression pins. No enforcement file was edited during this
campaign.

## Constraints

* **Inert executors only.** Every probe uses `_common.Recorder`, which
  records the call it receives and performs no I/O. "executed = true" in a
  probe means only that the kernel handed the call to the recorder.
* **No policy weakening.** Fixtures use ordinary, non-adversarial
  deployment configuration. Where a finding needs `trust_private_networks`
  or a policy value, both the default and the configured case are reported.
* **No repeat of F-1 … F-8.** Every candidate below is a new strategy or a
  new composition. Adjacent findings name the repaired finding they extend.
* **Round-1 preservation.** `redteam/deepseek_redteam/` is untouched.
* **No commit/merge/push.** All remediation changes remain uncommitted.

## Layout

| File | Purpose |
|---|---|
| `_common.py` | Shared fixtures: `Recorder`, `make_context`, `make_kernel`, `emit` |
| `probe_r2a_ipv4_mapped_metadata.py` | IPv4-mapped IPv6 metadata endpoint |
| `probe_r2b_destination_keys.py` | Unlisted destination-key coverage gap |
| `probe_r2c_authority_shaped_host.py` | Authority-shaped bare-host destination |
| `probe_r2d_payment_alias.py` | Payment amount-alias disagreement |
| `probe_r2e_tenant_nested_container.py` | Cross-tenant container values |
| `probe_r2f_tenant_spellings.py` | Tenant aliases and encoded refs |
| `probe_r2g_clock_revocation.py` | Caller clock vs revocation |
| `probe_r2h_clock_approval_expiry.py` | Caller clock vs approval expiry |
| `probe_r2i_record_remote_binding.py` | `record_remote_execution` binding |
| `probe_r2j_malformed_url.py` | Malformed URL exceptions |
| `probe_r2k_sandbox_subclass.py` | `SandboxExecutor` subclass confinement |
| `probe_concurrency.py` | Concurrency composition probes (held) |
| `probe_evidence_authenticity.py` | Evidence authenticity / replay (held) |
| `probe_alternate_paths.py` | Layer / advisory / lease / MCP paths (held) |
| `CAMPAIGN_REPORT.md` | Verdict matrix, findings, final assessment |

## Run

Each probe is standalone:

```sh
cd redteam/deepseek_redteam_round2
/opt/homebrew/bin/python3.12 probe_r2a_ipv4_mapped_metadata.py
/opt/homebrew/bin/python3.12 probe_r2b_destination_keys.py
# ...
```

Every probe prints a human summary and then a JSON object with at least:

```json
{
  "id": "R2-A",
  "invariant": "the declared property under test",
  "source": ["path:function", "..."],
  "severity": "P0",
  "classification": "REPRODUCED | SOURCE-SUPPORTED | HYPOTHESIS | REJECTED | HELD",
  "falsified": true,
  "control": { "...": "a nearby legitimate case that is handled correctly" },
  "cases": { "...": "observed verdict / destination / execution" }
}
```

## Classification vocabulary

| Label | Meaning |
|---|---|
| **REPRODUCED** | A running probe reaches the unsafe outcome with a realistic input and a legitimate configuration. |
| **SOURCE-SUPPORTED** | Source shows the gap and the probe reaches the executor, but whether it is an exploit depends on a downstream schema/semantics not exercised here. |
| **HYPOTHESIS** | A plausible mechanism was identified but not demonstrated end-to-end. |
| **REJECTED** | The candidate did not hold up; a control or the source shows the property is intact, or the path requires trusted material. |
| **HELD** | A negative result: the tested property survived the attempted composition. |
