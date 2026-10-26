# Published raw evidence

Raw, reproducible evidence for the monitoring-incident Phase 1 runs, published in
response to the independent audit (§9: "the reported run's raw evidence was not
published"). Generated against commit `a7f3c14` on the frozen manifest
`monitoring-incident-manifest-v1` (sha256 `a054fcdb52fc…`), clean tree
(`governed_paths_dirty=false` on every run).

| file | contents |
|---|---|
| `EVIDENCE_ANCHOR.json` | one row per run (244 runs): `run_id`, suite, policy, scenario, condition, `case_id`, `manifest_sha256`, `commit`, `terminal_hash`, `evidence_valid`, and the key outcomes (`unauthorized_executed`, `monitoring_intact_final`, `enforcement_bypass_total`, `out_of_band_monitoring_break`, `uninspectable_monitoring_state`). |
| `raw_evidence.tar.gz` | every run's full `evidence.jsonl` (hash-chained records) and `summary.json`, under `<suite>/<run_id>/`. |
| `raw_evidence.sha256` | sha256 of the tarball. |

Runs: scripted `deny` (96) + scripted `oracle` (96) + counterexamples across all
four conditions (52) = 244.

## Independent anchoring and offline verification (audit §5, §9)

This is tamper-**evident**, not tamper-**proof**, and the docs no longer claim
otherwise:

- The hash chain is verified against a **retained terminal hash**. Committing
  `EVIDENCE_ANCHOR.json` to git is the external anchor: git history timestamps
  the terminal hashes outside the run directories, so a later rewrite of a run's
  `evidence.jsonl` (and its in-directory `summary.json`) no longer matches the
  committed `terminal_hash`.
- The per-episode HMAC signing key is in memory and never persisted, so decision
  signatures are **not** offline-verifiable. Offline verification here means
  re-deriving the hash chain and the action hashes and replaying effects with
  real tools (as the audit's `recompute.py` does), not checking signatures.

## Reproduce / verify

```bash
# regenerate (deterministic run_ids at this commit + manifest for scripted/counterexample runs)
python -m experiments.monitoring_incident scripted --output OUT --escalation deny
python -m experiments.monitoring_incident scripted --output OUT --escalation oracle
python -m experiments.monitoring_incident counterexamples --output OUT \
    --conditions ungoverned local_only global_only hierarchical

# verify any run's chain against its anchored terminal hash
python -m experiments.monitoring_incident verify \
    --log OUT/<run_id>/evidence.jsonl \
    --terminal-hash <terminal_hash from EVIDENCE_ANCHOR.json>
```
