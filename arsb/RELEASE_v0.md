# ARSB v0 — development release (frozen)

**Status: development benchmark.** Frozen so results can be compared and challenged, not validated as a standard.
Do not quote ARSB v0 results as a comparative ranking of the systems it includes until the independent challenge
(`CHALLENGE.md`) has reported.

Tag: `arsb-v0-dev`. Spec: `SPEC.md` v0.1.1. Frozen file hashes: `FREEZE.json`.

## What is frozen

| Part | Files | Rule |
|---|---|---|
| Benchmark | `SPEC.md`, `core/*`, `scenarios/*.json` + `MANIFEST.json` + `_build.py`, `__main__.py`, `freeze.py`, reference baselines | never change within v0; `python -m arsb.freeze check` fails otherwise (also a unit test) |
| Third-party adapters | `adapters/morrison.py`, `adapters/progent_adapter.py`, `adapters/camel_adapter.py` | may be revised only to translate a capability the SUT has gained; every result produced with a revised adapter states the revision and its diff |
| Results | `results/v0/run1`, `results/v0/run2` | retained as published; reruns are checked with `python -m arsb.freeze verify` |

## Reproducibility package

- `repro/reproduce.sh`: checks freeze, builds a venv from the locks, reruns everything, verifies outcomes.
- `repro/base-environment.lock`, `repro/competitors.lock`: exact packages (Python 3.13.16), including
  `progent @ 5be7b63` and `camel-prompt-injection @ f083b6b`.
- `scenarios/_build.py` regenerates the scenario files byte for byte (hashes in `MANIFEST.json`).
- `results/v0/run{1,2}/arsb-results.json`: every repetition, step outcome and predicate; SHA-256 beside each.
- Outcomes (classification, per-repetition violation and utility) are deterministic across runs; timings and temp
  paths are not and are excluded from verification.

## Known limitations (binding on any use of v0 results)

1. Scripted threat model only; no live-model results.
2. One author wrote the spec, scenarios and all adapters, and also evaluated Morrison — a conflict of interest.
3. No held-out scenario set yet; all 23 scenarios are public.
4. CaMeL is driven by compiled programs (no privileged or quarantined LLM); its approval-required policy is a denial
   because its code has no confirmation path. Progent's approval is simulated at its stdin prompt.
5. Single host; thread concurrency only; no multi-process, multi-host or retention-window scenarios.
6. EVD and FCL families are runnable only for systems that export evidence or expose fault hooks (only Morrison in
   v0): results there are not comparative.
7. Small scenario counts per family (1–5); a single scenario can decide a property cell.
8. Synthetic fixture; operations are strict (positive whole amounts), which removes some attacks (e.g. negative
   transfers) by construction.
