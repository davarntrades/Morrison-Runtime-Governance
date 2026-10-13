# CI Setup and Reproducibility Guide

This repository ships lightweight GitHub Actions workflows for **bounded regression/invariance checking**.
These workflows validate pinned deterministic behavior; they do **not** claim universal safety guarantees.

## Workflows

## 1) `.github/workflows/ci.yml`

**Triggers:** `push`, `pull_request`

Validates:
- compile/import sanity checks
- deterministic core governance suites
- `runtime_eval` deterministic + adversarial hardening suites
- `multi_agent_eval` suite
- `global_governance` suite
- quickstart replay hash consistency across repeated runs

Failure conditions include:
- import or compile breaks
- deterministic suite regressions (including pinned governance bypass checks)
- quickstart replay hash drift

Artifacts uploaded:
- `ci_logs/*`
- `ci_artifacts/ci_summary.md`

## 2) `.github/workflows/reproducibility.yml`

**Triggers:** `pull_request`, `push` to `main`, manual `workflow_dispatch`

Validates:
- replay-sensitive suites (`runtime_eval`, adversarial hardening, multi-agent)
- repeated quickstart run hash sequence equality

Artifacts uploaded:
- `repro_logs/*`

## Output classification framing

When reading CI output, distinguish:

- **Governance failure:** pinned deterministic governance expectations regressed.
- **Malformed/no-plan output:** malformed proposal or no executable proposal path.
- **Planner self-refusal:** planner declines to act; not equivalent to a governance block verdict.

## Local reproduction

From repository root:

```bash
python -m pip install --upgrade pip
if [ -f requirements.txt ]; then pip install -r requirements.txt; fi
if [ -f runtime_eval/requirements.txt ]; then pip install -r runtime_eval/requirements.txt; fi

python -m compileall morrison_governance runtime_eval multi_agent_eval global_governance
python3 morrison_governance/test_governance.py
python3 morrison_governance/test_interception.py
python3 morrison_governance/test_open_world.py
python3 morrison_governance/test_long_horizon.py
python3 runtime_eval/tests/test_runtime_eval.py
python3 runtime_eval/tests/adversarial/test_hardening.py
python3 multi_agent_eval/tests/test_multi_agent_eval.py
python3 global_governance/tests/test_global_governance.py
python3 quickstart.py
python3 quickstart.py
```

Then compare replay hashes printed by the two quickstart runs; they should match in deterministic conditions.

## Badge examples

Replace `OWNER` and `REPO`:

```md
![CI](https://github.com/OWNER/REPO/actions/workflows/ci.yml/badge.svg)
![Reproducibility](https://github.com/OWNER/REPO/actions/workflows/reproducibility.yml/badge.svg)
```
