# Independent Agent Exposure Audit (£5,000, bounded scope)

> **ILLUSTRATIVE SAMPLE.** The client in this repository is SCE-02, a fictional UK motor
> insurer. No real organisation, model or payment system is involved.

An entry-level engagement. It answers three questions for one autonomous agent in one
workflow:

1. What can the agent actually reach and execute?
2. Do the organisation's existing safeguards enforce the local and global constraints it claims?
3. What prohibited actions or sequences remain reachable, and what evidence supports that?

The organisation's own safeguards are the subject. A Morrison Runtime Governance boundary
appears only as a separately labelled comparison. Recommendations name no product, and
Resurrection Tech's dual role (auditor and enforcement vendor) is disclosed in every report.
This offering does not change the Enterprise Runtime Governance Audit's scope or pricing.

## Run it

```bash
python -m audit_demo.exposure --output audit_demo/deliverables
```

No `agentdojo`, model, network or credentials are needed. One command writes
`deliverables/SCE-02_Independent-Agent-Exposure-Audit/` (and a `.zip`). It takes about 3 seconds
of compute.

| Pack item | Requirement it meets |
|:--|:--|
| `01_scope/` | Scope statement, constraints, controls, assumptions, exclusions; onboarding requirements; the customer adapter contract |
| `04_report/…Executive_Summary…pdf` | Board-readable executive summary |
| `04_report/…Technical_Report…pdf` | Reachability, local and global findings, adversarial results, control verification, residual exposure register, comparison, methodology and limitations |
| `02_assessment/` | Executed assessment with state before and after every step |
| `03_enforcement_evidence/` | One record per step, plus a register (CSV) |
| `05_verification/` | Independent verification (15 checks, including replay), self-tests (11 tampering attempts), reproducibility, report-immutability and offline checks |
| `MANIFEST.sha256` | Integrity: `sha256sum -c MANIFEST.sha256` |
| `index.html` | Offline evidence viewer linking every finding to its records |

## Modules

| Module | Role |
|:--|:--|
| `adapter.py` | The customer adapter contract: declared and observed operations, the customer-control path, the direct (test-only) path, observation, and unobservable state |
| `sce02.py` | The fictional customer: claims platform (system of record), customer controls with seeded weaknesses SW1–SW10, and the explicitly configured Morrison comparison |
| `scenarios.py` | 29 executed scenarios (3 benign, 14 local, 10 global, 2 combined) and 3 unsupported or untested items |
| `run.py` | Executes each scenario in the customer, no-control and Morrison arms; classifies outcomes from state only |
| `metrics.py` | Figures with explicit denominators; residual register; vendor-neutral actions |
| `report.py` | Technical report and executive summary in the original Resurrection Tech branding |
| `verify.py` | Independent re-derivation of every outcome and printed figure, evidence-ID resolution, neutrality, coverage, digest and replay checks |
| `selftest.py` | Mutation tests that try to make the verifier accept a wrong result |
| `findings_log.py` | Counterexamples found while building this audit (DF1–DF12), recorded before any change |
| `pack.py` | End-to-end pipeline and offline viewer |

## Outcome vocabulary

- **HELD** / **FAILED**: the prohibited state was absent / present in the system of record
  after the customer's safeguards acted.
- **FAILED_MISREPORTED**: the safeguard reported a block, but the state changed anyway.
- **INCONCLUSIVE**: the result depends on state the audit cannot observe. It is never counted as
  prevented.
- **UNSUPPORTED** / **NOT_TESTED**: outside the bounded scope. Listed, never counted.
- For the comparison only, **PREVENTED_BY_FAIL_CLOSED_ERROR**: stopped by error handling, not
  by a policy rule.

## Readiness

| Area | Status |
|:--|:--|
| Executable end-to-end audit through a documented entry point | **Supported** |
| Local and global constraints evaluated separately, and together | **Supported** |
| Reachability separating documented, observed and untested | **Supported** (bounded; not exhaustive) |
| Outcomes from execution and state, not verdicts or control reports | **Supported** |
| Failures, inconclusive and unsupported items in the report | **Supported** (enforced by the verifier) |
| Every evidence reference resolves; figures recomputed independently | **Supported** |
| Pack inspectable offline | **Supported** (checked with network blocked) |
| Original branding | **Supported** |
| Real customer onboarding (adapter for a real agent stack) | **Uncertain**: SCE-02 is hand-built; no real adapter exists yet |
| 48-hour delivery | **Uncertain**: credible only if the adapter and sandbox exist before the clock starts |
| Frontier Lab integration | **Unsupported** for customer adapters. Frontier runs its own simulator and policy; usable separately for model-behaviour questions |
| Control Room integration | **Unsupported / not tested**: its repository was not available |
| Concurrency, time windows, live-model behaviour | **Unsupported** in the £5,000 scope |
