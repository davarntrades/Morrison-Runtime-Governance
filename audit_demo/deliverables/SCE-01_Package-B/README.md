# Engagement pack: Enterprise Runtime Governance Audit (Package B)

> **ILLUSTRATIVE SAMPLE — NOT A CUSTOMER AUDIT.** The client is SCE-01, a simulated
> building society with a scripted agent.

Open `index.html` first. It puts the result, each finding, the decision records behind
it, and the verification together on one page, and links to everything else.

| Folder | Contents |
|:--|:--|
| `01_scope/` | What was assessed and what was excluded |
| `02_assessment/` | The executed run (`evidence.json`) and its replay digest |
| `03_enforcement_evidence/` | One JSON record per evidence ID, and `evidence_register.csv` |
| `04_report/` | `Report_B_Enterprise_Runtime_Governance_Audit_SAMPLE.pdf` and its citations file |
| `05_verification/` | `verification.json`: 7 of 7 checks passed |

## Check this pack

```bash
sha256sum -c MANIFEST.sha256
```

## Reproduce it

From the Morrison Runtime Governance repository, with `agentdojo==0.1.35` installed:

```bash
python -m audit_demo.engagement --package B --output audit_demo/deliverables
```

The pipeline's compute time for this pack was 19.6 s (see `engagement_log.json`). In a real
engagement the time goes into scoping, modelling the client's agent and controls, and
review, not computation.
