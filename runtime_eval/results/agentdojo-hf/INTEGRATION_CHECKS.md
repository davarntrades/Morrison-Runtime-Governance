# Research integration checks — 15 October 2026

Base main: `97979463c6ba2eb619a37e7d5f4c029fcd3b5b56`.

- 28 imported report/evidence files match source Git blob identities exactly. SHA-256 and byte lengths are recorded in `RESEARCH_INTEGRATION_MANIFEST.json` alongside the additional historical source archive.
- Both evidence ZIPs pass CRC checks; their SHA-256 hashes match the retained archive manifest. This is transport integrity checking, not another scientific evidence reanalysis.
- Every file in the new execution-source archive matches execution commit `f2b9a6ce369fbab0f4e5a23e5d656d2eef947172`.
- Relative links in the integration README resolve. No report measurements were edited.
- Integration allowlist contains only `runtime_eval/results/AGENTDOJO_HF_QWEN32B.md` and `runtime_eval/results/agentdojo-hf/`. No production, test, policy, workflow, ARSB or violation-ledger files change.
- Existing main's inference workflows require manual dispatch. No workflow is imported, modified or dispatched. Source branch one-off paid replay remains disabled. No secrets are accessed or modified.

## Offline regression

Python 3.12 with the retained benchmark environment's site-packages; pytest 9.1.1:

`python -m pytest -q morrison_governance runtime_eval/tests`

Result: **1,195 passed, 7 skipped, 1 failed**. Failure:
`morrison_governance/test_evidence_consistency.py::test_readme_suite_count_matches_a_real_collection`.
README publishes 1,657; actual collection reports 1,666.

The identical single-test failure was reproduced on an untouched detached checkout of base main, with the same environment. It predates this integration. No tests, findings or README counts were changed to conceal it.

Main's existing Pylint run also failed before this integration:
https://github.com/davarntrades/Morrison-Runtime-Governance/actions/runs/38613552057
Main's historical Python application run passed:
https://github.com/davarntrades/Morrison-Runtime-Governance/actions/runs/38613552214
These historical CI outcomes are distinct from the local regression result above.

The connector cannot read branch-protection settings (GitHub 403, administration access unavailable). Required-check configuration therefore cannot be independently confirmed through that endpoint. The pull request must remain open if its required checks do not pass; no force merge or protection bypass is authorised.

No paid inference, experiment replay or completed evidence verification was performed during integration.
