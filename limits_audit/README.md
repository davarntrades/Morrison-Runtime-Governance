# Limits Audit — three empirical probes against the real engine

Three standalone scripts that test specific claimed limitations of the
Morrison Runtime Governance authorization kernel. They import the real
`morrison_governance` package and drive the real `GovernanceKernel`; nothing
is simulated or mocked out of the decision path. The only fixtures are the
tool functions that stand in for real side effects, so that an execution can
be counted.

```
python3 limits_audit/test_1_containment.py
python3 limits_audit/test_2_coverage.py
python3 limits_audit/test_3_escalation.py
```

| Probe | Question |
|---|---|
| `test_1_containment.py` | Is there a path to tool execution that skips the governed authorization interface? |
| `test_2_coverage.py` | What does the governor actually check, and what integration point is not wired into it? |
| `test_3_escalation.py` | What happens after ESCALATE if no human ever responds? |

Findings are summarised in `FINDINGS.md`.
