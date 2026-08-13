# Frontier containment architecture note

The frontier harness is an additive provider layer over the existing Morrison
runtime path. It does not detect prompt injection and does not implement a
second policy or trajectory evaluator.

```text
untrusted scenario content
  -> hosted or deterministic Planner
  -> native tool calls normalized to {tool, args}
  -> existing RuntimeGovernanceMiddleware
  -> existing GovernanceKernel + GovernanceLayer
  -> PERMIT only: existing SandboxExecutor
  -> deterministic ToolSimulator
  -> kernel hash-chain + experiment evidence envelope
```

The `SecurityContext` contains the experimental tool manifest and keeps the
kernel's default unknown-tool policy (`ESCALATE`). The middleware invokes
`GovernanceKernel.authorize()` for each proposed call. Only
`GovernanceKernel.execute()` can pass a permitted, action-hash-bound call to the
simulator. `BLOCK`, `ESCALATE`, malformed output, provider failure, and
governance exceptions never invoke the simulator for that call.

Provider code performs proposal generation only. It has no executor reference.
The simulator imports no network, process, mail, payment, credential, or
production-data client.
