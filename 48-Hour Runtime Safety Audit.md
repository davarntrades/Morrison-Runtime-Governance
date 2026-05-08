<div align="center">

# 48-Hour Runtime Safety Audit

**Find out what your AI agents can execute — before they execute it.**

Resurrection Tech Ltd · Morrison Framework™

</div>

-----

## How It Works

|Step                        |What Happens                                                                                                                  |Time  |
|:---------------------------|:-----------------------------------------------------------------------------------------------------------------------------|:----:|
|**1. Free Preview**         |You send us your agent architecture (tool definitions, planner format, target domains). We confirm scope and feasibility.     |30 min|
|**2. Ω Configuration**      |We define domain-specific forbidden states based on your operational requirements.                                            |4 hrs |
|**3. Governance Evaluation**|We run the Morrison governance layer against your agent’s tool call patterns. Every trajectory is classified: PERMIT or BLOCK.|24 hrs|
|**4. Report Delivery**      |You receive a full report: which trajectories reached Ω, which didn’t, where your attack surface is, and what to do about it. |48 hrs|

-----

## What You Get

- **Trajectory classification** — every tool call plan evaluated for reachability into Ω
- **Attack surface map** — chained attacks, delayed intent, privilege escalation, data exfiltration paths
- **Domain Ω report** — which forbidden states are reachable from your current architecture
- **Risk priority matrix** — ordered by severity and reachability distance
- **Remediation path** — what structural changes prevent unsafe trajectories

-----

## What You Send Us

- Tool definitions (names, parameters, descriptions)
- Example planner outputs (tool call format your LLM produces)
- Domain context (what must never happen — unauthorized transfers, credential access, PHI exposure, etc.)
- Optionally: logs of recent agent tool calls for pattern analysis

No model access required. No code deployment. We evaluate the trajectory geometry, not the model.

-----

## Investment

|Component                         |Cost       |
|:---------------------------------|:----------|
|Free preview (scope confirmation) |£0         |
|48-Hour Runtime Safety Audit      |£18K–25K   |
|Follow-on: Structural Safety Pilot|£120K–250K+|

-----

## Why 48 Hours

The governance layer evaluates trajectories at ~100K per 4.5 seconds. The time is spent on Ω configuration and report production, not computation. Your results reflect your operational reality, not synthetic benchmarks.

-----

<div align="center">

*If your systems can execute actions, they can execute unsafe ones.*
*This audit determines whether they are allowed to.*

**Contact: Davarn Morrison**
Founder — Resurrection Tech Ltd
GitHub: [github.com/davarntrades](https://github.com/davarntrades)

© 2026 Davarn Morrison — Intelligence Invariant™ · All Rights Reserved

</div>
