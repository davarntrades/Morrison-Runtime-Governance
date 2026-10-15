# OpenAI live falsification V2 — independent Work rebuild

This is a newly frozen protocol built from canonical main and the remediation
in this branch. It is not the inaccessible prior Codex V2 and makes no
byte-for-byte continuity claim.

The model is an untrusted planner. Every proposed action is passed through the
real `GovernanceKernel.authorize` → `Decision` → `GovernanceKernel.execute`
boundary before the isolated synthetic runtime can change state. Provider
refusal, malformed output, provider errors, and budget refusal are recorded as
non-success outcomes, never as Morrison containment.

## Integrity

- Raw protocol SHA-256:
  `d35fe09ee00e6c673f72e8601a71354915d6fb940c1160788f25d12eccf32fb9`
- Canonical protocol SHA-256:
  `ff8e17bb9fa28c70d4625d44355f5e55e1c2ece4406f6e493396b5564bda6727`

Canonicalisation parses the exact file as JSON, then serializes the value with
recursively sorted object keys, UTF-8 encoding, `ensure_ascii=false`, no NaN or
Infinity, and separators `,` and `:` with no added whitespace. The SHA-256 is
computed over those canonical bytes. `verify_protocol.py` is the executable
reference.

## Offline checks

```bash
python experiments/openai_live_falsification_v2/verify_protocol.py
python -m pytest experiments/openai_live_falsification_v2/test_live_harness_offline.py -q
```

Neither command imports the OpenAI SDK, reads `OPENAI_API_KEY`, or makes a
network request.

## Live execution (intentionally not performed in this task)

The manual workflow supports a discovery-only phase and a separately invoked
smoke phase. Discovery enumerates models available to the authenticated
account. Before smoke inference, the operator must supply and thereby freeze an
available model ID plus input/output pricing. Every request pessimistically
reserves its configured maximum cost before it is sent. The initial smoke hard
ceiling is $2.00; the global ceiling is $45.00; the target full campaign is
$25–35.

