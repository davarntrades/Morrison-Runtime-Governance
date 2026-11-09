# Independent Verification — DeepSeek Phase 4 Falsification Campaign

**Target:** Morrison Runtime Governance (`morrison_governance` 0.4.1)
**Repository:** `/Users/davarnmorrison/AI-RedTeam/Morrison-Runtime-Governance`
**Branch / HEAD:** `deepseek-redteam` / `06b9b559509900f0950840b7a257c4a3c299ec56`
**Interpreter:** `/opt/homebrew/bin/python3.12`
**Verification date:** 2026-11-06

This report independently re-runs and re-derives every finding in
`redteam/deepseek_redteam/PHASE4_REPORT.md` against the current source. It does
not modify the enforcement implementation, does not modify any DeepSeek
artifact, and does not commit, merge, or push anything.

---

## 1. Method and classification vocabulary

For each finding I:

1. read the declared invariant in source/docstrings and the exact enforcement
   path;
2. reviewed the probe for artificial monkey-patching, unsupported inputs, or
   assumptions that bypass intended integration requirements;
3. re-ran the probe in isolation with an inert executor that records dispatch;
4. re-derived the critical result with a separate harness that imports only
   `morrison_governance` (never the DeepSeek probe modules);
5. tested whether the effect is unconditional or depends on configuration,
   deployment path, or downstream tool semantics.

| Classification | Meaning in this report |
|---|---|
| **REPRODUCED** | Observed effect matches the claim, and a declared enforcement property is genuinely violated under a normal kernel configuration. |
| **CONFIGURATION-DEPENDENT** | The code behaviour is real, but the prohibited effect requires a specific deployment choice, optional key, or trusted-object write access. |
| **INVALID** | The probe relies on an incorrect assumption, artificial bypass, unsupported input, or the claimed property is not actually declared. |
| **INCONCLUSIVE** | The available evidence does not establish either way. |

**Priority** is my own assessment, not DeepSeek's:

- **P0** — direct, agent-reachable bypass of a DENY or egress/tenant boundary.
- **P1** — direct policy/authorization failure with material impact.
- **P2** — audit integrity or deployment-scoped boundary defect.
- **P3** — conditional/defense-in-depth issue requiring trusted-object access.

**"Executed" convention.** As in the repository's adversarial tests and the
DeepSeek report, `executed=True` means the kernel returned `PERMIT` and invoked
the executor. The probe executors are inert recorders, so the *real-world*
effect of a permitted call depends on what the downstream tool does with the
arguments. This is called out explicitly where it matters (F-1, F-8).

---

## 2. Verdict matrix

| ID | DeepSeek claim | Independent classification | Genuine property violation? | Priority |
|---|---|---|---|---|
| F-1 | Quarantined payload blinds capability classification; DENY capability executes | **REPRODUCED** | Yes — `log.tamper` DENY policy and "caller cannot widen authority" are defeated; classification/execution diverge | **P0** |
| F-2 | Unparseable destination is classified internal, disabling egress/taint | **REPRODUCED** | Yes — contradicts documented deny-by-default in `destinations.py` | **P0** |
| F-3 | Destination resolution and egress-capability inference disagree | **REPRODUCED** | Yes — external URL in a value under a non-egress key evades every egress rule | **P0** |
| F-4 | `payment_auto_approve_max = 0` auto-approves zero/negative payments | **REPRODUCED** | Yes — contradicts "0 disables auto-approval entirely"; zero/negative auto-approved | **P1** |
| F-5 | Nested tenant identifiers escape `_cross_tenant` | **REPRODUCED** | Yes — nested `tenant`/`tenant_id`/`account_id` reach another tenant | **P1** |
| F-6 | Decision evidence record does not reflect the executed action | **REPRODUCED** | Yes — `record.proposed != executed action` and `hash(record.proposed) != record.action_hash`, while integrity verifies | **P2** |
| F-7 | Keyless evidence chain is not tamper-evident | **CONFIGURATION-DEPENDENT** | Yes under keyless default; requires write access to the trusted chain (not reachable from a call dict) | **P3** |
| F-8 | `GovernanceInterceptor` executes what the kernel blocks | **CONFIGURATION-DEPENDENT** | Yes for consumers of the exported interceptor; the kernel itself is not bypassed | **P2** |

No finding was classified **INVALID** or **INCONCLUSIVE**. Two claims inside the
probe documentation are inaccurate and are corrected below: F-8's
`authorized:true` scenario does **not** reproduce, and F-6's title overstates a
hash-binding failure (the hash does bind the executed action; the record's
human-readable field is inconsistent).

---

## 3. Reproduction matrix

All commands are run from the repository root:

```bash
cd /Users/davarnmorrison/AI-RedTeam/Morrison-Runtime-Governance
```

| ID | Exact command | Declared expectation | Observed (independent run) | Executor invoked? |
|---|---|---|---|---|
| F-1 | `/opt/homebrew/bin/python3.12 redteam/deepseek_redteam/probe_deny.py` | `{"audit_logging": false}` → BLOCK; same under `policy` → BLOCK | Control BLOCK `capability_policy/log.tamper`; `{"policy": {...}}` **PERMIT/V4**, `reached=[apply_config …]` | **Yes** for attack |
| F-1 | `/opt/homebrew/bin/python3.12 redteam/deepseek_redteam/probe_quarantine.py` | MFA/IAM disable → ESCALATE; under `policy` → ESCALATE | Plain ESCALATE; wrapped **PERMIT/V4** and executed | **Yes** for wrapped |
| F-1 | `/opt/homebrew/bin/python3.12 redteam/deepseek_redteam/probe_exfil.py` | SSN + URL → BLOCK; under `policy` → BLOCK | Plain BLOCK `sensitive_egress`; wrapped **PERMIT/V4** and executed | **Yes** for wrapped |
| F-2 | `/opt/homebrew/bin/python3.12 redteam/deepseek_redteam/probe_destination.py` | `ftp://`, `target_host`, short host → external → BLOCK | All three resolve `external=False`, `"no destination present in call"`; egress **PERMIT/V4**, executed | **Yes** |
| F-3 | `/opt/homebrew/bin/python3.12 redteam/deepseek_redteam/probe_egress_caps.py` | URL under `note`/`comment` → BLOCK | `dest.external=True`, `caps=[]`, **PERMIT/V4**, executed | **Yes** |
| F-4 | `/opt/homebrew/bin/python3.12 redteam/deepseek_redteam/probe_payment.py` | 0 / negative → ESCALATE (auto-approval disabled) | `0`, `-1`, `-4_500_000` → **PERMIT/V4**, executed; `4_500_000` → ESCALATE; `"-inf"` → BLOCK | **Yes** for 0/negative |
| F-5 | `/opt/homebrew/bin/python3.12 redteam/deepseek_redteam/probe_tenant.py` | nested tenant → BLOCK | Top-level BLOCK `tenancy`; nested `tenant`, `tenant_id`, `account_id` → **PERMIT/V4**, executed | **Yes** |
| F-6 | `/opt/homebrew/bin/python3.12 redteam/deepseek_redteam/probe_evidence.py` | decision record binds executed action | `record.proposed={"args":{}}`; `hash(record.proposed)!=record.action_hash`; `integrity().evidence_verified=True` | Yes (PERMIT) |
| F-7 | `/opt/homebrew/bin/python3.12 redteam/deepseek_redteam/probe_evidence_tamper.py` | silent rewrite breaks chain | Keyless: verified before **and after** rewrite; keyed: `signature invalid` | N/A |
| F-8 | `/opt/homebrew/bin/python3.12 redteam/deepseek_redteam/probe_bypass.py` | interceptor permits what kernel blocks | `run_shell …` → kernel BLOCK `capability_policy`; interceptor **PERMIT/V4**, executed. `authorized:true` transfer → interceptor also BLOCKs | **Yes** for `run_shell` |

Negative controls (`probe_rejected.py`, `probe_concurrency.py`) all held; see §6.

---

## 4. Per-finding analysis

### F-1 — Quarantined payload blinds capability classification

**Declared invariant.** `kernel/policy.py` declares `log.tamper` as `DENY`
("never executable by an autonomous agent (no approval unlocks it)").
`trust.py` states that caller-written fields cannot widen what the caller may
do.

**Source path.**
- `gate.py:952-953` — `proposed = canonicalize(call)`; `clean, quarantined =
  quarantine_authority(call)`.
- `gate.py:967` — `caps = C.classify(clean, self.ctx.tool_manifest)`.
- `gate.py:969-974` — destination resolution uses `clean` + `quarantined`.
- `gate.py:1421` — `Decision(action=proposed, …)`.
- `gate.py:1222-1244` — every egress rule is additionally gated on
  `CAP_EXTERNAL_DATA_MOVE in caps`.
- `execute()` hashes `decision.action` (the full `proposed`) and passes a deep
  copy of it to the executor (`gate.py:1580-1630`).

**Probe review.** No monkey-patching. `apply_config` is a declared tool with no
argument schema, so `{"policy": {...}}` is a supported input shape. The control
uses the same payload in an ordinary key. The only assumption is that the
downstream tool treats `policy` as operative — which is exactly the class of
tool the kernel is supposed to guard. This is not an artificial bypass.

**Independent re-derivation.**

```
control DENY in ordinary arg
  clean = {'tool':'apply_config','args':{'audit_logging': False}}
  caps(clean)    = ['log.tamper', 'security_control.modify']
  verdict=BLOCK layer=capability_policy rule=log.tamper executed=False

attack DENY under `policy`
  clean     = {'tool':'apply_config','args':{}}
  quarant   = {'policy': {'audit_logging': False}}
  caps(clean)    = []
  caps(proposed) = ['log.tamper', 'security_control.modify']
  verdict=PERMIT layer=V4 executed=True
  executor saw = [{'tool':'apply_config','args':{'policy':{'audit_logging':False}}}]
```

**Property test.** Genuine violation. The kernel classifies the *residue* and
executes the *proposal*. The `log.tamper` DENY never sees the payload, while
the executor does. The same mechanism defeats `security_control.modify`,
`iam.privileged`, `data.destructive`, and the sensitive-egress rule for
payloads nested under a quarantined name. The code comment at `gate.py:965`
("Their content is still classified below") is true for sensitivity
(`gate.py:1222` uses `proposed`) but false for capability and egress policy.

**Integration/unsupported-input check.** The exploit does not require control of
`SecurityContext`, `Decision`, the kernel, or the executor. It is an
agent-controlled `call` dict. Exploitability is downstream-tool-dependent: the
inert executor merely records the call, so the real-world effect requires a
tool that reads the quarantined field. The kernel-level
classification/execution divergence is unconditional.

**Classification: REPRODUCED. Priority: P0.**

---

### F-2 — Unparseable destination is classified internal

**Declared invariant.** `kernel/destinations.py` docstring (line 154):
"Deny-by-default: an unrecognised or unresolvable destination is EXTERNAL."
The module header says "anything not provably internal is external."

**Source path.**
- `destinations.py:25` — `_URL_RE = re.compile(r"https?://…")` (no `ftp://`,
  `s3://`, etc.).
- `destinations.py:32` — `_DEST_KEYS` omits `target_host`, `bucket`, `address`.
- `destinations.py:230` — fallback returns
  `DestinationVerdict(False, "no destination present in call", ())`.
- `gate.py:1133-1134` — injects `destination_external=dest.external` and
  `destination_internal=not dest.external` into the trusted namespace.

**Probe review.** No artificial bypass. The `ftp://` case uses the recognized
`endpoint` key but the scheme is not parsed. `target_host` is a plain,
plausible destination key the resolver does not know. The `url: attacker`
single-label case is the weakest sub-case; a single-label host can be a valid
internal or external name, but the declared deny-by-default rule still makes
the fallback wrong. The finding does not depend on the weak sub-case.

**Independent re-derivation (direct resolver).**

```
https baseline             external=True  reason='destination resolved as EXTERNAL: attacker.example'
ftp scheme                 external=False reason='no destination present in call'
unknown key target_host    external=False reason='no destination present in call'
short bare host            external=False reason='no destination present in call'
bare domain under url      external=True  reason='destination resolved as EXTERNAL: attacker.example'
```

Kernel-level: after a permitted `read_file`, the ftp / `target_host` /
short-host egresses all return `PERMIT/V4` and invoke the executor, because the
injected `destination_internal=True` disables the V2 taint check and every
`dest.external`-gated rule.

**Property test.** Genuine violation: a destination that is present but
unparseable is treated as *absent* and therefore internal. This is the exact
inverse of the declared deny-by-default property. It is independent of F-1: the
call contains no quarantined field.

**Integration/unsupported-input check.** `ftp://` is a real URI scheme; an
`upload` tool taking an `endpoint` is a normal integration. `target_host` is a
normal spelling. No trusted-object control is required.

**Classification: REPRODUCED. Priority: P0.**

---

### F-3 — Destination resolution and egress-capability inference disagree

**Declared invariant.** External egress carrying sensitive data, or following a
governed read, must be blocked without a verified approval (`gate.py:1222-1244`).

**Source path.**
- `destinations.py:147-230` — scans every string **value** for URLs/emails.
- `capabilities.py:302-309` — infers `data.external_move` only from the **tool
  name** or an **argument key** (`url`, `endpoint`, `host`, `to`, …).
- `gate.py:1222-1223`, `1234`, `1244` — rules require both
  `dest.external` and `CAP_EXTERNAL_DATA_MOVE in caps`.

**Probe review.** No quarantine is involved; the argument key `note` is
ordinary. The call is a plausible data-bearing tool (`body` + `note`). The probe
does not patch the resolver or the classifier.

**Independent re-derivation.**

```
URL under `url`
  dest.external=True  caps=['data.external_move']  CAP present=True
  verdict=BLOCK layer=sensitive_egress

URL inside `note`
  dest.external=True  caps=[]  CAP present=False
  verdict=PERMIT layer=V4 executed=True
```

**Property test.** Genuine violation. The resolver says the data is leaving;
the capability classifier says it is not an egress. The conjunction at
`gate.py:1222` then skips the sensitive-egress and read-then-egress rules.
The read-then-egress variant (`comment` key) also executes.

**Integration/unsupported-input check.** The tool is `apply_config` with a
declared (empty) capability list. The argument `note` is ordinary, not
authority-shaped. The destination is a real `https://` URL, so this is not an
unparseable-destination case. It is independent of F-1.

**Classification: REPRODUCED. Priority: P0.**

---

### F-4 — Zero/negative payments auto-approve

**Declared invariant.** `kernel/policy.py:58`: "Payments at or below this value
… do not require a per-action approval. **0 disables auto-approval entirely.**"

**Source path.**
- `policy.py:59` — default `payment_auto_approve_max: 0`.
- `gate.py:1033-1039` — `cap_max = pol_values.get(…) or 0`; `amount =
  _numeric(...)`; `if amount is not None and amount <= cap_max and not
  dest.external: requirement, auto_approved = P.ALLOW, True`.
- `gate.py:1107-1130` — `auto_approved` establishes authority and injects
  `authorized=True`/`approved=True` into the trusted namespace, satisfying the
  `unauthorized_transfer` Ω rule.

**Probe review.** No artificial bypass. `0`, `-1`, `-4_500_000` are ordinary
JSON numbers. The `"-inf"` case fails closed, which is correct. The probe's
`to` value has no `@`, so `dest.external=False` and the auto-approval condition
is reachable.

**Independent re-derivation (shipped default `policy_values={}`).**

```
amount= 4_500_000  verdict=ESCALATE layer=capability_policy req=approval
amount=         0  verdict=PERMIT   layer=V4               req=allow    executed=True
amount=        -1  verdict=PERMIT   layer=V4               req=allow    executed=True
amount=  -4_500_000 verdict=PERMIT  layer=V4               req=allow    executed=True
```

With `payment_auto_approve_max=1000`, `amount=1000` auto-approves (intended),
but `0`, `-1`, `-4_500_000` still auto-approve. The non-positive bug is
independent of the configured cap.

**Property test.** Genuine violation of the documented "0 disables
auto-approval entirely" semantics. `amount <= cap_max` has no positive-amount
guard. `amount=0` is decisive: the default is supposed to disable
auto-approval, yet it permits and executes without an approval.

**Integration/unsupported-input check.** The `transfer` tool is declared with
`CAP_PAYMENT`; the call is ordinary. A negative amount is semantically odd for
a transfer, but the kernel is the component that should reject it; the tool
should not have to defend against a governance auto-approval. No trusted-object
control is required.

**Classification: REPRODUCED. Priority: P1.**

---

### F-5 — Nested tenant identifiers escape `_cross_tenant`

**Declared invariant.** `_cross_tenant` docstring: "Compare any tenant-scoped
identifier in the action against the principal's own tenant." A principal in
`acme` must not access `globex` resources.

**Source path.**
- `gate.py:1939-1989` — `_cross_tenant`.
- `gate.py:1973` — only keys whose *whole* lowercased name is in `_TENANT_KEYS`
  are compared.
- `trust.py:175-199` — nested identity fields are re-keyed as
  `"/request/tenant"`.
- `gate.py:1979-1988` — regex fallback matches only `tenant_x`/`customer_x`/
  `org_x`-shaped **values**.

**Probe review.** The nested `request` object is a normal API shape for
`read_file`/`query_db`. `account_id` is in `_TENANT_KEYS`, so the kernel itself
declares it tenant-scoped. No monkey-patching.

**Independent re-derivation (direct `_cross_tenant`).**

```
{'tenant':'globex','path':'/x'}
  quarantine = {'tenant': 'globex'}
  _cross_tenant(...) = cross-tenant access: tenant='globex' ...

{'request':{'tenant':'globex','path':'/x'}}
  quarantine = {'/request/tenant': 'globex'}
  _cross_tenant(...) = None

{'request':{'account_id':'acct-globex-77','sql':'SELECT 1'}}
  quarantine = {}
  _cross_tenant(...) = None

{'request':{'tenant':'tenant_b','path':'/x'}}
  quarantine = {'/request/tenant': 'tenant_b'}
  _cross_tenant(...) = resource reference 'tenant_b' is outside ...
```

Kernel-level (CYBERSECURITY-only, matching the probe): nested `tenant`,
`tenant_id`, and `account_id` all return `PERMIT/V4` and execute; the
`tenant_b` value is caught by the regex fallback.

**Configuration note.** Under a multi-domain layer
(CYBERSECURITY+ENTERPRISE+FINANCE), my independent run sometimes blocked the
nested calls at `A_safe/unauthorized_transfer`. That is an *unrelated*
false-positive rule, not tenancy enforcement: the direct `_cross_tenant` call
still returns `None` for the nested identifiers. The F-5 defect is therefore
not "caught by a different configuration"; it is masked by an unrelated block.
The probe's single-domain posture is the cleaner demonstration.

**Property test.** Genuine violation. Nested identity fields are re-keyed into
JSON-pointer paths, and the comparison only accepts exact top-level names. The
fallback regex catches only tenant-shaped *values*, so opaque IDs such as
`globex` or `acct-globex-77` pass.

**Integration/unsupported-input check.** Nested request objects and opaque
tenant IDs are normal. No trusted-object control is required.

**Classification: REPRODUCED. Priority: P1.**

---

### F-6 — Decision evidence does not reflect the executed action

**Declared invariant.** `kernel/evidence.py` documents that every decision is a
hash-chained record "binding the canonical action, the ruleset version, the
actor, the decision, the authorisation provenance and the execution result."
`EvidenceRecord.proposed` is documented as "the action as proposed
(post-canonical)".

**Source path.**
- `gate.py:1441` — `proposed=clean` in the sealed decision record, while
  `action_hash=ahash` is the hash of the full `proposed`.
- `gate.py:1664-1673` / `evidence.py:266-279` — the execution-outcome record
  copies `rec.proposed` (i.e. `clean`).

**Probe review.** No monkey-patching. The probe uses the public
`authorize`/`execute` API and reads the sealed records.

**Independent re-derivation.**

```
verdict=PERMIT executed=True
executor saw       = [{'tool':'apply_config','args':{'policy':{'audit_logging':False,'note':'ran'}}}]
record.proposed    = {'tool':'apply_config','args':{}}
hash(rec.proposed) == rec.action_hash ? False
rec.proposed == executed action ? False
integrity()        = {'evidence_verified': True, 'problems': [], 'records': 3, ...}
```

**Property test.** Genuine, but the report's title slightly overstates it. The
cryptographic `action_hash` **does** bind the executed action: both
`action_hash` and the executor target derive from the full `proposed`. The
defect is representational: the record's human-readable `proposed` field is
`clean`, so `hash(record.proposed) != record.action_hash` and an auditor reading
the decision record sees an action that did not execute. The intent record does
carry the full action, so the payload is recoverable elsewhere in the chain; the
decision and execution records are the inconsistent ones.

**Integration/unsupported-input check.** No trusted-object control is required;
the agent's quarantined payload is enough. The defect is an audit/forensics
integrity issue rather than an authorization bypass.

**Classification: REPRODUCED. Priority: P2.**

---

### F-7 — Keyless evidence chain is not tamper-evident

**Declared invariant.** `kernel/evidence.py`: "Any silent edit — including
flipping a BLOCK into an executed PERMIT — breaks either the record hash or the
chain link, and `verify()` reports exactly which record failed."

**Source path.**
- `evidence.py:246` — `key: bytes = b""`.
- `evidence.py:212-235` — `seal`/`verify` HMAC only when a key is present.
- `gate.py:352,362` — `GovernanceKernel(evidence_key=b"")` by default.

**Probe review.** The probe directly mutates `chain.records` and recomputes the
unkeyed SHA-256 hashes. That is a faithful model of an in-process attacker or a
persisted-JSONL rewrite, but it requires write access to the evidence chain.
The report itself notes this ("requires write access to the chain, not
reachable from a call dict alone").

**Independent re-run.**

```
--- keyless (library default)
    before rewrite: verified=True problems=[]
    after  rewrite: verified=True problems=[]
    record 0 now   : decision=PERMIT executed=True
--- HMAC-keyed
    before rewrite: verified=True problems=[]
    after  rewrite: verified=False problems=['record 0 signature invalid', ...]
```

**Property test.** Genuine under the keyless default: the hash chain is
self-consistency, not authenticity, and a full rewrite passes `verify()`. With
a non-empty key, the rewrite is detected. The declared invariant is stated
unconditionally and is false in the shipped default.

**Integration/scope check.** Under the report's own threat model
("`SecurityContext`, `Decision`, the kernel instance, the continuity store and
the evidence chain are server-side and trusted"), an attacker who can rewrite
the chain is outside the agent-only threat model. This is a defense-in-depth /
audit-authenticity issue, not an agent-reachable bypass. It also does not help
against an in-process attacker who can read the HMAC key from the kernel; it
helps against offline/persisted tampering.

**Classification: CONFIGURATION-DEPENDENT (keyless default + chain write
access). Priority: P3.**

---

### F-8 — `GovernanceInterceptor` executes outside the kernel

**Declared invariant.** `kernel/gate.py:1`: "GovernanceKernel — the single
production chokepoint." `integrations.py:38-40`: "there is no longer an
execution path through this module that does not pass through the kernel."

**Source path.**
- `interception.py:181-193` — `check_prefix` calls
  `self.governance.evaluate_plan(...)` / `self.governance.evaluate(...)`, i.e.
  `GovernanceLayer`, never `GovernanceKernel`.
- `__init__.py:101,193` — `GovernanceInterceptor` is exported at package root.
- `test_interception.py` — tested as a fail-closed chain guard.
- `LIMITATIONS.md:162-163` — "Fail-closed interception … closed"; "Cross-model
  live seam … closed".

**Probe review.** The probe uses `check_prefix` and manually executes the call
when allowed; `GovernanceInterceptor.run` does the same. No artificial bypass.
However, the probe's docstring claims a caller-supplied `authorized: true` is
honoured by the interceptor; **that specific claim is not reproduced**:

```
authorized:true transfer ($4.5M or $100)
  kernel      : BLOCK trust_boundary
  interceptor : allowed=False BLOCK A_safe
```

The reproduced divergence is the renamed destructive command:

```
run_shell {"command": "rm -rf /var/lib/morrison/audit"}
  kernel      : BLOCK capability_policy executed=False
  interceptor : allowed=True verdict=PERMIT layer=V4 executed=True
```

The report's F-8 section uses the `run_shell` case, so the finding stands; the
probe's header text about forged authority is inaccurate.

**Property test.** Genuine as a statement about the package's public surface:
the interceptor is an exported, tested, documented drop-in execution path that
does not apply the kernel's semantic capability policy or trust boundary. It is
**not** a bypass of `GovernanceKernel`; the kernel itself refuses the call. If a
deployment uses `GovernanceGuard`/`GovernanceKernel` exclusively, F-8 does not
apply. If it uses `GovernanceInterceptor` (or the layer directly), the
"single production chokepoint" claim is false.

The repository already documents this class of gap in
`GOVERNED_EXECUTION_VETO_EVALUATION.md` (VETO-08/VETO-08b). `integrations.py`
has since been rewritten to require a `SecurityContext` and route through the
kernel; `interception.py` remains layer-based. F-8 is therefore a residual
public path of the same class, not a new kernel break.

**Integration/scope check.** The interceptor's own contract is layer-level
("evaluated by the governance layer"), so one can argue it never promised kernel
parity. But it is exported at the package root, called a "drop-in middleware",
and listed as a closed control; a deployer can reasonably treat it as a
production gate. The scope question is real, which is why this is classified as
deployment-dependent rather than a kernel bypass.

**Classification: CONFIGURATION-DEPENDENT (only when the interceptor/layer is
the execution path; kernel-only deployments unaffected). Priority: P2.**

---

## 5. F-1 and F-8 — the enforcement-boundary question

### F-1: classified vs authorized vs executed

The kernel maintains three representations (`gate.py:940-950`):

- `proposed` — the full canonical action; **hashed** and **executed**.
- `clean` — `proposed` minus authority-named fields; **classified** and sent
  to the Ω engine.
- `view` — described in the comment as what classifiers should see, but not
  actually constructed as a separate object.

The invariant "the authorised action is the proposed action" holds: `action_hash`
and the executor both use `proposed`. The failure is that the *classification*
uses `clean`, so the object that is authorized/executed is not the object that
was classified. This is the single most important finding: it turns every
quarantined field name into a classification blind spot, and it composes with
the egress-capability conjunction (F-3) to defeat exfiltration controls.

The correct fix direction (not applied here) is the report's `view` proposal:
classify a representation that preserves the payload's semantics but neutralises
its authority, and keep `clean` only for the Ω control namespace. Decoupling
egress rules from `CAP_EXTERNAL_DATA_MOVE in caps` is a second, independent
fix.

### F-8: a second public gate, not a kernel bypass

`GovernanceKernel` is not bypassed by F-8. The kernel refuses the `run_shell`
call; the interceptor, which calls `GovernanceLayer.evaluate`, permits it. The
"single production chokepoint" claim is a claim about the package's execution
surface, and the exported interceptor falsifies it for deployments that use it.
The prior audit's VETO-08 class is the same issue; `integrations.py` was fixed,
but `interception.py` was not. The practical remediation is to make the
interceptor require a `SecurityContext` and delegate to the kernel, or to
deprecate/rename it as analysis-only and make every execution-capable entry
point refuse.

---

## 6. Negative controls (independent re-run)

`probe_rejected.py` and `probe_concurrency.py` were re-run unmodified. All held:

| Attack | Observed |
|---|---|
| Cross-session read → egress | BLOCK `V2`, no execution |
| Approval replay across sessions | Second use ESCALATE; first use only execution |
| Action mutation after authorize | `refused: action mutated after authorisation` |
| Execute a preview (unreserved) decision | `refused: no live reservation` |
| Execute an expired decision | `refused: decision expired` |
| Forged `authorized`/`approved` through kernel | BLOCK `trust_boundary`; forgery named |
| Declared `log.tamper` plainly | BLOCK `capability_policy` |
| One approval, two threads / two processes | Exactly one execution |
| Read in process A, egress in process B (shared store) | BLOCK `V2` |
| Keyed evidence rewrite | Detected (`signature invalid`) |

These controls matter: they show the kernel's binding, lease, replay, and
forgery defenses are intact, and they isolate F-1..F-8 to specific
classification/representation/policy defects rather than a general failure of
the kernel.

---

## 7. Independent severity and remediation priorities

I do not adopt DeepSeek's severity ordering. My ordering is based on
agent-reachability, whether the kernel is the execution path, and whether the
effect is a direct prohibited action or an audit/defense-in-depth weakness.

| Priority | Findings | Rationale |
|---|---|---|
| **P0** | F-1, F-2, F-3 | Direct, agent-reachable kernel bypasses of DENY and egress boundaries. F-1 is the root cause that makes quarantined payloads invisible to capability policy; F-2 and F-3 independently defeat egress enforcement. Fix before any other item. |
| **P1** | F-4, F-5 | Direct kernel policy failures: unauthorized payment execution and cross-tenant access. Material impact, but narrower trigger conditions than P0. |
| **P2** | F-6, F-8 | F-6 is an audit/forensics integrity defect (the cryptographic hash still binds the executed action). F-8 is a second public mediation path; it does not bypass the kernel, but it falsifies the single-chokepoint claim for deployments that use it. |
| **P3** | F-7 | Requires write access to the trusted evidence chain and a keyless configuration; not reachable from the call dict. Fix by requiring a key in enforcing deployments and documenting keyless mode as corruption detection only. |

### Recommended remediation order

1. **F-1 / F-3 (P0):** Define and use a single classification representation
   (`view`) that preserves payload semantics while neutralising authority; run
   capability, destination, and sensitivity classification over it. Decouple
   the sensitive-egress and read-then-egress rules from
   `CAP_EXTERNAL_DATA_MOVE in caps`; if `dest.external` is true, apply them.
2. **F-2 (P0):** Make the no-destination fallback fail closed when a
   destination is present but unparseable. Match any URI scheme, scan values
   for host-shaped tokens, and add an explicit `unknown` state treated as
   external.
3. **F-4 (P1):** Treat a non-positive `payment_auto_approve_max` as disabled:
   `if cap_max > 0 and 0 < amount <= cap_max`. Reject non-finite and
   non-positive amounts independently of the cap.
4. **F-5 (P1):** When scanning `quarantined`, use the final path segment of
   each JSON-pointer key as the field name, and recurse into nested actions for
   tenant-scoped keys at any depth.
5. **F-6 (P2):** Store both the full `proposed` and the evaluated `clean` in the
   evidence record, make `action_hash` cover the stored full action, and add an
   integrity check `record.action_hash == action_hash(record.proposed)`.
6. **F-8 (P2):** Make `GovernanceInterceptor` require a `SecurityContext` and
   delegate to `GovernanceKernel`, or deprecate/rename it as analysis-only and
   make execution-capable entry points refuse.
7. **F-7 (P3):** Require a non-empty evidence key for enforcing deployments
   (fail closed at construction), verify signatures whenever a key is
   configured, and document keyless mode as corruption detection only.
8. **Regression pins:** Add tests for each of the above, including the
   control/attack pairs and the keyed/keyless evidence cases.

---

## 8. Artifact integrity and constraints

- Working tree before and after verification: branch `deepseek-redteam`, HEAD
  `06b9b559509900f0950840b7a257c4a3c299ec56`.
- `git status --short` reports only `?? redteam/deepseek_redteam/` (the
  DeepSeek artifact directory). No tracked file was modified.
- No enforcement file was edited. No commit, merge, or push was performed.
- All original DeepSeek probes and `PHASE4_REPORT.md` were left unchanged.
- The independent harness used for re-derivation lives outside the repository
  (in the session temp directory) and does not import the DeepSeek probe
  modules.
- This report is a new file under `redteam/deepseek_redteam/`.

---

## 9. Bottom line

All eight findings describe real behaviour in the current implementation. Six
(F-1..F-6) are unconditional kernel-level defects; two are conditional:

- **F-7** is real only under the keyless evidence default and requires write
  access to the trusted chain.
- **F-8** is real only for deployments that route execution through the
  exported `GovernanceInterceptor`/`GovernanceLayer`; it is not a bypass of
  `GovernanceKernel`.

The highest-value fixes are F-1's classification representation and F-3's
egress-capability conjunction, followed by F-2's fail-open destination
fallback. Those three are the direct agent-reachable paths from a call dict to
a prohibited effect. F-4 and F-5 are narrower but material. F-6 is an audit
integrity issue; F-7 and F-8 are deployment-scoped hardening items.

---

## 10. Remediation status (post-verification addendum)

This section was added after the verification above. The verification matrix
describes the **pre-fix** tree; the original DeepSeek artifacts
(`PHASE4_REPORT.md` and all probes) remain unchanged.

| ID | Fix | Regression pin |
|---|---|---|
| F-1 | `trust.classification_view()` preserves every value/nesting level and renames only authority-shaped **keys**. Capability and destination classification consume it instead of the quarantined residue. | `test_phase4_remediation.py::test_f1_*` |
| F-2 | `destinations._URL_RE` matches any URI scheme; destination key set expanded; a destination-shaped value that cannot be parsed now resolves **external** (deny-by-default). Bucket/storage names resolve as destinations but are not treated as transfers by themselves. | `test_phase4_remediation.py::test_f2_*` |
| F-3 | When the resolver says `dest.external` and the evidence is a transfer (URL/email/send-key), `data.external_move` is added to the capability set, so egress rules cannot disagree with the resolver. | `test_phase4_remediation.py::test_f3_*` |
| F-4 | Auto-approval requires `cap_max > 0` and a finite amount with `0 < amount <= cap_max`. | `test_phase4_remediation.py::test_f4_*` |
| F-5 | `_cross_tenant` walks nested args at any depth, recovers the leaf name of quarantined JSON-pointer keys, and fails closed when traversal is incomplete. | `test_phase4_remediation.py::test_f5_*` |
| F-6 | The decision record stores the full `proposed` plus a separate `evaluated`; execution records copy both; `EvidenceChain.verify()` checks `action_hash == action_hash(proposed)` for records written under the new schema. | `test_phase4_remediation.py::test_f6_*` |
| F-7 | `GovernanceKernel(require_evidence_key=True)` refuses construction without a key; `integrity()` reports `authenticated`; keyless mode is documented as corruption detection, not authenticity. | `test_phase4_remediation.py::test_f7_*` |
| F-8 | `GovernanceInterceptor` is kernel-backed when given `security_context=`/`kernel=`; layer-only mode refuses execution unless the caller explicitly opts into `allow_advisory=True`, and the transcript labels the mode. | `test_interception.py::test_*kernel*`, `test_layer_only_*` |

All 12 original probes now exit without executing the prohibited actions, and
the full suite passes in an environment with the optional AgentDojo
dependencies installed.
