# Round-2 Independent Adversarial Falsification Campaign

**Target:** Morrison Runtime Governance (`morrison_governance` 0.4.1), repaired
Phase-4 kernel
**Repository:** `/Users/davarnmorrison/AI-RedTeam/Morrison-Runtime-Governance`
**Branch / HEAD:** `deepseek-redteam` / `06b9b55`
**Interpreter:** `/opt/homebrew/bin/python3.12`
**Date:** 2026-11-06

This is the second independent campaign. It does not repeat F-1 … F-8. It
attacks the repaired implementation with previously untested strategies and
compositions. All executors are inert recorders. No enforcement source was
modified. No commit, merge, or push was performed.

---

## 1. Verdict matrix

| ID | Candidate | Severity | Classification | Falsified? |
|---|---|---|---|---|
| R2-A | IPv4-mapped IPv6 metadata endpoint | P0 | REPRODUCED | **Yes** |
| R2-B | Unlisted destination-key coverage gap | P0/P1 | REPRODUCED | **Yes** |
| R2-C | Authority-shaped bare-host destination | P0/P1 | REPRODUCED | **Yes** |
| R2-D | Payment amount-alias disagreement | P1 | REPRODUCED | **Yes** |
| R2-E | Cross-tenant container values | P1 | REPRODUCED | **Yes** |
| R2-F | Tenant aliases / encoded qualified refs | P2 | REPRODUCED (refs) / SOURCE-SUPPORTED (aliases) | **Yes (refs)** |
| R2-G | Caller clock vs revocation | P1 | REPRODUCED (API-level) | **Yes** |
| R2-H | Caller clock vs approval expiry | P1/P2 | REPRODUCED (API-level) | **Yes** |
| R2-I | `record_remote_execution` action binding | P2 | REPRODUCED | **Yes** |
| R2-J | Malformed URL exceptions out of `authorize` | P2/P3 | REPRODUCED | **Yes** |
| R2-K | `SandboxExecutor` subclass confinement | P2 | REPRODUCED | **Yes** |
| R2-L | Concurrency compositions | — | HELD | No |
| R2-M | Evidence authenticity / replay | — | HELD (documented limits) | No |
| R2-N | Alternative execution paths | — | HELD (documented/trusted paths) | No |

Reproduction commands:

```sh
cd redteam/deepseek_redteam_round2
/opt/homebrew/bin/python3.12 probe_r2a_ipv4_mapped_metadata.py
/opt/homebrew/bin/python3.12 probe_r2b_destination_keys.py
/opt/homebrew/bin/python3.12 probe_r2c_authority_shaped_host.py
/opt/homebrew/bin/python3.12 probe_r2d_payment_alias.py
/opt/homebrew/bin/python3.12 probe_r2e_tenant_nested_container.py
/opt/homebrew/bin/python3.12 probe_r2f_tenant_spellings.py
/opt/homebrew/bin/python3.12 probe_r2g_clock_revocation.py
/opt/homebrew/bin/python3.12 probe_r2h_clock_approval_expiry.py
/opt/homebrew/bin/python3.12 probe_r2i_record_remote_binding.py
/opt/homebrew/bin/python3.12 probe_r2j_malformed_url.py
/opt/homebrew/bin/python3.12 probe_r2k_sandbox_subclass.py
/opt/homebrew/bin/python3.12 probe_concurrency.py
/opt/homebrew/bin/python3.12 probe_evidence_authenticity.py
/opt/homebrew/bin/python3.12 probe_alternate_paths.py
```

---

## 2. Findings

### R2-A — IPv4-mapped IPv6 metadata endpoint bypasses the hard BLOCK

**Severity:** P0
**Classification:** REPRODUCED
**Declared invariant:** `kernel/destinations.py`, `_host_is_internal` docstring:
*"Metadata endpoints are never internal under any configuration."* The
`dest.forbidden` branch is a hard BLOCK (`gate.py`, step 8).

**Source:**
- `morrison_governance/kernel/destinations.py`:`_FORBIDDEN_HOSTS` (76-82),
  `_FORBIDDEN_NETS = ("169.254.0.0/16", "fe80::/10")` (83), `_forbidden()`
  (99-108), `_host_is_internal()` (111-152).
- `morrison_governance/kernel/gate.py`: `dest.forbidden -> BLOCK`
  (`forbidden_destination`, 1122-1127).

**Reproduction:** `probe_r2a_ipv4_mapped_metadata.py`

The IPv4-mapped form `http://[::ffff:169.254.169.254]/…` normalises to the
host string `::ffff:169.254.169.254`. `ipaddress` reports it
`is_private=True` and `is_link_local=True`, but `_forbidden()` compares the
literal string against the IPv4 `169.254.0.0/16` and IPv6 `fe80::/10`
networks, so neither membership matches.

| URL | `trust_private_networks` | external | forbidden | verdict | executed |
|---|---|---|---|---|---|
| `http://169.254.169.254/latest/meta-data/` | True | True | **True** | **BLOCK** | False |
| `http://[::ffff:169.254.169.254]/latest/meta-data/` | False | True | False | PERMIT | **True** |
| `http://[::ffff:169.254.169.254]/latest/meta-data/` | True | **False** | False | PERMIT | **True** |
| `http://[::ffff:a9fe:a9fe]/latest/meta-data/` | True | **False** | False | PERMIT | **True** |
| `http://[::ffff:169.254.169.254]/latest/user-data/` | False | True | False | PERMIT | **True** |

With the default `trust_private_networks=False` the mapped address is
"external", so the hard `forbidden_destination` BLOCK is skipped. With
`trust_private_networks=True` it is classified **internal**, directly
contradicting the "never internal under any configuration" invariant. In both
cases the recorder is invoked.

**Why it matters:** IMDSv1-style endpoints vend live cloud-role credentials to
a plain GET. The mapped form is accepted by ordinary HTTP clients and URL
parsers, so this is a live credential-acquisition path, not a parser curiosity.

**Remediation direction (not implemented):** canonicalise every host to a
single IP representation and unmap IPv4-mapped IPv6 before the forbidden
check; compare `ip in ip_network` for mapped forms and check
`ipv4_mapped` explicitly. Add regression pins for `::ffff:169.254.169.254`,
`::ffff:a9fe:a9fe`, and NAT64/6to4 forms.

---

### R2-B — Destination-key coverage gap resolves a present destination as "none"

**Severity:** P0/P1
**Classification:** REPRODUCED
**Declared invariant:** `kernel/destinations.py` module docstring:
*"Deny-by-default: anything not provably internal is external."* A destination
present in the call must be resolved.

**Source:**
- `morrison_governance/kernel/destinations.py`:`_DEST_KEYS` (36-41) — exact
  key membership.
- `classify_destination()` (166-267): a bare host is treated as a destination
  only when `kl in _DEST_KEYS` (232).
- `morrison_governance/kernel/gate.py`: capability inference from the
  destination verdict (999-1001).

**Reproduction:** `probe_r2b_destination_keys.py`

After a governed `read_file`, an `http_request` carrying the data in a key
not in `_DEST_KEYS` is PERMIT and reaches the recorder:

| key | destination | verdict | executed |
|---|---|---|---|
| `base_url` | `no destination present in call` | PERMIT | **True** |
| `base` | `no destination present in call` | PERMIT | **True** |
| `target` | `no destination present in call` | PERMIT | **True** |
| `redirect_uri` | `no destination present in call` | PERMIT | **True** |
| `server_name` | `no destination present in call` | PERMIT | **True** |
| `upstream` | `no destination present in call` | PERMIT | **True** |
| `url` (control) | `EXTERNAL: attacker.example` | **BLOCK** | False |

Because the destination resolves "none", the call also carries no
`data.external_move` capability, so the V2 data-flow taint and the kernel
egress policy never see an external sink. URL-shaped values are caught
regardless of key; the exploit needs a bare host, which is ordinary for
`base_url`, `target`, `redirect_uri`, etc.

**Remedy direction:** resolve destinations by value shape and by a
normalised key family, not exact key membership; add the omitted spellings
and a key-normalisation step before the bare-host branch.

---

### R2-C — Authority-shaped key renames a bare-host destination out of view

**Severity:** P0/P1
**Classification:** REPRODUCED
**Declared invariant:** `kernel/trust.py`, `classification_view` docstring:
*"Quarantine removes a field's power to AUTHORISE. It must not remove the fact
that the field names a destination … a URL under `external` is still a
destination."*

**Source:**
- `morrison_governance/kernel/trust.py`:`classification_view()` (218-250)
  renames every authority-shaped key to a neutral name.
- `morrison_governance/kernel/destinations.py`:`_DEST_KEYS` + bare-host branch
  (232-248).
- `morrison_governance/kernel/trust.py`:`forged_authority_claims()` (253-268)
  and `gate.py` materiality (1084-1092).

**Reproduction:** `probe_r2c_authority_shaped_host.py`

`{"approved_url": "attacker.example"}` is quarantined, then
`classification_view` renames it to `{"payload": "attacker.example"}`. The
value has no scheme, so the bare-host branch requires the key to be in
`_DEST_KEYS`; `payload` is not. The call resolves "no destination present".

| args | view | destination | judged | executed |
|---|---|---|---|---|
| `approved_url=attacker.example` | `payload=attacker.example` | none | PERMIT | **True** |
| `authorized_url=attacker.example` | `payload=attacker.example` | none | PERMIT | **True** |
| `approval_url=https://attacker.example/drop` | `payload=https://…` | EXTERNAL | **BLOCK** | False |
| `url=https://attacker.example/drop` (control) | unchanged | EXTERNAL | **BLOCK** | False |

`forged_claims` records `approved_url`/`authorized_url`, but the claim is
non-material because the relaxed requirement is not APPROVAL, so it raises no
verdict.

**Remedy direction:** run the bare-host branch against the *original* key or
against the value shape, not the renamed classification key. Keep the rename
for capability morphology only.

---

### R2-D — Payment auto-approval binds the first amount alias, not the executed amount

**Severity:** P1
**Classification:** REPRODUCED
**Declared invariant:** `kernel/policy.py`: thresholds live server-side
because `excessive_amount` was defeated by a caller-supplied threshold.
`kernel/gate.py`: the payment auto-approval compares the server threshold to
the action's amount.

**Source:**
- `morrison_governance/kernel/gate.py`:`_numeric(args, ("amount", "value",
  "total"))` (1921-1928) returns the **first present** alias.
- `gate.py`: auto-approval (1059-1080).

**Reproduction:** `probe_r2d_payment_alias.py`

With `policy_values={"payment_auto_approve_max": 100}`:

| transfer args | verdict | requirement | `authorization.approved` | executed |
|---|---|---|---|---|
| `{amount: 1, value: 4_500_000}` | **PERMIT** | allow | False | **True** |
| `{amount: 4_500_000}` | ESCALATE | approval | False | False |
| `{value: 4_500_000}` | ESCALATE | approval | False | False |
| `{amount: 50}` | PERMIT | allow | False | True |

`_numeric` reads `amount=1`, auto-approves, and the recorder receives the
whole argument dict including `value=4_500_000`. An executor that prefers
`value` moves the full amount. The server did not verify an approval
artifact; it silently relaxed the requirement.

**Remedy direction:** resolve the amount from the executor's declared amount
argument (per-tool schema), or reject an action that carries disagreeing
aliases; never auto-approve when more than one amount alias is present with
different values.

---

### R2-E — Cross-tenant check ignores container values under authority keys

**Severity:** P1
**Classification:** REPRODUCED
**Declared invariant:** `kernel/gate.py`, `_cross_tenant` docstring:
*"The comparison walks the WHOLE payload. It used to inspect only top-level
argument names, so `{"request": {"tenant": "globex"}}` … reached another
tenant."*

**Source:**
- `morrison_governance/kernel/gate.py`:`_tenant_pairs()` (1997-2015) appends
  quarantined values **as-is**.
- `_cross_tenant()` `scalars()` (2037-2040) yields only `str/int/float` and
  skips `dict`/`list`.
- `trust.py`:`quarantine_authority()` removes the whole authority key and
  stores its value under a JSON-pointer path.

**Reproduction:** `probe_r2e_tenant_nested_container.py`

With principal tenant `acme`:

| args | `_cross_tenant` | verdict | executed |
|---|---|---|---|
| `{"tenant": {"id": "globex"}}` | None | PERMIT | **True** |
| `{"tenant": {"tenant_id": "globex"}}` | None | PERMIT | **True** |
| `{"tenant": ["globex"]}` | None | PERMIT | **True** |
| `{"tenant": [{"tenant_id": "globex"}]}` | None | PERMIT | **True** |
| `{"request": {"tenant": {"tenant_id": "globex"}}}` | None | PERMIT | **True** |
| `{"policy": {"tenant_id": "globex"}}` | None | PERMIT | **True** |
| `{"metadata": {"tenant": {"id": "globex"}}}` | None | PERMIT | **True** |
| `{"tenant": "globex"}` (control) | cross-tenant | **BLOCK** | False |
| `{"request": {"tenant": "globex"}}` (control) | cross-tenant | **BLOCK** | False |
| `{"metadata": {"tenant_id": "globex"}}` (control) | cross-tenant | **BLOCK** | False |

The gap is container values under a quarantined authority key. A scalar under
the same key is caught; an ordinary nested non-authority key is caught because
`iter_pairs` recurses into it.

**Remedy direction:** traverse the quarantined value (or
`classification_view`) instead of appending the container as one unscannable
pair. Recurse into dict/list values before the scalar comparison.

---

### R2-F — Tenant aliases and encoded qualified references escape

**Severity:** P2
**Classification:** REPRODUCED (encoded refs) / SOURCE-SUPPORTED (aliases)
**Declared invariant:** `_cross_tenant` compares tenant-scoped identifiers and
qualified resource references (`tenant_b.customers`, `s3://tenant-b/…`)
against the principal's tenant.

**Source:**
- `morrison_governance/kernel/gate.py`:`_TENANT_KEYS` (1931-1932).
- `_TENANT_REF_RE` (1981-1982): literal `(?:tenant|customer|org)[-_][a-z0-9]+`.
- `gate.py`:`_cross_tenant` qualified-reference loop (2075-2081).
- `normalize.normalize_text()` exists but is not applied here.

**Reproduction:** `probe_r2f_tenant_spellings.py`

Aliases outside `_TENANT_KEYS`:

| args | `_cross_tenant` | verdict |
|---|---|---|
| `organization=globex` | None | PERMIT |
| `customer=globex` | None | PERMIT |
| `account=globex` | None | PERMIT |
| `org_name=globex` | None | PERMIT |
| `tenant_name=globex` | None | PERMIT |
| `tenant_ids=["globex"]` | None | PERMIT |

Encoded/zero-width qualified references:

| path | `_cross_tenant` | verdict |
|---|---|---|
| `tenant%5Fglobex/customers.csv` | None | PERMIT |
| `tenant%2Dglobex/customers.csv` | None | PERMIT |
| `tenant\u200b_globex/customers.csv` | None | PERMIT |
| `s3://tenant%2Dglobex/b` | None | PERMIT |
| `tenant_globex/customers.csv` (control) | outside tenant | **BLOCK** |
| `s3://tenant-globex/b` (control) | outside tenant | **BLOCK** |

The encoded-reference branch is the kernel-level falsification: the exact
reference refused in literal form is permitted when percent-encoded or
interleaved with a zero-width character. The alias branch depends on the
executor's field schema, so it is recorded as SOURCE-SUPPORTED.

**Remedy direction:** normalise (percent-decode, strip zero-width/format
characters, case-fold) before matching; extend the key set or derive it from
the tool manifest; match the tenant reference as a token after normalisation.

---

### R2-G — Caller-supplied clock outruns the wall-clock revocation window

**Severity:** P1
**Classification:** REPRODUCED (API-level)
**Declared invariant:** `gate.py`, `_lease_problem`: *"this transition was
subsequently refused in the same session … the earlier PERMIT is void"* and
*"a caller-supplied clock cannot extend a lease."*

**Source:**
- `morrison_governance/kernel/gate.py`:`_lease_problem` (808-875);
  revocation comparison `now - revoked_at <= decision_ttl_s` (864-874).
- `morrison_governance/kernel/continuity.py`:
  `InMemoryContinuityStore.revoke()` stamps `time.time()` (327-335).
- `gate.py`: decision freshness has an `issued_wall` cross-check (848-852);
  the revocation check does not.

**Reproduction:** `probe_r2g_clock_revocation.py`

Fixture: a shared-resource aggregate-outflow rule with a 25,000 limit. Both
transfers are 20,000 from `SHARED`.

```
T = time.time() + 10_000_000
first  authorize(now=T) -> PERMIT
second authorize(now=T) -> BLOCK (outflow_SHARED), revokes the first
execute(first, now=T + 1)        -> (True, None)   effect recorded
execute(first, now=time.time())  -> refused: "the earlier PERMIT is void"
```

The revocation timestamp is wall time; `_lease_problem` compares it to the
caller's `now`. A caller whose clock is more than `decision_ttl_s` ahead of
wall time makes the revocation look ancient, and the earlier PERMIT executes.
Under the normal wall clock the control refuses.

**Remedy direction:** compare revocations on the wall clock (or on both
clocks and refuse if either says live). The decision's own freshness already
does this; revocation should match.

---

### R2-H — Caller-supplied clock revives an expired approval

**Severity:** P1/P2
**Classification:** REPRODUCED (API-level)
**Declared invariant:** an approval past its `expires_at` is refused, and a
caller-supplied clock cannot extend a lease.

**Source:**
- `morrison_governance/kernel/trust.py`:`ApprovalArtifact.verify` (343) uses
  the caller's `now` for `issued_at` / `expires_at`.
- `morrison_governance/kernel/gate.py`:`verified_approval(now)` (1007-1020);
  `authorize(call, now=...)` and `execute(..., now=...)` are public.

**Reproduction:** `probe_r2h_clock_approval_expiry.py`

```
PAST = time.time() - 100_000
approval = issue_approval(CALL, ttl_s=10, now=PAST)

authorize(CALL)                -> ESCALATE  "approval has expired"
authorize(CALL, now=PAST + 5)  -> PERMIT    "approval verified"
execute(decision, now=PAST + 5)-> (True, ...)  effect recorded
execute(decision)              -> refused   "decision expired 99_875s ago"
```

The decision-freshness wall cross-check still refuses the wall-clock
execution, which is why the exploit must supply the same rewound `now` to both
`authorize` and `execute`. The approval expiry itself has no wall-clock
independent check.

**Remedy direction:** store `issued_wall`/`expires_wall` on the approval (or
verify on wall time in addition to the caller clock) and refuse if either
clock says expired.

---

### R2-I — `record_remote_execution` commits a caller-mutated `decision.action`

**Severity:** P2
**Classification:** REPRODUCED
**Declared invariant:** the decision record names the action that actually ran
(F-6); a decision whose action was mutated after authorisation cannot be
recorded as executed.

**Source:**
- `morrison_governance/kernel/gate.py`:`record_remote_execution()` (1757-1797)
  calls `_lease_problem(require_reservation=False)` then
  `_commit(decision.decision_id, stamp, decision.action)` / `_file(...)`.
- `_lease_problem()` hashes the stored `semantic_hash` /
  `security_binding_hash`; it never re-derives `action_hash(decision.action)`.
- `execute()` *does* re-derive the target hash (1637-1646) and refuses the
  mutation.

**Reproduction:** `probe_r2i_record_remote_binding.py`

```
decision = authorize(read_file /data/customers.csv)   # PERMIT, reserved
decision.action = {"tool": "summarize", "args": {"q": "harmless"}}
record_remote_execution(decision)                     # succeeds
```

| record | value |
|---|---|
| ledger / `executed_history` | `summarize {"q": "harmless"}` |
| sealed evidence `proposed` | `read_file {"path": "/data/customers.csv"}` |
| evidence `action_hash` | original `read_file` hash |
| `action_hash(decision.action)` | different hash |
| `chain.verify()` | **True** |

Control: an unmutated `record_remote_execution` leaves ledger and evidence in
agreement; `execute(mutated decision)` is refused with "action mutated after
authorisation".

**Impact:** audit/evidence divergence. It does **not** erase read taint: the
committed attempt keeps the original decision's capability set (`data.read`),
and `_any_read_occurred` reads capabilities, not the action. If the original
decision had no read capability, the mutated read does not acquire taint
either. The defect is that the two authoritative records disagree about what
ran.

**Remedy direction:** in `record_remote_execution`, re-derive
`action_hash(decision.action)` and require it to equal `decision.action_hash`
before committing; record the executed target, not the mutable decision field.

---

### R2-J — Malformed IPv6 URLs raise out of `authorize()`

**Severity:** P2/P3
**Classification:** REPRODUCED
**Declared invariant:** every proposed transition receives a closed Decision;
`kernel/normalize.py` `normalize_action` says *"Never raises"*
(458-461); the interceptor converts governance errors to BLOCK/fail_closed.

**Source:**
- `morrison_governance/kernel/destinations.py`:`classify_destination()` uses
  `urlparse(...).hostname` without a guard (205-209).
- `morrison_governance/kernel/normalize.py`:`normalize_action()` (458).
- `morrison_governance/kernel/gate.py`:`authorize()` (887-913) has no
  try/except around normalisation or destination resolution.
- `morrison_governance/interception.py`:`GovernanceInterceptor.check()`
  catches and returns `BLOCK/fail_closed` (251-258).

**Reproduction:** `probe_r2j_malformed_url.py`

| input | `authorize()` | `classify_destination` | `normalize_action` |
|---|---|---|---|
| `http://[::1` | `ValueError: Invalid IPv6 URL` | raises | raises |
| `http://[]/x` | `ValueError: '' does not appear to be an IPv4 or IPv6 address` | raises | raises |
| `http://[::ffff:1.2.3.4/x` | `ValueError: Invalid IPv6 URL` | raises | raises |
| `http://[::1]/` (control) | `PERMIT` Decision | ok | ok |

Through the interceptor, all three malformed inputs are `BLOCK`,
`allowed=False`, `fail_closed=True`; the runtime is not called. Direct kernel
callers see an exception instead of a closed Decision.

**Remedy direction:** wrap URL parsing in `try/except` and return a deny
verdict (`external=True`, `forbidden=False`, reason "unparseable destination")
rather than propagating. This is a contract/availability defect, not an open
door on the interceptor path.

---

### R2-K — `SandboxExecutor` subclass defeats legacy-mode confinement

**Severity:** P2
**Classification:** REPRODUCED
**Declared invariant:** `runtime_eval/governance/middleware.py`, `__init__`:
*"It is confined to an inert simulator: a SandboxExecutor calls
ToolSimulator.simulate and nothing else. Point it at anything that can
actually act and it refuses to construct, so this cannot become a second
ungoverned execution surface in a deployment."*

**Source:**
- `runtime_eval/governance/middleware.py`:`__init__` (108-116) — the
  confinement is `isinstance(sandbox, SandboxExecutor)`.
- `middleware.py`:`step` — legacy dispatch `self.sandbox.execute(call)`
  (242-250).

**Reproduction:** `probe_r2k_sandbox_subclass.py`

```python
class EvilExecutor(SandboxExecutor):
    def execute(self, call):
        self.effects.append(dict(call))
        return {"ok": True, "real_effect": True}

mw = RuntimeGovernanceMiddleware(layer, EvilExecutor())   # kernel is None
mw.run(OneShot(delete_bucket), {}, max_steps=3)
```

Observed:

| check | result |
|---|---|
| layer `delete_bucket` | PERMIT |
| kernel `delete_bucket` (manifest `infra.destructive`) | ESCALATE |
| legacy middleware constructed with `kernel is None` | yes |
| `EvilExecutor.effects` | `[delete_bucket {"bucket": "prod"}]` |
| plain duck-typed executor | **refused** (`ValueError`) |
| same call with `security_context=` | kernel set, effects `[]` |

The guard is a nominal type check. Subclassing preserves
`isinstance(..., SandboxExecutor)` while replacing the inert `execute` body,
so the dispatch the class was supposed to confine reaches a real effect. A
deployment that writes a recording/telemetry subclass is already outside the
intended inert-simulator contract.

**Remedy direction:** do not rely on `isinstance` for an execution-surface
confinement. Accept only a sealed/final inert simulator, or require an
explicit `sandbox_is_inert=True` capability that the class cannot be
subclassed out of, or make the legacy path dispatch through a private
simulator object the caller cannot supply.

---

## 3. Negative results (held)

### R2-L — Concurrency compositions

`probe_concurrency.py` — all held:

| Probe | Result |
|---|---|
| `max_outstanding_reservations=8`, 40 threads, one kernel | 8 PERMIT / 32 ESCALATE |
| same, two kernels sharing one `InMemoryContinuityStore` | 8 PERMIT / 32 ESCALATE |
| 20 threads execute one decision | 1 success, 1 effect |
| 40 threads append + verify an evidence chain | 40 unique seqs, `verify() == True` |
| one approval, two sessions, shared store | `PERMIT` / `ESCALATE`; one effect |
| one approval, ten kernels, shared store | 1 PERMIT / 9 ESCALATE |
| shared-resource aggregate, two principals, 10 threads | 1 PERMIT / 9 BLOCK |
| one decision redeemed by two kernels in the same session | 1 success, 1 effect |

No concurrency counterexample found. The reservation cap counts RESERVED and
UNCONFIRMED entries; the store transaction serialises writers; `execute()`
consumes and commits under the same lock; evidence append is module-locked;
approval replay state is keyed to the continuity identity; and
shared-resource history is read across principals.

### R2-M — Evidence authenticity, replay, config-dependent enforcement

`probe_evidence_authenticity.py` — all held:

| Probe | Result |
|---|---|
| keyless chain rewritten + resealed | `verify() == True` (documented: integrity, not authenticity) |
| keyed chain rewritten without the key | `verify() == False`, "signature invalid" |
| keyed chain rewritten by a key holder | `verify() == True` (expected) |
| `require_evidence_key=True` without a key | `ValueError` at construction |
| `require_evidence_key=True` with a key | authenticated chain |
| policy change after authorisation | `execute()` refused, "governing ruleset changed" |
| sealed BLOCK record with `executed=True` | `verify() == False`, fail-closed violation |
| execution-outcome record mutated | `verify() == False`, signature invalid |
| replay into a same-key chain | accepted (the chain authenticates key possession, not provenance) |
| legacy `evaluated=None` record | skips the `action_hash`↔`proposed` binding check by design |

These are stated limits, not new falsifications. `evaluated=None` is only
reachable by a writer that can already append records; a keyed chain does not
authenticate an unkeyed writer.

### R2-N — Alternative execution paths

`probe_alternate_paths.py` — all held:

| Path | Result |
|---|---|
| `GovernanceLayer.evaluate()` directly | PERMIT, but documented as not the kernel; no effect |
| `GovernanceGuard.advisory(...).dispatch()` | `GovernanceConfigurationError`, no effect |
| `GovernanceGuard(gov)` without a context | `GovernanceConfigurationError` |
| `GovernanceInterceptor(layer)` closed mode | `BLOCK/fail_closed` |
| `GovernanceInterceptor(layer, allow_advisory=True)` | executes, but `enforcement="advisory"`, `advisory=True` |
| raw `mint_lease(fabricated_decision, signer)` | mints, but `LeaseVerifier` refuses without registration |
| `wrap_mcp_call_tool` | dispatches through the kernel; ESCALATE refused |

The advisory path is explicitly opted into and labels itself advisory. Raw
`mint_lease` requires the trusted signer and a store write, so it is not a
boundary bypass.

### Additional held checks

- **Resource ownership fail-closed** (`_resource_owner_problem`): an owned id
  permits; an unknown id, a foreign id, and a missing resource argument all
  BLOCK with `resource_owner_unknown`.
- **Nested authority-field classification**: `{"policy": {"audit_logging":
  false}}`, `{"outer": {"policy": {"mfa_required": false}}}`, and
  `{"config": {"authorized": true}}` are classified on the preserved value and
  BLOCK (`log.tamper` / `security_control.modify` / `forged_authority_claim`).
- **`execute()` action binding**: executing a different call or a mutated
  decision is refused with "action mutated after authorisation".
- **Destination revalidation direction**: the commit-time check refuses
  internal→external and newly-forbidden destinations; it does not need to
  refuse external→internal for safety.
- **Approval single-use**: one approval, ten kernels / two sessions, shared
  store → exactly one PERMIT.

---

## 4. Final assessment

### Declared invariants falsified

1. **Metadata endpoints are never internal under any configuration** — R2-A.
2. **Deny-by-default: a destination present in the call is resolved** — R2-B,
   R2-C.
3. **A server-side payment threshold governs the amount the action moves** —
   R2-D.
4. **The cross-tenant check walks the whole payload at every depth** — R2-E.
5. **Qualified tenant references are attributed to a tenant** — R2-F
   (encoded/zero-width forms).
6. **A subsequent refusal voids the earlier PERMIT; a caller clock cannot
   extend a lease** — R2-G.
7. **An approval past `expires_at` is rejected** — R2-H.
8. **The decision record names the action that actually ran** — R2-I
   (`record_remote_execution`).
9. **Every proposed transition receives a closed Decision; `normalize_action`
   never raises** — R2-J.
10. **Legacy middleware is confined to an inert `SandboxExecutor`** — R2-K.

### Declared invariants that survived

- Reservation caps under concurrency, single-use execution, evidence-append
  serialisation, approval single-use across sessions, and shared-resource
  aggregate enforcement (R2-L).
- Keyed evidence authenticity, `require_evidence_key`, ruleset-change
  invalidation, the fail-closed evidence invariant, and execution-outcome
  immutability (R2-M).
- `GovernanceGuard`/advisory/interceptor/MCP/lease surface behaviour (R2-N).
- Resource-ownership fail-closed, nested authority-field classification,
  `execute()` action binding, destination revalidation direction.

### Highest-priority remediation order

1. **R2-A** (P0) — unmap and canonicalise IPv6 before the forbidden check.
2. **R2-B / R2-C** (P0/P1) — resolve destinations by value shape and key
   family; do not let the authority-key rename erase a bare host.
3. **R2-D** (P1) — bind auto-approval to the executed amount; reject
   disagreeing amount aliases.
4. **R2-E** (P1) — traverse container values under authority keys in the
   tenant check.
5. **R2-G / R2-H** (P1) — wall-clock cross-checks for revocation and approval
   expiry.
6. **R2-F** (P2) — normalise tenant references before matching.
7. **R2-I / R2-J / R2-K** (P2) — re-derive the action hash in
   `record_remote_execution`; return a closed Decision for unparseable
   destinations; replace the `isinstance` confinement.

### Residual limits (not falsifications)

- Caller-controlled `now` is a public API parameter. R2-G and R2-H are
  API-level findings; a deployment that always uses wall time is not affected.
  The lesson is that the clock-sensitive guards should cross-check wall time
  rather than trusting the caller's clock.
- Keyless evidence chains are self-consistency only, as documented; a writer
  that can rewrite the chain and recompute hashes passes. `evidence_key` /
  `require_evidence_key` is the authenticating configuration.
- The layer-only `GovernanceLayer.evaluate()` and
  `GovernanceInterceptor(allow_advisory=True)` are advisory by design and
  label themselves as such; T1 remains a deployment responsibility, as stated
  in `kernel/mediation.py`.

---

## 5. Artifact integrity

- No enforcement file was modified during this campaign.
- `redteam/deepseek_redteam/` (round-1) is unchanged.
- All remediation changes from the prior campaign remain uncommitted.
- Every reproduction uses `_common.Recorder`; no probe performs real I/O.
