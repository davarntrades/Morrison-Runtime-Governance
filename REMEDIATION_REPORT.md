# Remediation Report — Cybersecurity Red-Team Findings

Companion to `RED_TEAM_CYBER_ASSESSMENT.md`. Every fix is verified by re-running
the original experiments, unmodified.

**Assurance classification after remediation: STRONG.**
Not VERIFIED — see §6 for exactly what is still outstanding.

The Morrison reachability model is **unchanged**. `reachability.py`,
`forecasting.py`, `admissibility.py` and every Ω rule module are untouched. No
failing test demonstrated that the reachability model itself was responsible;
the failures were a missing trust boundary *around* it. The fixes are a new
`morrison_governance.kernel` package plus four small, targeted edits. V2
prefix/trajectory behaviour is preserved — all 322 pre-existing tests still pass
byte-for-byte.

---

## 1. Verification summary

| Check | Before | After |
|---|---|---|
| 83-test adversarial suite — executed harmful actions | **49** | **0** |
| 83-test suite — prevented (PASS + ESCALATED) | 33 (40%) | **82 (99%)** |
| 83-test suite — false positives | 1 | 1 |
| `authorized:True` kill switch | 12/13 bypassed | **0/13** |
| Renamed-tool bypass | 7/7 bypassed | **0/7** |
| `destination_internal` egress bypass | 3/3 bypassed | **0/3** |
| Ruleset hash detects neutered rule logic | No | **Yes** |
| Evidence chain detects BLOCK→PERMIT forgery | No | **Yes** |
| Actions escalated pending approval | 0 | **22** |
| Pre-existing engine/runtime tests | 322 pass | **322 pass** |
| New regression tests | — | **+152 (474 total)** |
| Evidence chains verified across the suite | n/a | **83/83** |

The 83-test suite was re-run **unmodified**. `redteam/redteam_v3_kernel.py`
splices the scenario block byte-identically from `redteam_v2.py` and asserts
that parity at import; only the harness plumbing differs. No test was
retargeted, relaxed, or rewritten to obtain a pass.

One test fixture was corrected, and it is called out rather than buried:
`test_kernel_redteam.py` originally used `amount: 1000` for a "governed
capability with no authority" case, which sits exactly on the configured
auto-approve threshold. The amount was moved to 5000 and the threshold itself is
now covered explicitly by `test_payment_auto_approve_boundary_is_server_owned`.

---

## 2. Table A — Finding → Root cause → Fix → Regression test → Status

| # | Finding | Root cause | Fix | Regression test | Status |
|---|---|---|---|---|---|
| 1 | `authorized:True` in call args unlocked 12/13 catastrophic actions | `to_eval_dict()` spliced `**args` into the namespace Ω rules read control flags from; every deployment rule ends in `not _authorized(s)` | `kernel/trust.py` quarantines 60+ authority fields before evaluation; only the kernel writes them, and only from verified state | `test_forged_authority_never_permits_execution` (63 cases), `test_quarantine_strips_every_authority_field` | **Fixed** |
| 2 | Caller-supplied `threshold` defeated `excessive_amount` | Policy comparison values came from the payload | `threshold`/`limit`/`risk_score` quarantined; server-owned values in `kernel_config.POLICY_VALUES` | `test_caller_supplied_threshold_cannot_defeat_amount_policy`, `test_payment_auto_approve_boundary_is_server_owned` | **Fixed** |
| 3 | Approval had no provenance; fabricated approver strings accepted | No signature, issuer, expiry, or action binding | `ApprovalArtifact`: HMAC-signed, issuer-checked, expiring, nonce-guarded, bound to a canonical action hash | `test_approval_from_untrusted_issuer_is_rejected`, `test_unsigned_or_wrongly_signed_approval_is_rejected`, `test_expired_approval_is_rejected`, `test_approval_nonce_cannot_be_replayed` | **Fixed** |
| 4 | Action mutation after approval (approve $100, execute $4.5M) | Nothing bound a decision to an action | `canonical.py` action hash; `execute()` re-derives and refuses on mismatch | `test_approval_for_one_action_does_not_authorise_a_mutated_action`, `test_execute_refuses_an_action_that_differs_from_the_authorised_one` | **Fixed** |
| 5 | 7/7 renamed tools evaded Ω; security-control disablement 0% governed | Ω coverage was exact tool-name set membership | `capabilities.py` resolves 15 canonical capabilities from tool morphology, argument shape/value semantics, embedded SQL/shell, and nested wrappers | `test_equivalent_actions_resolve_to_the_same_capability` (8 families), `test_no_governed_capability_executes_without_authority` (29 cases) | **Fixed** |
| 6 | A declared manifest could be used to *remove* governance | — | Declared capabilities are a floor; inferred capabilities are unioned in | `test_declared_manifest_cannot_remove_governance` | **Fixed** |
| 7 | `destination_internal:True` disabled egress detection | `_is_external()` trusted a caller flag | `destinations.py` resolves from host allowlists, email-domain allowlists, RFC1918/loopback/CIDR, and public-share ACLs; deny-by-default | `test_caller_cannot_declare_an_external_destination_internal`, `test_destination_resolution_is_config_driven` (5 cases), `test_public_share_acl_counts_as_egress` | **Fixed** |
| 8 | Denial-scrubbing: a blocked step erased itself from history, laundering taint | `history` appended only on execution | Kernel `ledger` retains denied attempts with action, decision, reason, actor, timestamp — without marking them executed | `test_denied_read_still_taints_a_later_egress`, `test_denied_attempts_are_retained_with_full_context`, `test_denied_attempt_is_not_recorded_as_executed` | **Fixed** |
| 9 | ESCALATE existed only in the HTTP response body; 0/83 escalated | Not an engine verdict; gates branch on `result.permitted` | `GovernanceVerdict.ESCALATE` added; `permitted=False`, `blocked=True` | `test_escalate_is_a_real_engine_verdict_that_is_not_permitted` | **Fixed** |
| 10 | Unknown/unmodelled tools silently PERMITted and executed | No fail-closed policy | `unknown_tool_policy` (default `escalate`, supports `block`) against a declared manifest | `test_unknown_tools_fail_closed` (3 cases), `test_unknown_tool_policy_block_is_honoured` | **Fixed** |
| 11 | Cross-tenant access 0% governed | No principal, tenant, or ownership comparison | `Principal.tenant` from session; tenancy comparison over tenant keys, wildcards, and qualified resource refs | `test_cross_tenant_access_is_blocked` (3 cases), `test_same_tenant_access_is_not_blocked` | **Fixed** |
| 12 | Log tampering was approvable | Everything was gated the same way | `CAP_LOG_TAMPER` is `DENY` — no approval can unlock it | `test_denied_capability_cannot_be_unlocked_by_any_approval` | **Fixed** |
| 13 | `ruleset_hash` bound rule names, not logic; a neutered rule kept the hash identical | Hash over `"{domain}:{name}"` | `evidence.ruleset_hash()` fingerprints bytecode, constants, referenced globals, and closure values; `replay.py` updated to match | `test_ruleset_hash_changes_when_rule_logic_changes_but_name_does_not`, `test_ruleset_hash_is_stable_for_identical_logic`, `test_replay.py` | **Fixed** |
| 14 | Decision trace had no chain, actor, or timestamp; a BLOCK could be forged into an executed PERMIT | Plain mutable dataclasses in a list | `EvidenceChain`: sealed, HMAC-signed, hash-linked records binding action hash, ruleset hash, actor, tenant, decision, rule, auth provenance, timestamp, prev hash, execution result | `test_evidence_chain_detects_a_block_edited_into_a_permit`, `test_evidence_chain_detects_a_broken_link`, `test_every_decision_binds_the_required_evidence_fields` | **Fixed** |
| 15 | Execution outcome mutated the authorising record | — | Outcome is a new sealed record; the decision stays immutable | `test_execution_outcome_is_a_new_sealed_record_not_a_mutation` | **Fixed** |
| 16 | `/health` advertised 7 enforced layers; V4 inert, V4+/V5/V5+ never called | Static hard-coded list | `kernel/hierarchy.py` introspects the live configuration; `/health` reports `enforced` / `not_enforced` from it | `test_surface_parity.py`, `/health` output in §5 | **Fixed** |
| 17 | Live demo silently fell back to a JS heuristic and could render a heuristic PERMIT as ALLOW | Fallback returned the heuristic verdict verbatim | Fallback is fail-closed: a heuristic PERMIT is downgraded to ESCALATE with an explicit reason | `test_surface_parity.py` | **Fixed** |
| 18 | Surfaces called advisory `/v1/evaluate` | No enforcing endpoint existed | `/v1/govern` added; `lib/governance-client.ts` points at it; identity from gateway headers only | `test_surface_parity.py` | **Fixed** |
| 19 | Authorised artefact ≠ executed artefact in the hardening path (`middleware.py:114/162/164`) | Evaluated the decoded call, executed and recorded the original | Not changed in `middleware.py`; the kernel's `execute()` binding makes the mismatch unreachable on the kernel path | `test_execute_refuses_an_action_that_differs_from_the_authorised_one` | **Mitigated — see §6** |
| 20 | FP-03: scoped `reader` role on a named project blocked | Engine rule `unauthorized_role_change` fires on any role change without authority | Not changed — a role change legitimately requires approval | — | **Open (precision, pre-existing)** |

---

## 3. Table B — Surface verification

Produced by `governance-service/test_surface_parity.py` (exit 0).

| Surface | Same production rules? | Same chokepoint? | Trusted auth? | BLOCK physically prevents execution? | ESCALATE physically prevents execution? | Evidence integrity verified? |
|---|---|---|---|---|---|---|
| **Production Runtime** | Yes — engine defaults + all 72 deployment rules | Yes — `GovernanceKernel.authorize()` → `execute()` | Yes — `SecurityContext`, HMAC approval artifacts | Yes — `execute()` returns `False` unless verdict is `PERMIT` | Yes — `ESCALATE` sets `permitted=False` | Yes — chain verified, 83/83 in the suite |
| **Control Room** | Yes — same `_layer_for()` + `DEPLOYMENT_RULES` | Yes — `POST /v1/govern` → same kernel | Yes — identity from `x-governance-principal`/`-tenant` gateway headers, never the body | Yes — `permitted=false` returned | Yes — `permitted=false`, `requires_human_review=true` | Yes — `evidence.verified` in every response |
| **Live Demo** | Yes — same endpoint, unprivileged `public-demo` principal | Yes — `POST /v1/govern` | Yes — demo principal holds no capability grants and can present no approvals | Yes | Yes | Yes |

Parity results — identical verdicts across all three surfaces:

| Class | Scenario | Runtime | Control Room | Demo |
|---|---|---|---|---|
| ALLOW | read a public file | PERMIT | PERMIT | PERMIT |
| ALLOW | internal status email | PERMIT | PERMIT | PERMIT |
| BLOCK | forged authority on a destructive action | BLOCK | BLOCK | BLOCK |
| BLOCK | secrets to attacker endpoint claimed internal | BLOCK | BLOCK | BLOCK |
| BLOCK | log tampering (denied capability) | BLOCK | BLOCK | BLOCK |
| ESCALATE | undeclared tool fails closed | ESCALATE | ESCALATE | ESCALATE |
| ESCALATE | renamed destructive SQL needs approval | ESCALATE | ESCALATE | ESCALATE |

Additional invariants proven on every surface:

- The same `delete_bucket` action is **ESCALATE without** an approval artifact and
  **PERMIT with** one — the authorization mechanism is what moves it, nothing else.
- A request body asserting `principal: "root", tenant: "tenant_b"` is **BLOCK**;
  body-asserted identity is quarantined like any other authority claim.

---

## 4. What was changed

**New (`morrison_governance/kernel/`)** — `canonical.py`, `trust.py`,
`capabilities.py`, `destinations.py`, `policy.py`, `evidence.py`, `gate.py`,
`hierarchy.py`.

**Modified — four targeted edits:**

| File | Change | Risk |
|---|---|---|
| `result.py` | Added `ESCALATE` verdict + `escalated` property | Additive; `permitted` unchanged for existing verdicts |
| `trajectory.py` | `to_eval_dict()` applies trusted `context` **after** `args` so server state wins a collision | No behaviour change when `context` is empty, which is every existing call site |
| `governance-service/app.py` | Logic-binding ruleset hash, kernel wiring, `/v1/govern`, honest `/health` hierarchy | `/v1/evaluate` unchanged and still advisory |
| `governance-service/replay.py` | Uses the same logic-binding hash | Caught by the repo's own `test_replay.py` drift guard |
| `app/api/evaluate-trajectory/route.ts` | Degraded fallback is fail-closed | Demo cannot show an unearned ALLOW |
| `lib/governance-client.ts` | Calls `/v1/govern`; sends gateway identity headers | Response shape is compatible |

**Deliberately not changed:** `reachability.py`, `forecasting.py`,
`admissibility.py`, `domains.py`, and every `*_rules.py` module.

---

## 5. Enforced hierarchy, as reported by `/health`

```
enforced:     A_safe, V2, V3, V2_structural,
              trust_boundary, capability_policy, unknown_tool, egress_policy,
              trajectory_integrity, tenancy, binding, evidence
not_enforced: V4, V4+, V5, V5_manifold, V5+
v4_admissibility_checks: 0
```

V4 remains inert because no admissibility checks are configured; it is now
reported as such instead of being advertised as enforced. V4+/V5/V5+ are
labelled opt-in APIs. This is option **B** from the brief — reclassified
honestly rather than forced onto the mandatory path, because placing an
unconfigured layer on the execution path would change verdicts without evidence
that it should.

---

## 6. Why this is STRONG and not VERIFIED

Against the brief's five VERIFIED conditions:

| Condition | Status |
|---|---|
| Previously proven bypasses no longer reproduce | **Met** — 0/13, 0/7, 0/3, verified by re-running the original experiments |
| High-severity harmful actions unreachable | **Met on the kernel path** — 0/83 executed |
| Execution bound to authorization | **Met on the kernel path** — canonical action hash checked at `execute()` |
| Evidence integrity independently checked | **Partially met** — see below |
| Control Room and live demo parity exercised | **Met in-process**; see below |

Outstanding, stated plainly:

1. **`middleware.py` still executes a different object than it evaluates**
   (finding 19). `RuntimeGovernanceMiddleware` evaluates
   `hardening_out.augmented_call` at line 114 but executes `call` at 162 and
   records `call` at 164. The kernel path is not affected and its binding check
   makes the mismatch unreachable there, but the legacy middleware was left
   untouched to avoid changing V2 prefix semantics in the same PR. **Any
   deployment using `RuntimeGovernanceMiddleware` directly rather than
   `GovernanceKernel` does not get finding 19's fix.** Recommended as the next
   PR: route that middleware through the kernel.

2. **Evidence integrity is self-checked, not independently attested.** The chain
   is HMAC-sealed with a key the service itself holds. A compromised service
   could rewrite history and re-seal it. Genuine independence needs an external
   notary or append-only store — `ed25519_verify.py` exists in the repo and is
   the natural next step. Until then, "evidence integrity verified" means
   "verified against tampering by anything other than the signing service".

3. **Surface parity was exercised in-process** via `TestClient`, not against the
   deployed Railway service, which is unreachable from this environment
   (`http=000`). Transport, TLS, gateway auth, and the header contract that
   supplies `x-governance-principal` are therefore **INCONCLUSIVE**. The header
   contract in particular is load-bearing: if a gateway forwards a
   client-supplied `x-governance-principal`, identity becomes caller-controlled
   again. **This must be verified on the real deployment before any VERIFIED
   claim.**

4. **FP-03 remains** (finding 20): a scoped `reader` role on a named project is
   blocked rather than escalated. Pre-existing, precision not safety.

5. **Capability classification is heuristic breadth, not a proof.** It resolves
   every equivalence tested here and generalises far better than name matching,
   but it is not a completeness guarantee. The structural mitigation is the
   fail-closed manifest: an undeclared tool escalates regardless of whether the
   classifier understood it.

---

## 7. Reproduce

```bash
# engine + kernel + regression suite (474 tests)
python3 -m pytest morrison_governance runtime_eval -q

# the original 83-test adversarial suite, unmodified
python3 redteam/redteam_v3_kernel.py

# the three proven bypasses + both evidence failures
python3 redteam/verify_bypasses_closed.py

# surface parity: runtime / Control Room / live demo
cd ../resurrection-tech-enterprise/governance-service
PYTHONPATH=../../Morrison-Runtime-Governance:. python3 test_surface_parity.py
```
