# PR #36 — evidence repair and adversarial re-falsification

## Scientific assessment

**SUPPORTED within the defined bounded execution environment.** Four individually
locally admissible 30-record actions reach 120 records under local-only enforcement.
Separate local and joint-global checks block the corresponding fourth transition
before protected record mutation, leaving 90. Governance calls issue the decisions;
protected records independently establish execution. This is a reproducible bounded
execution distinction. No scientific novelty claim is made.

Original artifact head: `f5b1d321aef33030b2ddfd4d5c6a0a7c53365d86` (clean baseline).
Final repaired source: `7bd0b2259296f077f5d8b79dc795572a7b927a31` (clean at formal run starts).
Production policy defaults and existing governance modes are unchanged. Original
43 focused assertions remain unchanged. The extra 37 repair tests bring the
published core collection count to 1,654; README/facts values describe collection,
not a claim that every collected test passed.

The first repair source `7314cda0b2a21843b06c5104edeecb9ddd745752`
passed 43 original tests, 33 repair tests, 1,302 regression tests (8 skips), and
1,643 full-suite tests (8 skips). A broader malformed-metadata probe then found
a new counterexample: a PERMIT-shaped response with a non-serializable reason
committed 30 records before evidence hashing raised TypeError, leaving no
decision trace. This was reproduced directly and is preserved in
`runs/malformed-metadata-counterexample/`. The final source validates every
response field and establishes metadata serializability before permit can reach
the effect gate. The same probe now yields local PERMIT, global ERROR, final
BLOCK, zero records and one decision trace; four field-specific regression
cases were added. `phase-one/` and the first-phase run logs retain the earlier
results instead of overwriting them. A green suite did not erase the counterexample.

## Before and after

| Defect | Before | Repaired behavior | Status |
| --- | --- | --- | --- |
| Failure-path telemetry | Completed local PERMIT incorrectly recorded NOT_EVALUATED when global authority raised | Local PERMIT retained; global ERROR includes exception type, message and traceback; final BLOCK; ordered START/RESULT/ERROR events; no effect | FIXED |
| Expanded malformed-response counterexample | Non-serializable authority metadata could fail evidence hashing after committing 30 records | Full response metadata validated before effect; four field-specific tests and exact post-fix probe commit zero records with complete failure trace | FIXED |
| Run-specific provenance | One repaired SHA attributed to historical failed and successful runs | Every formal new run captures start commit, branch, clean/dirty state, tracked diff hash, full source snapshot hash/map, command, environment, timestamps, log digest, counts and exit; uncertain historical per-run fields explicitly UNKNOWN | FIXED for new capture and historical attribution; missing historical snapshots cannot be recovered |
| Package integrity | Row verifier did not bind header/source/summary fields | Canonical SHA-256 manifest covers every package artifact; verifier requires separately supplied retained anchor, validates file set/digests, chains, actual state reconstruction, identity/binding and CSV/JSON agreement | FIXED against retained external anchor |

The wrapper observes the existing hierarchy's calls without re-evaluating or
manually assigning permits. It wraps current tier methods at invocation so
injected failures cannot erase completed observations. Exceptions caught inside
existing governance modes retain the exact returned error reason and BLOCK
result; tier exceptions exposed to the wrapper also retain their traceback.
Malformed responses fail closed. Local and global normal-path decisions and
protected transitions match all original primary fields exactly. Version, new
telemetry and evidence hashes necessarily change.

## Sequential comparison

The same fixed fixture, proposer, validation, SHA-256 request binding, principals,
session, empty protected state, submission method and lock type serve both arms.
Before each of the four authentic authority calls, protected records, candidate,
local history, joint history and used action IDs are identical. Global evaluation
is the intended enforcement difference. Both arms now use the same tier-observer
logic. Reversing arm execution order produces exactly the same primary traces.

| Measurement | Local-only | Hierarchical |
| --- | --- | --- |
| Individual local verdicts | PERMIT ×4 | PERMIT ×4 |
| First three operations | Executed | Executed |
| Fourth operation | Executed | Local PERMIT, global BLOCK |
| Executed totals by step | 30, 60, 90, 120 | 30, 60, 90, 90 |
| Final executed records | 120 | 90 |
| Global limit >100 reached | Yes | No |
| Protected mutation from denied operation | Not applicable | None; exact before/after record lists identical |

`traces.json` includes complete synthetic records, identities, separate verdicts,
ultimate decisions and hashes. `traces.csv` is the corresponding compact view.
State reconstruction appends only the exact candidate records whose effect was
observed. It agrees with protected snapshots and decision traces in both arms.
The cumulative rule fires through the existing reachability evaluator on the
joint-trajectory representation; this is not predictive V3 forecasting evidence.

## Concurrent comparison and scheduling

| Workload | Local-only | Hierarchical |
| --- | --- | --- |
| Sequential: 4 distinct agents ×30 | 120 | 90 |
| Concurrent: 8 distinct agents ×30, 20 trials per arm | 240 in every trial | 90 in every trial |
| Concurrent executed actions per trial | 8 | 3 |

Concurrency preserves the original review workload: eight worker threads wait
at one `threading.Barrier(8)`, then submit the same eight fixed actions through
the same locked executor. It proposes 240 records, whereas the sequential
experiment proposes 120. Actual OS scheduling/lock acquisition order is not
fixed and is not claimed identical across arms. Each trial records its precise
serialization schedule and full decision/state trace. Every request exports 30
records from a distinct agent, so which three requests commit does not change
the cumulative cap. `concurrent-summary.csv` exposes all 40 schedules; full
records are in `adversarial-full.json.gz`.

Each trial starts a fresh trusted executor instance. The printable fixture
session label is reused, but the enforced session state is scoped to that
instance/run. A limit spanning multiple instances with the same label is not
demonstrated; that requires independently bound session identity and shared
state. Caller-supplied session reset identifiers remain rejected.

The lock spans validation, decision, protected append, history update and
trace append. Tests assert consecutive before/after states, exactly three
hierarchical commits and unchanged records on every denial. This demonstrates
in-process threaded serialization during normal operation, not a durable or
distributed transaction.

## Adversarial findings and residual boundaries

Reproduced checks cover matched authority-entry inputs, shared adapter/lock,
reversed arm order, independent protected reconstruction, cross-agent and
same-agent composition, 100/101 boundaries, fresh-state reset, session/principal
substitution, forged request-side authority claims, replay, missing/mismatched
binding, partial evaluation and authority exceptions/timeouts/malformed/unavailable
responses. Error-path checks observe local PERMIT/global ERROR/final BLOCK,
correct event ordering and zero protected mutation.

* The proposer is scripted, agent identities are fixture labels, and concurrent
  agents are worker threads. Effects append synthetic records to a list; no
  real export endpoint or learned proposal distribution is measured.
* At 40+40+20, all effects commit and total is exactly 100. At 40+40+21,
  the final locally admissible request blocks globally; total remains 80.
* Request-side forged authority fields are rejected by the fixture schema.
  The fixture has no exported cryptographic execution lease; these tests do
  not establish signature forgery resistance or resource-side authentication.
* Binding is mandatory SHA-256 identity comparison, not authentication. The
  trusted test driver supplies principal identity; real deployments require
  an independently authenticated identity channel and protected authority.
* Timeout and unavailable-authority tests inject `TimeoutError` and
  `ConnectionError`. There is no watchdog for an authority that never returns;
  transport cancellation and operational deadlines remain deployment work.
* A direct Python write to the fixture's private record list reaches 120 with
  zero governance evidence. This bypass is reproduced and retained. The tested
  boundary is submission through the trusted API. Python privacy conventions
  do not enforce isolation against hostile same-process code.
* Crash, memory allocation failure and evidence-storage failure between effect,
  history and evidence updates are not rollback-safe; neither process replicas
  nor external exporters are mediated by this fixture. Credential isolation,
  shared durable serialization and resource-side enforcement remain deployment
  obligations. No broader complete-mediation claim is made.

## Integrity and provenance

`package-manifest.json` canonicalizes schema, algorithm and the complete file
map. The verifier requires a 64-character SHA-256 anchor from **outside the
package**; it never reads an anchor supplied inside it. The retained anchor is
published in the PR description and final review response. Reviewers must retain
it independently of the material being verified. No signature, independent
identity attestation or immutable storage service is provided.

Tests alter source attribution, summary totals, action records, ordering,
identities, local/global verdicts, execution decisions, protected state, JSON,
CSV, configuration, input fixture, validation metadata, reports, manifest
entries, file deletion and extra files. All such alterations reject against
the retained anchor, including after regenerating a self-consistent manifest.
A deliberate negative control shows that supplying the attacker's NEW anchor
can accept forged source attribution. That demonstrates hash consistency rather
than authenticated provenance; it is not claimed otherwise.

Every new formal run has its own `runs/<name>/run-start.json`, `run.json` and
`stdout.log`. Source capture precedes execution, including hashing untracked
files when dirty. Working-tree state after the run is separately recorded.
Full-suite tests can regenerate existing Living Boundary artifacts; the end
snapshot exposes those changes rather than retroactively changing the start
snapshot. Evidence outputs are outside the repository while source runs occur.

Historical original artifacts remain byte-for-byte copied under
`historical-original-package/` and unchanged at their original repository path.
`historical-provenance.json` retains each original validation entry, flags the
legacy top-level SHA attribution, and explicitly marks unavailable contemporaneous
commit/branch/clean/diff/timestamp fields unknown. The original failed collection
assertion is preserved as an excerpt; the complete original failed stdout and
source snapshot were not retained and are not invented. Fresh pre-repair
baseline review, all 40 baseline concurrent traces and reproduced defects are
retained in `baseline-review.json.gz`.

## Reproduce

Use the pinned source for execution, and the final PR artifact commit for the
preserved evidence package. Set `OUT` to an empty directory **outside** the
repository so output files do not contaminate start-state provenance.

```sh
git checkout 7bd0b2259296f077f5d8b79dc795572a7b927a31
python -m pip install pytest==8.3.5
OUT=/tmp/pr36-independent-replay
python -m experiments.local_global_admissibility.evidence_tools record --output "$OUT/runs/primary" -- python -m experiments.local_global_admissibility.experiment --output "$OUT"
python -m experiments.local_global_admissibility.evidence_tools record --output "$OUT/runs/original-focused" -- python -m pytest -q experiments/local_global_admissibility/test_experiment.py multi_agent_eval/tests
python -m experiments.local_global_admissibility.evidence_tools record --output "$OUT/runs/repairs" -- python -m pytest -q experiments/local_global_admissibility/test_repairs.py
python -m experiments.local_global_admissibility.evidence_tools record --output "$OUT/runs/adversarial" -- python -m experiments.local_global_admissibility.review --output "$OUT/adversarial.json"
python -m experiments.local_global_admissibility.evidence_tools record --output "$OUT/runs/regression" -- python -m pytest -q --ignore=living-boundary
python -m experiments.local_global_admissibility.evidence_tools record --output "$OUT/runs/full" -- python -m pytest -q
```

To inspect compressed raw traces:

```sh
python -c 'import gzip,sys; sys.stdout.buffer.write(gzip.open(sys.argv[1],"rb").read())' adversarial-full.json.gz
```

To verify the retained original package, obtain the final PR artifact tree and
supply the anchor from the PR description/review response:

```sh
python -m experiments.local_global_admissibility.evidence_tools verify experiments/local_global_admissibility/repair_evidence --anchor RETAINED_EXTERNAL_SHA256
```

To seal a new independent reproduction, use `evidence_tools seal DIRECTORY` and
retain the printed anchor separately. Its timestamps and concurrent lock order
will differ; primary deterministic decision/state fields are expected to match.
An original retained anchor is not expected to verify a newly generated run.

Verification operates on the supplied files at verification time. Use a
read-only evidence snapshot and trusted verifier code; a verification result
does not prevent later file mutation.

## Observed validation results

The final per-run counts, durations, skips and statuses are appended below only
from completed recorded runs. The prior interrupted full-suite result remains
preserved as historical evidence; it is never reported as a pass.

| Final-source run | Actual result | Exit status |
| --- | --- | --- |
| final-primary | Assertions completed; see recorded output | 0 |
| final-original-focused | 43 passed | 0 |
| final-repairs | 37 passed | 0 |
| final-adversarial | Assertions completed; see recorded output | 0 |
| final-regression | 1306 passed, 8 skipped | 0 |
| final-full | 1647 passed, 8 skipped | 0 |

Final full-suite stdout: **1,647 passed, 8 skipped in 393.01 seconds**.
The final excluded-Living-Boundary regression suite has 1,306 passes, an
increase of 37 over the historical 1,269 baseline. The full suite collects one
additional optional Petri case beyond the documented core collection of 1,654.
All eight skip identities/reasons match the baseline exactly. No new skip
markers were introduced. The 19 recorded integrity cases passed.

All required checks completed on the final pinned source. PR #36 is
**technically ready for merge review of this bounded experiment**, with the
residual boundaries above. It remains a draft; no merge or deployment occurred.

Post-seal real-package probes rejected changes to source, totals, ordering,
identity, protected state and CSV even after attacker resealing. Editing the
manifest alone also rejected. An extra helper initially asserted that resealing
this manifest-only change must still reject; that was an incorrect expectation
because resealing restores the exact original manifest when artifact bytes
are unchanged. The failed helper assertion and corrected restoration check
are preserved in `package-verification-observations.json`. No implementation
or suite assertion was weakened. This receipt refers to the tested pre-receipt
anchor; the final package anchor additionally covers the receipt and this report.
