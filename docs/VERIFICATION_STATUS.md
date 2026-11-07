# Verification status of public claims

This page lists public claims about Morrison Runtime Governance whose status is
not yet verified, and what has to happen before each can be relied on. It
exists so that enterprise-facing documents can point to one honest status
instead of restating unverified figures. If a claim is not on this page and is
not backed by code or a results file in this repository, treat it as
unverified.

| Claim | Status | Blocking item |
|---|---|---|
| 129,857 evaluations, 0 FP / 0 FN | Historical, unverified | Recover the harness, dataset, code path and records |
| 160/160 healthcare, 0 FP / 0 FN | Historical, unverified | Recover the harness and results |
| UK patent GB2600765.8 | Application reference; legal status unconfirmed | Check the UK IPO register |
| Kalaris Labs reproduction | Collaboration disclosed; details held externally | Document any financial, contractual or organisational arrangements where relevant |
| `pip install morrison-governance` | Unverified; package does not build | See [PACKAGING_STATUS.md](PACKAGING_STATUS.md) |
| Hosted console data handling | Pending technical verification | Publish a data-processing and retention policy |
| Customer deployment enforcement | Deployment artifact not selected | Audit the chosen artifact |

## Historical evaluation figures

**129,857 governance evaluations with zero false positives and zero false
negatives** (previously in `README.md`, `ENTERPRISE.md` and
`deployable infrastructure repository.md`, with an "Accuracy 100%" badge).

- **Origin.** Testing of the original Morrison governance layer during initial
  development.
- **Code path.** The figure first appears in this repository in commit
  `6da704e` (2026-05-22). `GovernanceKernel`, the current enforcement path, was
  introduced in commit `39565a9` (2026-09-09). The figure therefore did not
  measure the current kernel. The exact harness and code path have not been
  identified.
- **Records.** No harness, dataset or results file behind the figure has been
  found in this repository. The per-model table (GPT-4o 9,095; Qwen2.5-0.5B
  10,000; Qwen2.5-7B 438; Llama-3.1-8B 318; banking benchmark 10,000; stress
  test 100,000) exists only as prose.
- **Status.** Unverified historical record. Kept in `ENTERPRISE.md` §6 and in
  `deployable infrastructure repository.md`, labelled as such. It is not a
  current performance claim and must not be quoted as one.

**160 healthcare scenarios, 160/160 correct, 0 FP / 0 FN** (`ENTERPRISE.md`,
`Pricing Strategy.md`, `deployable infrastructure repository.md`). Same status:
no harness or results file found in this repository; labelled as historical
and unverified.

**Reproducible current results.** These come from different test conditions
and are not substitutes for the historical figures. Each must be quoted with its
own conditions:

- AgentDojo, offline oracle mode (model-free, fully compromised agent):
  [runtime_eval/results/AGENTDOJO_BENCHMARK.md](../runtime_eval/results/AGENTDOJO_BENCHMARK.md).
- AgentDojo live, Claude Opus 5.5, banking sample:
  [runtime_eval/results/AGENTDOJO_LIVE_OPUS55.md](../runtime_eval/results/AGENTDOJO_LIVE_OPUS55.md).
- ARSB v0 is frozen historical research and its leaderboard is withdrawn
  (see [issue #39](https://github.com/davarntrades/Morrison-Runtime-Governance/issues/39)).

## Patent status

GB2600765.8 is a UK patent **application** reference. Its current legal status
(pending, published, granted, terminated) has not been confirmed against the UK
IPO register. Documents now describe it as a "UK patent application". No
document should describe it as a granted patent until the register confirms a
grant.

`Morrison Runtime Governance — Enterprise Pilot.md` also lists GB2602013.1,
GB2602072.7 and GB2602332.5. These are in UK application-number format and are
now described as applications; their status has not been checked either.

## Kalaris Labs collaboration

Kalaris Labs and Resurrection Tech have a technical research collaboration. It
has covered reproduction of bounded experimental results, adversarial
evaluation, identification of architectural weaknesses and publication of
technical findings. The README now discloses the collaboration and attributes
the reruns and articles to Kalaris Labs without calling them unaffiliated
third-party work. Any financial, contractual or organisational arrangements are
to be documented separately where relevant.

## Hosted console data handling

The browser console at resurrection-tech.com accepts user-supplied tool-call
sequences. Its data inventory, storage locations, retention periods, access
controls and deletion mechanisms are **pending technical verification**. A
documented data-processing and retention policy will be established before
customer production use. Until it is published, the README advises against
submitting production data, credentials, personal data or confidential
workflows.

## Customer deployment artifact

The final customer deployment artifact has not been selected. The options are a
customer-controlled library integration and a separately deployed governance
service. The chosen path will undergo its own security and enforcement audit.
The known limits of the library in this repository are listed under
[Enforcement boundary](../morrison_governance/DEPLOYMENT.md#enforcement-boundary-read-before-deploying).

## Items for legal review

These were deliberately **not** changed in this documentation pass:

- `License.md:61`, `License.md:77-78`, `License.md:107` describe GB2600765.8 as
  a "UK Patent" and say Resurrection Tech "owns the patents". `License.md` was
  left unchanged; its wording needs legal review against the application's
  actual status.
- `README_PARTNERSHIPS.md:54-55` and `README_PARTNERSHIPS.md:108-109` reserve
  rights in "UK Patent GB2600765.8". These are partner terms, so they were left
  unchanged; the badge on the same page was corrected.
- The IP notice paragraphs in `ENTERPRISE.md`, `Pricing Strategy.md`,
  `48-Hour Runtime Safety Audit.md`, `Morrison Runtime Governance — Enterprise
  Pilot.md` and `deployable infrastructure repository.md` were changed from "UK
  Patent" to "UK patent application" as a terminology correction. Legal should
  confirm that wording.
- Compatibility between the public repository licence and the separate
  enterprise commercial agreement.
- Safe-harbour wording for the draft [SECURITY.md](../SECURITY.md).
