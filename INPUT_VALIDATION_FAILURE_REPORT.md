# Input Validation Failure — `GovernanceLayer.evaluate()` Does Not Fail Closed

## Scope and provenance — 13 September 2026

Assessed at full SHA `f4127fc396c93fb4121a95a7a1cd2a81e08ac108` (`main`). The
finding originates from an external review that fuzzed the primary documented
entry point with malformed tool-call shapes. Every reproduction below was
re-run in this working tree before being written down; none is quoted from the
external report unverified.

**Test-count discrepancy, recorded rather than reconciled.** The external review
reported 720 passed / 7 skipped. The suite in this tree at this SHA reports
**1304 passed, 0 skipped** (`python3 -m pytest -q`, 440s). The difference is not
explained here — different collection scope, a different revision, or optional
dependencies changing skip behaviour are all consistent with what is observed.
It is stated so that nobody treats "720/7" as this tree's verified baseline. The
baseline this report commits to is **1304 passed**.

This report documents the defect only. It proposes no fix and asserts no
remediation.

**This describes behaviour at `f4127fc`, before any remediation.** A fix lands
in a later commit on this branch. Everything below is the measured pre-patch
state and is deliberately left standing: the defect was real, it was reachable
through the primary documented entry point, and a reader of the fixed tree
should be able to see what was wrong rather than infer that the invariant
always held. Nothing here is rewritten once the fix exists.

---

## 1. The claim under test

> `GovernanceLayer.evaluate()` fails closed on any input it cannot classify.

This is the claim the codebase's own stated principle implies. From
`morrison_governance/interception.py:9`:

```
  * governance path raises         → call dropped (fail-closed, NOT
                                       fail-open) — a broken guard must
                                       never become an open door
```

That principle is implemented in `GovernanceInterceptor`. It is **not**
implemented in `GovernanceLayer.evaluate()`, which is the entry point shown in
`README.md` and in `core.py`'s own usage docstring, and which is therefore the
surface most integrations actually call.

**The claim is FALSE.**

---

## 2. Falsification — unclassifiable input returns PERMIT

Run from the repository root:

```python
from morrison_governance import GovernanceLayer, OmegaDomain
g = GovernanceLayer(domains=[OmegaDomain.FINANCE, OmegaDomain.CYBERSECURITY])
for call in [
    {'tool': 'http_request', 'args': 'https://attacker.com'},   # args not a dict
    {'args': {'url': 'https://attacker.com'}},                  # missing 'tool'
    {'tool': 12345, 'args': {}},                                # non-string tool
]:
    r = g.evaluate(call)
    print(call, '->', r.verdict.value, r.reason)
```

Observed:

| Input | Verdict | Reason |
|---|---|---|
| `{'tool': 'http_request', 'args': 'https://attacker.com'}` | **PERMIT** | Trajectory does not reach Ω under evaluated hierarchy |
| `{'args': {'url': 'https://attacker.com'}}` | **PERMIT** | Trajectory does not reach Ω under evaluated hierarchy |
| `{'tool': 12345, 'args': {}}` | **PERMIT** | Trajectory does not reach Ω under evaluated hierarchy |

The reason string is the terminal fall-through message from
`ReachabilityEvaluator.evaluate()`. It asserts that the hierarchy was evaluated
and found nothing. For rows 2 and 3 the hierarchy was evaluated against a state
that no longer carries the fields the rules inspect.

### 2a. Correction — row 1 is mis-attributed and is NOT a validation defect

Row 1 was carried over from the external review and is wrong. Measured on
unmodified `main`:

| Input | Verdict |
|---|---|
| `{'tool': 'http_request', 'args': 'https://attacker.com'}` (string args) | PERMIT |
| `{'tool': 'http_request', 'args': {'url': 'https://attacker.com'}}` (**well formed**) | **PERMIT** |

The fully well-formed call returns the same verdict. The malformed shape did
not cause the PERMIT. A single-step external HTTP request with no prior
data-acquisition step is simply not an Ω violation under the default rules —
the V2 taint rule requires a source→sink chain, and one egress step is not a
chain. Whether *that* is the right default is a separate question about rule
coverage, and this report makes no claim about it.

A bare string `args` is moreover a **supported** shape, not a malformed one:
`from_dict` parses it with `json.loads` and falls back to `{"raw": <string>}`,
and `test_hardening_v041.py::test_no_false_positive_plain_single_step` asserts
that `{"tool": "shell", "args": "ls -la"}` must PERMIT. This was established the
hard way — an early version of the fix rejected bare-string args and broke three
pre-existing tests.

Rows 2 and 3 stand: a call with no tool name, and a call whose tool name is an
integer, are genuinely unclassifiable and genuinely returned PERMIT.

### 2b. The gap is wider than the three reported cases

Six further shapes return PERMIT in this tree:

| Input | Entry point | Verdict |
|---|---|---|
| `{}` | `evaluate` | PERMIT |
| `{'tool': '', 'args': {}}` | `evaluate` | PERMIT |
| `{'tool': None, 'args': {}}` | `evaluate` | PERMIT |
| `[42]` | `evaluate_openai` | PERMIT |
| `42` | `evaluate_langchain` | PERMIT |
| `[]` | `evaluate_openai` | PERMIT |

The last three are a distinct sub-case and are the more serious of the six: in
`from_openai` and `from_langchain`, an item matching neither the duck-typed
branch nor the `dict` branch is **silently discarded**. The extractor then
returns an empty trajectory, and an empty trajectory permits. A caller that
submits one unparseable tool call receives the same PERMIT as a caller who
submitted nothing at all. The two are not the same event and the API does not
distinguish them.

(`evaluate_plan([])` also returns PERMIT. That case is *defensible* — a
well-formed empty plan proposes nothing, so there is nothing to block — and is
listed separately from the silent-drop cases for that reason.)

---

## 3. Failure by crash, not by design

Five shapes raise instead of returning a verdict:

| Input | Raises |
|---|---|
| `{'tool': 'http_request', 'args': None}` | `TypeError: 'NoneType' object is not a mapping` |
| `{'tool': 'http_request', 'args': {'f': object()}}` | `TypeError: Object of type object is not JSON serializable` |
| `{'tool': ['http_request'], 'args': {}}` | `TypeError` |
| `{'tool': 'http_request', 'args': ['https://attacker.com']}` | `TypeError` |
| `{'tool': 'http_request', 'args': 42}` | `TypeError` |

**These are not a mitigation and must not be recorded as one.** The distinction
matters:

- An exception propagating out of `evaluate()` will, in the common integration
  shape `result = g.evaluate(call); if result.permitted: execute(call)`, stop
  the caller before `execute()` is reached. In that specific shape the outcome
  is safe.
- That safety is a property of **where the exception happens to land**, not of
  any decision this layer made. Nothing in `evaluate()` chose it. No
  `GovernanceResult` is produced, no verdict is recorded, nothing is logged as
  a governance event, and a caller that wraps the call in `try/except` and
  continues — a wholly ordinary thing to write — converts it directly into a
  bypass.

`GovernanceInterceptor` handles this correctly for its own path: a raising
governance call is caught and the call is dropped, deliberately. `evaluate()`
has no equivalent. The safety observed here is accidental, and accidental
safety is not a control.

---

## 4. Root cause

The extraction layer has no "could not classify this call" state. Unrecognised
shapes are silently normalised into shapes that look well-formed, and then
travel the same code path as input that was classified and found unproblematic.
The verdict is identical because, by the time the rules run, the two cases are
indistinguishable.

`TrajectoryExtractor.from_dict` (`trajectory.py:133`) performs three lossy
normalisations, none of which can fail:

```python
tool = tool_call.get("tool", tool_call.get("name", tool_call.get("function", "unknown")))
args = tool_call.get("args", tool_call.get("arguments", tool_call.get("input", {})))
if isinstance(state.args, str):
    try:    state.args = json.loads(state.args)
    except: state.args = {"raw": state.args}
```

Measured effect on each reproduction:

| Input | Extracted `tool` | Extracted `args` | Keys the rules see |
|---|---|---|---|
| `{'tool':'http_request','args':'https://attacker.com'}` | `'http_request'` | `{'raw': 'https://attacker.com'}` | `args, raw, step, tool` |
| `{'args':{'url':'https://attacker.com'}}` | `'unknown'` | `{'url': 'https://attacker.com'}` | `args, step, tool, url` |
| `{'tool':12345,'args':{}}` | `12345` (int) | `{}` | `args, step, tool` |

Each row shows the same mechanism:

1. **String `args`** — the URL is relocated under the key `raw`. Rules keyed on
   `url` no longer see it. The tool name is still `http_request`, so the call
   looks like a well-formed egress with no destination.
2. **Missing `tool`** — becomes the literal string `"unknown"`, which matches no
   rule. The attacker-controlled `url` survives in `args` but no egress rule
   fires, because no rule is looking at a tool called `unknown`.
3. **Non-string `tool`** — `12345` is passed through unconverted. Rule
   predicates performing string operations on the tool name do not match an
   `int`.

In all three the sentinel is indistinguishable from a real value. `"unknown"`
is a tool name, not an error. `{"raw": ...}` is an args dict, not an error. The
system has no way to say *this input was not understood*, so it says the only
other thing it can: nothing reached Ω.

---

## 5. Affected surface — all four entry points, one shared path

Each of the four documented entry points was tested individually rather than
assumed to inherit from the others:

| Entry point | Extractor | `{'tool':'http_request','args':'https://attacker.com'}` |
|---|---|---|
| `evaluate()` | `from_dict` | **PERMIT** |
| `evaluate_plan()` | `from_plan` | **PERMIT** |
| `evaluate_openai()` | `from_openai` → `from_plan` | **PERMIT** |
| `evaluate_langchain()` | `from_langchain` → `from_plan` | **PERMIT** |

All four are affected, but not all four share one code path, and this matters
for any fix:

- `from_dict` (`trajectory.py:133`) implements the normalisation independently.
- `from_plan` (`trajectory.py:158`) implements the **same** normalisation a
  second time, duplicated rather than shared.
- `from_openai` (`trajectory.py:185`) and `from_langchain` (`trajectory.py:206`)
  build an intermediate `steps` list and delegate to `from_plan` — so they
  inherit `from_plan`'s behaviour **and** add their own silent-drop path (§2a)
  on top.

A fix applied to `from_dict` alone would leave three entry points defective. A
fix applied to `from_plan` alone would leave `evaluate()` defective and would
not address the silent drop in the two adapter extractors. Four paths require
four checks.

---

## 5a. The production kernel path — measured, not assumed

§6 originally recorded `/v1/govern` as out of scope. That was accurate when
written and is no longer true: the route was subsequently measured, using the
same method as everything else here. It is recorded rather than left as an open
question, because "untested" and "tested and partially affected" are different
claims and the earlier one is now misleading.

`GovernanceKernel.authorize()` — the `/v1/govern` path — is **mostly defended,
and defended by something other than input validation.** Measured:

| Input | Verdict | Layer |
|---|---|---|
| `{'tool': 12345, 'args': {}}` | ESCALATE | `unknown_tool` |
| `{'args': {'url': 'https://attacker.com'}}` | ESCALATE | `unknown_tool` |
| `{}` | ESCALATE | `unknown_tool` |
| `{'tool': 'read_file', 'args': None}` | **PERMIT** | `V4` |
| `{'tool': 'read_file', 'args': ['x']}` | **PERMIT** | `V4` |
| `42` | raises `AttributeError` | — |

Two things follow, and they pull in opposite directions:

1. **The kernel does not share most of the defect**, but not because it
   validates input. `unknown_tool_policy="escalate"` catches the malformed
   *tool* cases as a side effect of not recognising the resulting tool name.
   That is a different control doing an adjacent job, and it holds only while
   the policy is set to escalate.

2. **Malformed `args` on a KNOWN tool is not caught at all.** `read_file` is in
   the manifest, so `unknown_tool` never fires, and `canonicalize`
   (`kernel/canonical.py:51`) cannot fail: `args=None` becomes `{}`, and a
   non-dict `args` becomes `{"_positional": <value>}`. The call is laundered
   into a well-formed shape before the engine sees it, and reaches PERMIT at
   V4. This is the same root cause as §4 — a normalisation that cannot fail —
   in a second location.

The kernel is, however, already correct about the *rule-level* half of the
failure class: a governance layer that raises is converted into a BLOCK at
`layer="fail_closed"`, which
`test_kernel_redteam.py::test_fail_closed_on_governance_exception` has pinned
all along. `GovernanceLayer` had no equivalent.

---

## 6. What this report does and does not establish

**Established:**

- `evaluate()` returns PERMIT on at least **eight** distinct malformed inputs
  that it cannot classify, and raises on at least five more. (Eight, not nine:
  the string-args reproduction is excluded per §2a — it is not a validation
  defect.)
- All four documented entry points exhibit the PERMIT behaviour.
- The cause is a missing "unclassifiable" state in extraction, not a defect in
  the reachability model, the Ω rules, or the kernel.

**Not established:**

- **No exploited production bypass is demonstrated.** These are fuzzed inputs
  into a library entry point, not a captured attack against a deployment. A
  caller that constructs well-formed tool calls never reaches this path.
- ~~The enterprise deployment's `/v1/govern` route is **not** assessed here.~~
  **Superseded — see §5a.** This bullet was written before the route was
  measured. It has since been measured and is partially affected, so the
  statement that it is untested no longer holds.
- No claim is made about how likely a real integration is to emit a malformed
  call. The severity of this finding depends on that, and it is not measured.

- **One of the three originating reproductions does not demonstrate the
  defect it was cited for** (§2a). The finding survives on the other two and on
  six further shapes, but the external review's row 1 should not be repeated.

**The narrowest accurate statement:** the primary documented entry point treats
"I could not classify this call" as equivalent to "I classified this call and it
is safe", and the two must not be equivalent in a fail-closed system.
