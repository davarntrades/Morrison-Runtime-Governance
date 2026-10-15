# Challenge ARSB v0 — invitation to independent evaluators

ARSB v0 was written by the same people who evaluate Morrison Runtime Governance, one of its systems under test.
That conflict of interest is the reason for this invitation: the benchmark should be broken by someone who did not
write it, and anything it gets wrong should be found before its results are used.

## What to challenge

Anything, but especially:

1. **Threat models** (`SPEC.md` §2). Missing attacker capabilities; scripted attacks that are unrealistic; families
   that are trivially passed or trivially failed by construction.
2. **Competitor adapters** (`adapters/progent_adapter.py`, `adapters/camel_adapter.py`). Translations that misstate
   what Progent or CaMeL can enforce, either way: under-translation that makes them fail, or over-translation that
   adds enforcement they do not have. The authors of Progent and CaMeL are especially welcome.
3. **The Morrison adapter** (`adapters/morrison.py`). Anything that gives Morrison help another system does not get.
4. **Scoring** (`core/score.py`, `SPEC.md` §7–8). Classification rules, the utility floor, Pareto leadership, the
   treatment of UNSUPPORTED, and whether any rule favours a particular architecture.
5. **Ground truth** (`core/fixture.py`, `core/predicates.py`). Predicates that miss a prohibited state or flag a
   legitimate one; fixture semantics that remove attacks by construction.
6. **Hidden scenarios** (below). Scenarios that a current leader fails.

## Hidden-scenario protocol

1. Write scenarios in the v0 format (`SPEC.md` §5; see `scenarios/*.json`) against tag `arsb-v0-dev`, without
   coordinating with the maintainers.
2. Publish, before submitting the files, a commit or issue containing only the SHA-256 of each scenario file.
3. Submit the files. The maintainers run every system under test — including whatever Morrison version is current —
   and publish the results before any adapter or system change is made in response.
4. The scenarios are then revealed and their hashes checked against step 2.
5. Hidden scenarios become part of the next release's held-out set; they are not added to v0.

A hidden scenario counts against a system only if the ungoverned baseline reaches its prohibited state (otherwise it
is INCONCLUSIVE, as in the spec).

## What counts as a finding

- A system classified DEMONSTRATED_WITHIN_SCOPE on a property it does not have, or VIOLATED on one it does.
- An adapter translation that is wrong for its system, with the corrected translation.
- A scoring or classification rule that changes a reported leader when corrected.
- A hidden scenario in which a reported leader is VIOLATED.

Findings are recorded in the next release's notes with credit, whether or not they favour Morrison.

## Rules

- Do not modify frozen files to make a point; propose changes for v1. `python -m arsb.freeze check` must pass on any
  result you report against v0.
- No live-model evaluations are funded by this invitation; scripted scenarios only, unless agreed separately.
- Report through a GitHub issue on this repository titled `ARSB challenge: ...`.
