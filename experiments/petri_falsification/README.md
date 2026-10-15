# Prospective Petri regression harness

Integration, finite oracle, scenarios and scripted harness originate from
`8886b94bce83c95501e757eff578c3879eb464b9`. Imports are packaged here and the
integration explicitly enables the strict authority-claim envelope matching the
original oracle. Original scenario expectations are unchanged. Kernel tests
add nested-array cases beyond that historical dictionary-only oracle.

Environment: Python 3.12, inspect-ai 0.3.276, inspect-petri 3.1.1, pytest 9.1.1.
This differs from original Petri revision
`766d3842e67c573aaf7d5dffcdfb0381a35e3574` / 3.1.2.dev1; it is a prospective
compatibility test, not a recreation of that earlier environment.

```sh
python -m pip install inspect-ai==0.3.276 inspect-petri==3.1.1 pytest==9.1.1
python -m pytest -q experiments/petri_falsification/test_integration.py
python -m experiments.petri_falsification.run_offline --output /tmp/morrison-offline-new
python -m experiments.petri_falsification.run_scripted_petri --output /tmp/morrison-native-new
```

Output directories must be new. The native smoke calls Petri's audit task and
Inspect evaluation using scripted mock auditor/target/judge models, without live
model calls or external executors. Effects are ledger appends. This establishes
prospective harness operation, not live-model robustness or the source of the
original untraced construction refusal. Preserve failed runs alongside results.
