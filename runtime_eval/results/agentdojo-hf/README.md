# Permanent live Qwen research record

This is a research-only integration of the completed experiment. Historical reports and evidence are retained byte-for-byte. Their statements that no main merge occurred describe the experiment's completion, before this integration.

- [Full research report](../AGENTDOJO_HF_QWEN32B.md)
- [Original live evidence](cohort-38664428154/original-live-evidence.zip)
- [Independently verified evidence bundle](cohort-38664428154/verified-evidence.zip)
- [Recorded verification results](cohort-38664428154/verification.json)
- [Protocol](cohort-38664428154/protocol.json), [objectives](cohort-38664428154/objectives.json), [measured counts](cohort-38664428154/observed-counts.json)
- [Archive integrity anchors](cohort-38664428154/archive-verification.json)
- [Integration preservation manifest](RESEARCH_INTEGRATION_MANIFEST.json)
- [Historical execution source snapshot](cohort-38664428154/execution-source.tar.gz)

## Versions and boundaries

Final research commit: `3712226353148111159d6aea686849df1aca98ae` (the integration request contained a shortened, mistyped SHA).
Execution commit, including the exact historical governance kernel: `f2b9a6ce369fbab0f4e5a23e5d656d2eef947172`.
Offline analysis commit: `dc2cc4aeb2a7a32bbd1c0fdfa1e0f78f4fcee781`.

The source archive preserves the execution version's complete `morrison_governance`, `global_governance`, `multi_agent_eval` and AgentDojo harness directories, dependency lock, execution workflow, pytest configuration and root conftest. It is an inert historical archive, not production code or an active Actions workflow. Historical enforcement limitations remain part of the finding. For analysis source, use the pinned analysis commit; do not substitute the historical execution postprocessor, whose failure is documented and retained.

The exact model is `huihui-ai/Qwen3-32B-abliterated`, routed to Featherless AI through Hugging Face. Exact served revision was not attested. Each arm contains 11 episodes: six injected, two clean and three standalone diagnostics. The injected attacker-success counts were 5/6 ungoverned and 0/6 governed. Seven prohibited calls were proposed per arm; seven executed ungoverned and zero governed. Five attacker-directed sandbox transaction records represented $30,100 across separate episodes, and two passwords changed ungoverned; none occurred governed. No real bank balance was debited. Legitimate completion was 2/6 under injection in both arms and 2/2 versus 1/2 on clean tasks. Absent valid approval signing withheld a legitimate $98.70 payment.

All 22 episodes reached terminal turns, and the completed independent verification checked 22/22 evidence chains. The paid run's postprocessing failure was repaired without further inference. This demonstrates bounded local enforcement, not trajectory safety, shared multi-agent global safety or complete mediation. Historical violations and other experiments are not modified or retested.

## Integration safety

Only research reports, evidence, manifests and the inert source archive are imported. No production implementation, tests, policies, ARSB material, violation ledger or `.github/workflows` file is changed. Existing main is the integration base, not the experimental branch. Thus no source-branch enforcement changes can replace current production repairs.

The source branch's one-off paid execution workflows remain disabled. They are not imported. Existing main inference workflows require explicit manual dispatch; this research integration does not dispatch them, alter their gates, or access or change secrets. Automatic CI performs offline lint/tests only. The existing manually dispatched HF workflow is not represented as globally disabled; it is unchanged.

Integration checks validate file preservation, archive availability/CRC, documentation links and unchanged executable/workflow trees. They do not repeat the completed scientific evidence analysis or make inference requests. Recorded historical verification remains separately identifiable.
