"""Run the whole falsification study and emit RESULTS.json.

    python3 -m research.falsification.independent_authority.run_study
"""

from __future__ import annotations

import json
import pathlib
import sys

from . import h1_adversarial, h1_baseline, h2_adversarial, h2_evidence, matrix2x2


def build() -> dict:
    return {
        "study": "Independent Authority Falsification Study",
        "h1_baseline": h1_baseline.run_baseline(),
        "h1_adversarial": h1_adversarial.run(),
        "h2_enumeration_omit_capable": h2_evidence.enumerate_all(compromise_can_omit=True),
        "h2_enumeration_fabricate_only": h2_evidence.enumerate_all(compromise_can_omit=False),
        "h2_ordering": h2_adversarial.run(),
        "matrix_2x2": matrix2x2.run(),
    }


def main() -> int:
    data = build()
    out = pathlib.Path(__file__).parent / "RESULTS.json"
    out.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")

    b = data["h1_baseline"]
    a = data["h1_adversarial"]
    e = data["h2_enumeration_omit_capable"]
    m = data["matrix_2x2"]["cells"]["D_exec_independent_evidence"]

    print("H1 control  : reachable=%d  omega=%d" % (
        b["control"]["reachable_states"], b["control"]["reachable_omega_states"]))
    print("H1 governed : reachable=%d  omega=%d  capability_preserved=%s" % (
        b["governed_oracle"]["reachable_states"],
        b["governed_oracle"]["reachable_omega_states"],
        b["admissible_capability_preserved"]["all_admissible_preserved"]))
    print("H1 adversarial: %d/%d falsify, categories=%s" % (
        a["falsifying"], a["total_attacks"], sorted(a["by_category"])))
    print("H2 enumeration: %d/%d hold, %d fail, breakers=%s" % (
        e["property_holds"], e["total_combinations"], e["property_fails"],
        e["single_faults_that_break_alone"]))
    print("2x2 cell D  : omega=%d  undetected_divergence=%s" % (
        m["prohibited_reachability"], m["undetected_reality_divergence"]))
    print("\nwrote %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
