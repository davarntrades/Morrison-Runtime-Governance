"""Export the enterprise pipeline to TLA+ and cross-check the verifier.

What is being cross-checked, precisely:

  The Python verifier's REACHABILITY RESULT — the reachable state count, whether
  an unsafe state is reachable, and whether each liveness goal is reachable —
  for `enterprise_pipeline`, in control mode and in governed mode.

What is independent, and what is not:

  * The transition semantics are re-encoded in TLA+ from the declarative
    `pipeline.STAGES` table by a separate interpreter (this module), not by
    the `ActionDefinition` lambdas the verifier executes.
  * The unsafe invariants and the goals are re-written by hand as TLA+
    formulas (`_UNSAFE_TLA`, `_GOALS_TLA`), not translated from the Python
    predicates.
  * The search is TLC's, not the verifier's.
  * GOVERNANCE IS NOT RE-DERIVED. TLC cannot run Morrison. The governed spec
    takes the set of (completed-actions, action) pairs that Morrison permitted
    during the Python run as an oracle (`Permitted`). The cross-check therefore
    validates the verifier's state-space construction, invariant evaluation
    and goal accounting GIVEN Morrison's decisions; it does not validate the
    decisions.

Running TLC needs Java and `tla2tools.jar` (https://github.com/tlaplus/tlaplus).
`run_tlc` drives it and compares against `expected.json`; the finite
verification workflow does this in CI. `crosscheck_explicit` is a second,
deliberately minimal explicit-state search over the same exported data, which
runs anywhere; it is a second implementation by the same authors, NOT an
independent tool, and is labelled as such wherever it is reported.

    python -m morrison_governance.global_verification.tla_export --out DIR
    python -m morrison_governance.global_verification.tla_export --out DIR --tlc tla2tools.jar
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections import deque
from pathlib import Path
from typing import Any

from .comparison import compare_control_and_governed
from .governance import MorrisonKernelAdapter
from .pipeline import ALL_OPTIONS, STAGES, enterprise_pipeline
from .state import VerificationState
from .unsafe import DEFAULT_UNSAFE_INVARIANTS

MODULE = "EnterprisePipeline"

# VerificationState field -> (TLA+ variable, kind). Only fields the pipeline's
# effects touch; every other field stays at its default, which `_check_scope`
# verifies rather than assumes.
_VARS: dict[str, tuple[str, str]] = {
    "files_read": ("filesRead", "set"),
    "files_modified": ("filesModified", "set"),
    "secrets_accessed": ("secretsAccessed", "set"),
    "processes_running": ("processes", "set"),
    "messages_sent": ("messagesSent", "int"),
    "external_side_effects": ("externalSideEffects", "int"),
    "external_network_access": ("externalNetwork", "bool"),
    "monitoring_enabled": ("monitoringEnabled", "bool"),
    "governance_policy_mutated": ("policyMutated", "bool"),
    "secret_externalized": ("secretExternalized", "bool"),
}

# U1..U7 written directly in TLA+ over the modelled variables. Fields the
# pipeline never changes are constants at their defaults, which makes U2 (user
# privilege), U3 (no bypass) and U4 (no persistence) identically FALSE; that is
# checked by `_check_scope`, and stated here rather than silently dropped.
_UNSAFE_TLA = {
    "U1_SECRET_LEFT_TRUST_BOUNDARY": "secretExternalized",
    "U2_UNAUTHORISED_PRIVILEGE_ESCALATION": "FALSE",   # privilege_level never changes
    "U3_GOVERNANCE_BYPASS": "FALSE",                   # governance_bypassed never changes
    "U4_UNAUTHORISED_PERSISTENCE": "FALSE",            # persistence_created never changes
    "U5_MONITORING_DISABLED": "~monitoringEnabled",    # monitoring_change_approved stays FALSE
    "U6_GOVERNANCE_POLICY_MUTATED": "policyMutated",
    "U7_UNAUTHORISED_EXTERNAL_CONSEQUENCE": "externalSideEffects > 0",
}
_GOALS_TLA = {
    "LG_REPORT_PUBLISHED_INTERNALLY": '"publish_internal" \\in done',
    "LG_PIPELINE_COMPLETED": f"StageDone({len(STAGES)})",
}


def _tla_str(value: str) -> str:
    if '"' in value or "\\" in value:
        raise ValueError(f"string not exportable to TLA+: {value!r}")
    return f'"{value}"'


def _tla_set(items) -> str:
    return "{" + ", ".join(_tla_str(i) for i in sorted(items)) + "}"


def _check_scope() -> None:
    """Refuse to export if the TLA+ encoding could silently diverge."""
    if {u.identifier for u in DEFAULT_UNSAFE_INVARIANTS} != set(_UNSAFE_TLA):
        raise ValueError("unsafe invariants changed; update _UNSAFE_TLA")
    env = enterprise_pipeline()
    if env.unsafe_invariants != DEFAULT_UNSAFE_INVARIANTS:
        raise ValueError("pipeline uses non-default invariants; not exportable")
    if {g.identifier for g in env.goals} != set(_GOALS_TLA):
        raise ValueError("pipeline goals changed; update _GOALS_TLA")
    if env.initial_states != (VerificationState(),):
        raise ValueError("pipeline initial state changed; update Init")
    for option in ALL_OPTIONS:
        for effect in option.effects:
            if effect[1] not in _VARS:
                raise ValueError(f"{option.name} touches unmodelled field {effect[1]}")
        for fld, _ in option.requires:
            if fld not in _VARS:
                raise ValueError(f"{option.name} requires unmodelled field {fld}")


def harvest(escalations: str = "deny") -> dict[str, Any]:
    """Run the Python verifier and collect the oracle and the expectations."""
    policy = None if escalations == "deny" else (lambda p, d: ("deny", "approve"))
    comparison = compare_control_and_governed(
        enterprise_pipeline(), MorrisonKernelAdapter(), escalation_policy=policy)
    governed = comparison.governed
    permitted = set()
    for edge in governed.graph.edges.values():
        if edge.executed:
            done = governed.graph.nodes[edge.source].state["actions_completed"]
            permitted.add((tuple(sorted(done)), edge.action))
    goals = {g["identifier"]: g["reachable_from_every_initial_state"]
             for g in governed.liveness.get("goals", [])}
    control_goals = {g["identifier"]: g["reachable_from_every_initial_state"]
                     for g in comparison.control.liveness.get("goals", [])}
    return {
        "escalations": escalations,
        "permitted": sorted([list(done), action] for done, action in permitted),
        "expected": {
            "control_states": comparison.control.reachable_state_count,
            "control_unsafe_reachable": comparison.control.unsafe_reachable_state_count > 0,
            "control_goals": control_goals,
            "governed_states": governed.reachable_state_count,
            "governed_unsafe_reachable": governed.unsafe_reachable_state_count > 0,
            "governed_goals": goals,
            "verdict": comparison.verdict,
        },
    }


def render_tla(permitted: list) -> str:
    _check_scope()
    names = [v for v, _ in _VARS.values()]
    stage_sets = ", ".join(_tla_set(o.name for o in opts) for _, opts in STAGES)
    init_parts = ["done = {}"]
    for fld, (var, kind) in _VARS.items():
        default = getattr(VerificationState(), fld)
        if kind == "set":
            init_parts.append(f"{var} = {_tla_set(default)}")
        elif kind == "int":
            init_parts.append(f"{var} = {int(default)}")
        else:
            init_parts.append(f"{var} = {'TRUE' if default else 'FALSE'}")
    perm = ",\n    ".join(f"<<{_tla_set(done)}, {_tla_str(action)}>>"
                          for done, action in permitted)
    lines = [
        f"---- MODULE {MODULE} ----",
        "\\* GENERATED by morrison_governance/global_verification/tla_export.py",
        "\\* from pipeline.STAGES. Do not edit; regenerate.",
        "EXTENDS Naturals, FiniteSets",
        "CONSTANT Governed",
        "VARIABLES done, " + ", ".join(names),
        "vars == <<done, " + ", ".join(names) + ">>",
        "",
        f"StageOpts == <<{stage_sets}>>",
        "StageDone(k) == StageOpts[k] \\cap done # {}",
        "",
        "\\* Morrison's decisions from the Python run: (completed actions, action)",
        "\\* pairs that executed. An oracle, not a re-derivation.",
        "Permitted == {" + ("\n    " + perm + "\n" if perm else "") + "}",
        "Allowed(a) == ~Governed \\/ <<done, a>> \\in Permitted",
        "",
        "Init == " + "\n  /\\ ".join(init_parts),
        "",
    ]
    action_names = []
    for k, (_, opts) in enumerate(STAGES, start=1):
        for option in opts:
            name = "A_" + option.name
            action_names.append(name)
            body = [f"~StageDone({k})"]
            if k > 1:
                body.append(f"StageDone({k - 1})")
            for fld, item in option.requires:
                body.append(f"{_tla_str(item)} \\in {_VARS[fld][0]}")
            body.append(f"Allowed({_tla_str(option.name)})")
            body.append(f"done' = done \\cup {{{_tla_str(option.name)}}}")
            changed = set()
            updates: dict[str, str] = {}
            for effect in option.effects:
                var, kind = _VARS[effect[1]]
                current = updates.get(var, var)
                if effect[0] == "add":
                    updates[var] = f"{current} \\cup {{{_tla_str(effect[2])}}}"
                elif effect[0] == "set":
                    updates[var] = "TRUE" if effect[2] else "FALSE"
                elif effect[0] == "inc":
                    updates[var] = f"{current} + 1"
                changed.add(var)
            body.extend(f"{var}' = {expr}" for var, expr in updates.items())
            unchanged = [v for v in names if v not in changed]
            if unchanged:
                body.append("UNCHANGED <<" + ", ".join(unchanged) + ">>")
            lines.append(f"{name} ==\n  /\\ " + "\n  /\\ ".join(body))
            lines.append("")
    lines += [
        "Next == " + "\n  \\/ ".join(action_names),
        "Spec == Init /\\ [][Next]_vars",
        "",
        "\\* U1..U7, written in TLA+ (see tla_export._UNSAFE_TLA).",
        "Unsafe == " + "\n  \\/ ".join(f"({expr})" for expr in _UNSAFE_TLA.values()),
        "Safe == ~Unsafe",
    ]
    for gid, expr in _GOALS_TLA.items():
        lines.append(f"NotGoal_{gid} == ~(({expr}) /\\ Safe)")
    lines.append("====")
    return "\n".join(lines) + "\n"


def _cfg(governed: bool, invariant: str | None) -> str:
    out = ["SPECIFICATION Spec", f"CONSTANT Governed = {'TRUE' if governed else 'FALSE'}",
           "CHECK_DEADLOCK FALSE"]
    if invariant:
        out.append(f"INVARIANT {invariant}")
    return "\n".join(out) + "\n"


def write_bundle(out: Path, escalations: str = "deny") -> dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    data = harvest(escalations)
    (out / f"{MODULE}.tla").write_text(render_tla(data["permitted"]), encoding="utf-8")
    runs = {
        "control_count": (False, None),
        "control_safety": (False, "Safe"),
        "governed_safety": (True, "Safe"),
    }
    for gid in _GOALS_TLA:
        runs[f"governed_goal_{gid}"] = (True, f"NotGoal_{gid}")
        runs[f"control_goal_{gid}"] = (False, f"NotGoal_{gid}")
    for name, (governed, inv) in runs.items():
        (out / f"{name}.cfg").write_text(_cfg(governed, inv), encoding="utf-8")
    model = {
        "stages": [[o.name for o in opts] for _, opts in STAGES],
        "options": {o.name: {"effects": [list(e) for e in o.effects],
                             "requires": [list(r) for r in o.requires]}
                    for o in ALL_OPTIONS},
        "permitted": data["permitted"],
    }
    (out / "model.json").write_text(json.dumps(model, indent=1, sort_keys=True) + "\n",
                                    encoding="utf-8")
    (out / "expected.json").write_text(
        json.dumps(data["expected"], indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return data


# ── second implementation (NOT an independent tool) ──────────────────────

def crosscheck_explicit(model: dict[str, Any], governed: bool) -> dict[str, Any]:
    """Explicit-state BFS over the exported model data, written separately from
    the verifier (plain dicts, no ActionDefinition, no kernel)."""
    stages = model["stages"]
    options = model["options"]
    permitted = {(tuple(sorted(d)), a) for d, a in model["permitted"]}
    stage_of = {name: k for k, names in enumerate(stages) for name in names}
    sets = ("files_read", "files_modified", "secrets_accessed", "processes_running")
    init = {"done": frozenset(), **{f: frozenset() for f in sets},
            "messages_sent": 0, "external_side_effects": 0,
            "external_network_access": False, "monitoring_enabled": True,
            "governance_policy_mutated": False, "secret_externalized": False}

    def key(s):
        return tuple(sorted((k, tuple(sorted(v)) if isinstance(v, frozenset) else v)
                            for k, v in s.items()))

    def unsafe(s):
        return (s["secret_externalized"] or not s["monitoring_enabled"]
                or s["governance_policy_mutated"] or s["external_side_effects"] > 0)

    def stage_done(s, k):
        return any(n in s["done"] for n in stages[k])

    seen = {key(init): init}
    queue = deque([init])
    while queue:
        s = queue.popleft()
        for name, spec in options.items():
            k = stage_of[name]
            if stage_done(s, k) or (k > 0 and not stage_done(s, k - 1)):
                continue
            if any(item not in s[fld] for fld, item in spec["requires"]):
                continue
            if governed and (tuple(sorted(s["done"])), name) not in permitted:
                continue
            t = dict(s)
            t["done"] = s["done"] | {name}
            for effect in spec["effects"]:
                if effect[0] == "add":
                    t[effect[1]] = t[effect[1]] | {effect[2]}
                elif effect[0] == "set":
                    t[effect[1]] = effect[2]
                else:
                    t[effect[1]] = t[effect[1]] + 1
            if key(t) not in seen:
                seen[key(t)] = t
                queue.append(t)
    states = list(seen.values())
    last = len(stages) - 1
    return {
        "states": len(states),
        "unsafe_reachable": any(unsafe(s) for s in states),
        "goals": {
            "LG_REPORT_PUBLISHED_INTERNALLY": any(
                "publish_internal" in s["done"] and not unsafe(s) for s in states),
            "LG_PIPELINE_COMPLETED": any(
                stage_done(s, last) and not unsafe(s) for s in states),
        },
    }


# ── TLC ──────────────────────────────────────────────────────────────────

_DISTINCT = re.compile(r"(\d+) distinct states found")


def run_tlc(bundle: Path, jar: Path, java: str = "java") -> dict[str, Any]:
    """Run TLC on every config in the bundle and compare with expected.json."""
    expected = json.loads((bundle / "expected.json").read_text(encoding="utf-8"))
    results: dict[str, Any] = {}
    for cfg in sorted(bundle.glob("*.cfg")):
        proc = subprocess.run(
            [java, "-XX:+UseParallelGC", "-cp", str(jar), "tlc2.TLC", "-workers", "1",
             "-config", cfg.name, f"{MODULE}.tla"],
            cwd=bundle, capture_output=True, text=True, timeout=1800, check=False)
        text = proc.stdout + proc.stderr
        counts = _DISTINCT.findall(text)
        results[cfg.stem] = {
            "violated": "is violated" in text,
            "distinct_states": int(counts[-1]) if counts else None,
            "exit_code": proc.returncode,
            # Kept so a disagreement can be diagnosed from the CI log alone.
            "output_tail": text[-3000:],
        }
    checks = {
        "control_state_count":
            results["control_count"]["distinct_states"] == expected["control_states"],
        "governed_state_count":
            results["governed_safety"]["distinct_states"] == expected["governed_states"],
        "control_unsafe_reachable":
            results["control_safety"]["violated"] == expected["control_unsafe_reachable"],
        "governed_unsafe_reachable":
            results["governed_safety"]["violated"] == expected["governed_unsafe_reachable"],
    }
    for gid, reachable in expected["governed_goals"].items():
        checks[f"governed_goal_{gid}"] = results[f"governed_goal_{gid}"]["violated"] == reachable
    for gid, reachable in expected["control_goals"].items():
        checks[f"control_goal_{gid}"] = results[f"control_goal_{gid}"]["violated"] == reachable
    return {"tlc": results, "checks": checks, "agree": all(checks.values())}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--escalations", choices=("deny", "deny-and-approve"), default="deny")
    parser.add_argument("--tlc", type=Path, help="path to tla2tools.jar; runs TLC if given")
    args = parser.parse_args(argv)
    data = write_bundle(args.out, args.escalations)
    model = json.loads((args.out / "model.json").read_text(encoding="utf-8"))
    expected = data["expected"]
    second = {"control": crosscheck_explicit(model, governed=False),
              "governed": crosscheck_explicit(model, governed=True)}
    second_agree = (
        second["control"]["states"] == expected["control_states"]
        and second["governed"]["states"] == expected["governed_states"]
        and second["control"]["unsafe_reachable"] == expected["control_unsafe_reachable"]
        and second["governed"]["unsafe_reachable"] == expected["governed_unsafe_reachable"]
        and second["governed"]["goals"] == expected["governed_goals"]
        and second["control"]["goals"] == expected["control_goals"])
    report: dict[str, Any] = {"expected": expected,
                              "second_implementation": {**second, "agree": second_agree,
                                                        "independent": False}}
    status = 0 if second_agree else 1
    if args.tlc:
        tlc = run_tlc(args.out, args.tlc)
        report["tlc"] = tlc
        status = status or (0 if tlc["agree"] else 1)
        if not tlc["agree"]:
            # Artifact downloads are not always available; put the evidence in
            # the log: which checks disagreed, and what TLC actually said.
            print(json.dumps(tlc["checks"], indent=1))
            for name, res in tlc["tlc"].items():
                print(f"--- TLC {name}: exit={res['exit_code']} "
                      f"distinct={res['distinct_states']} violated={res['violated']}")
                print(res["output_tail"])
    (args.out / "crosscheck.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"verdict": expected["verdict"],
                      "second_implementation_agrees": second_agree,
                      "tlc_agrees": report.get("tlc", {}).get("agree", "not run")}))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
