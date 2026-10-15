"""Freeze integrity and result verification for ARSB releases.

    python -m arsb.freeze write                  # (release author) record FREEZE.json
    python -m arsb.freeze check                  # benchmark-defining files unchanged?
    python -m arsb.freeze verify NEW.json        # does a rerun reproduce the frozen outcomes?

Benchmark-defining files (spec, harness, scorer, scenarios, reference baselines)
must never change within a release. Adapters for third-party systems are frozen
too, but listed separately: an adapter may be revised only to translate a
capability the system under test has gained, and the revision must be reported
next to any result produced with it.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FREEZE = ROOT / "FREEZE.json"
BENCHMARK = ["SPEC.md", "__init__.py", "__main__.py", "freeze.py",
             "core/__init__.py", "core/adapter.py", "core/fixture.py", "core/policy.py",
             "core/predicates.py", "core/runner.py", "core/score.py",
             "adapters/__init__.py", "adapters/baselines.py", "adapters/reference_provenance.py"]
ADAPTERS = ["adapters/morrison.py", "adapters/progent_adapter.py", "adapters/camel_adapter.py"]


def _files(group):
    out = list(group)
    if group is BENCHMARK:
        out += sorted(str(p.relative_to(ROOT)) for p in (ROOT / "scenarios").glob("*.json"))
        out += ["scenarios/_build.py"]
    return out


def _digest(rel):
    return hashlib.sha256((ROOT / rel).read_bytes()).hexdigest()


def write(release: str) -> dict:
    data = {"release": release,
            "benchmark": {f: _digest(f) for f in _files(BENCHMARK)},
            "adapters": {f: _digest(f) for f in ADAPTERS}}
    FREEZE.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")
    return data


def check() -> dict:
    frozen = json.loads(FREEZE.read_text())
    report = {"release": frozen["release"], "benchmark_changed": [], "adapters_changed": []}
    for group, key in ((BENCHMARK, "benchmark"), (ADAPTERS, "adapters")):
        current = set(_files(group))
        for f, h in frozen[key].items():
            if f not in current or not (ROOT / f).exists() or _digest(f) != h:
                report[f"{key}_changed"].append(f)
        report[f"{key}_changed"] += sorted(current - set(frozen[key]))
    return report


def _outcomes(path) -> dict:
    d = json.loads(Path(path).read_text())
    return {sut: {sid: {"classification": r["classification"], "unsupported": r.get("unsupported"),
                        "violated": [x.get("violated") for x in r["reps"]],
                        "legitimate": [x.get("legitimate") for x in r["reps"]]}
                  for sid, r in per.items()}
            for sut, per in d["results"].items()}


def verify(new_path, frozen_path=ROOT / "results/v0/run1/arsb-results.json") -> dict:
    a, b = _outcomes(frozen_path), _outcomes(new_path)
    diffs = []
    for sut in sorted(set(a) | set(b)):
        for sid in sorted(set(a.get(sut, {})) | set(b.get(sut, {}))):
            x, y = a.get(sut, {}).get(sid), b.get(sut, {}).get(sid)
            if x != y:
                diffs.append({"sut": sut, "scenario": sid, "frozen": x, "new": y})
    return {"identical": not diffs, "differences": diffs}


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if argv[:1] == ["write"]:
        print(json.dumps(write(argv[1] if len(argv) > 1 else "v0"), indent=1)[:400])
        return 0
    if argv[:1] == ["check"]:
        r = check()
        print(json.dumps(r, indent=1))
        return 0 if not r["benchmark_changed"] else 1
    if argv[:1] == ["verify"]:
        r = verify(argv[1], *(argv[2:3] or []))
        print(json.dumps({"identical": r["identical"], "differences": len(r["differences"])}))
        for d in r["differences"]:
            print(f"  {d['sut']:20s} {d['scenario']:8s} {d['frozen'] and d['frozen']['classification']} -> "
                  f"{d['new'] and d['new']['classification']}")
        return 0 if r["identical"] else 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
