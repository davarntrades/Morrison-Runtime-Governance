"""Cross-planner divergence / agreement matrices. Run the same canonical
plan through N planners under the same governance config; record where
the verdicts diverge."""

from __future__ import annotations

from dataclasses import dataclass, field


def run_planners(planners: list, observation: dict, max_steps: int,
                  build_middleware) -> dict:
    """Run each planner through its own fresh middleware (so sandbox state
    is isolated) and return `{planner_name: RunResult}`."""
    out: dict = {}
    for p in planners:
        mw = build_middleware()
        result = mw.run(p, observation=observation, max_steps=max_steps)
        out[p.info.name] = result
    return out


def cross_planner_agreement(results: dict) -> dict:
    """For each planner pair, the fraction of (step, proposed.tool)
    decisions on which the verdict label agrees.

    Returns:
      {
        "pairs": [{"a","b","compared","agreed","agreement"}],
        "verdicts_by_planner": {name: [verdicts in step order]},
      }
    """
    verdicts_by_planner = {
        name: [r.verdict for r in res.trace.records]
        for name, res in results.items()
    }
    names = list(verdicts_by_planner)
    pairs = []
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            va, vb = verdicts_by_planner[a], verdicts_by_planner[b]
            n = min(len(va), len(vb))
            agree = sum(1 for x, y in zip(va[:n], vb[:n]) if x == y)
            pairs.append({"a": a, "b": b, "compared": n,
                          "agreed": agree,
                          "agreement": (agree / n) if n else 1.0})
    return {"pairs": pairs, "verdicts_by_planner": verdicts_by_planner}
