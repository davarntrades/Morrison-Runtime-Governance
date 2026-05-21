"""runtime_eval CLI — `python -m runtime_eval evaluate ...`."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from runtime_eval.domains import get_preset
from runtime_eval.governance import (
    OmegaRegistry, RuntimeGovernanceMiddleware,
)
from runtime_eval.metrics import latency_stats
from runtime_eval.planners import PLANNER_REGISTRY, get_planner
from runtime_eval.replay import TraceWriter
from runtime_eval.sandbox import SandboxExecutor, ToolSimulator


def _cmd_evaluate(args: argparse.Namespace) -> int:
    preset = get_preset(args.preset) if args.preset else None
    domains = (preset["domains"] if preset else args.domain.split(","))
    observation = (preset["observation"]
                   if preset else (json.loads(args.observation)
                                   if args.observation else {}))
    max_steps = (preset["max_steps"] if preset else args.max_steps)

    governance = OmegaRegistry(domains=domains).build()
    sandbox = SandboxExecutor(simulator=ToolSimulator())
    middleware = RuntimeGovernanceMiddleware(governance=governance,
                                              sandbox=sandbox)

    planner_kwargs = json.loads(args.planner_args) if args.planner_args else {}
    planner = get_planner(args.planner, **planner_kwargs)

    result = middleware.run(planner, observation=observation,
                             max_steps=max_steps)

    if args.trace:
        TraceWriter(args.trace).write(
            result.trace,
            extra_header={"planner": planner.info.name,
                           "model_id": planner.info.model_id,
                           "domains": domains})

    lat = latency_stats(r.latency_ms for r in result.trace.records)
    out = {
        "planner": planner.info.name,
        "model_id": planner.info.model_id,
        "domains": domains,
        "summary": result.trace.summary(),
        "latency": lat.as_dict(),
    }
    print(json.dumps(out, indent=2))
    return 0 if result.trace.fail_closed_holds() else 1


def _cmd_list(args: argparse.Namespace) -> int:
    out = {
        "planners": sorted(PLANNER_REGISTRY),
        "domains": OmegaRegistry.known(),
    }
    print(json.dumps(out, indent=2))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="runtime_eval")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ev = sub.add_parser("evaluate")
    ev.add_argument("--planner", required=True,
                     help="planner name from the registry (see `list`)")
    ev.add_argument("--planner-args", default="",
                     help='JSON of kwargs for the planner factory')
    ev.add_argument("--domain", default="finance",
                     help="comma-separated domain labels")
    ev.add_argument("--preset", default="",
                     help="domain preset name (overrides --domain)")
    ev.add_argument("--observation", default="",
                     help="JSON observation seed")
    ev.add_argument("--max-steps", type=int, default=8)
    ev.add_argument("--trace", default="",
                     help="path to write JSONL replay trace")
    ev.set_defaults(func=_cmd_evaluate)

    ls = sub.add_parser("list")
    ls.set_defaults(func=_cmd_list)

    ns = ap.parse_args(argv)
    return ns.func(ns)


if __name__ == "__main__":
    sys.exit(main())
