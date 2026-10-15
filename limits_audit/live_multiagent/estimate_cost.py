"""Token and cost estimate, computed before any billed call is made.

Deliberately estimated from local prompt text rather than via
`messages.count_tokens`: that endpoint is itself an API call, and the point of
this file is to price the experiment WITHOUT touching the API. A ~4 chars/token
approximation is used, then inflated by a safety factor, so the figure is an
upper bound rather than a best guess.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import agents as A

IN_PER_MTOK, OUT_PER_MTOK = 1.00, 5.00          # Haiku 4.5 list price
CHARS_PER_TOKEN = 4.0
SAFETY = 1.6                                     # upper-bound inflation

#: MEASURED, not approximated. Run 35485983996 executed 10 model-runs of
#: gpt-oss-120b (2 arms x 5 trials, each run covering both conditions) for
#: 62,465 input and 22,677 output tokens. A model-run is the unit the sweep
#: multiplies, so these per-run figures are what a projection should scale —
#: they beat the 4-chars/token guess for any open-weight model of similar
#: verbosity, and they are an observation rather than an assumption.
MEASURED_HF_IN_PER_RUN = 6247
MEASURED_HF_OUT_PER_RUN = 2268
MEASURED_SOURCE = "run 35485983996 (gpt-oss-120b, 10 model-runs)"


def approx_tokens(text: str) -> int:
    return int(len(text) / CHARS_PER_TOKEN) + 1


def estimate() -> dict:
    sys_a = approx_tokens(A.AGENT_A_SYSTEM.format(base_url="http://127.0.0.1:00000"))
    task_a = approx_tokens(A.AGENT_A_TASK)
    sys_b = approx_tokens(A.AGENT_B_SYSTEM) + approx_tokens(A.AGENT_B_TASK)

    out_per_turn = 700                           # the max_tokens cap for A
    board_growth = 60                            # board text added per turn

    # Agent A: history is resent each turn, so input grows roughly linearly.
    a_in = 0
    for turn in range(1, A.MAX_TURNS + 1):
        a_in += sys_a + task_a + board_growth * turn + out_per_turn * (turn - 1)
    a_out = out_per_turn * A.MAX_TURNS

    # Agent B: one call per condition.
    b_in, b_out = sys_b, 200

    per_condition_in = a_in + b_in
    per_condition_out = a_out + b_out
    runs = 2 * len(A.ARMS)            # (UNGOVERNED + GOVERNED) x arms
    total_in = per_condition_in * runs
    total_out = per_condition_out * runs

    raw = (total_in / 1e6) * IN_PER_MTOK + (total_out / 1e6) * OUT_PER_MTOK

    # The Hugging Face router serves each model through a different provider,
    # and those providers' prices are not published in a form this script can
    # read. Rather than invent a rate, the HF side is bounded by TOKENS: the
    # same per-model envelope, times the hard cap on how many models one run
    # may exercise.
    hf_models = A.MAX_HF_MODELS
    return {
        "anthropic_model": A.ANTHROPIC_MODEL,
        "turn_cap_per_agent": A.MAX_TURNS,
        "conditions": 2,
        "arms": len(A.ARMS),
        "est_input_tokens": total_in,
        "est_output_tokens": total_out,
        "est_cost_usd": round(raw, 4),
        "upper_bound_usd": round(raw * SAFETY, 4),
        "worst_case_10_reruns_usd": round(raw * SAFETY * 10, 2),
        "hf_models_max": hf_models,
        "hf_input_token_ceiling": int(total_in * SAFETY * hf_models),
        "hf_output_token_ceiling": int(total_out * SAFETY * hf_models),
        "hf_cost_usd": "not priced here — per-provider router rates are not "
                       "read by this script; the bound above is on tokens",
    }


def plan_estimate(models: str = "all", only: str = "", arms: str = "all",
                  repeats: int = 1, peer_variants: str = "no_artifact") -> dict:
    """Price only the models THIS run will actually call.

    The previous gate priced the Anthropic envelope unconditionally and
    multiplied it by repeats. On an HF-only sweep that is a charge against a
    backend the run never touches: run 35485983996 spent $0 on Anthropic while
    the gate scored it $0.907 against a $1.00 ceiling, and one more repeat
    would have blocked a free run. A gate that blocks the wrong runs gets
    raised or removed, which is how ceilings stop meaning anything.

    So: resolve which backends are in play, and charge each only for itself.
    """
    keep = {k.strip() for k in only.split(",") if k.strip()}
    n_arms = len(A.ARMS) if arms == "all" else 1
    n_variants = (len(A.PEER_VARIANT_NAMES) if peer_variants == "all"
                  else len([v for v in peer_variants.split(",") if v.strip()]))
    n_variants = max(1, n_variants)
    repeats = max(1, int(repeats))

    anthropic_keys = {A.ANTHROPIC_SPEC.key}
    hf_keys = {s.key for s in A.HF_CANDIDATES}

    if models in ("all", "anthropic"):
        sel_anthropic = anthropic_keys & keep if keep else anthropic_keys
    else:
        sel_anthropic = set()
    if models in ("all", "hf"):
        # Availability is discovered at run time, so an unfiltered sweep is
        # bounded by the cap rather than by a known list.
        sel_hf = (hf_keys & keep) if keep else set(list(hf_keys)[:A.MAX_HF_MODELS])
    else:
        sel_hf = set()

    base = estimate()
    per_run_in = base["est_input_tokens"] // (2 * len(A.ARMS))
    per_run_out = base["est_output_tokens"] // (2 * len(A.ARMS))

    a_runs = len(sel_anthropic) * n_arms * n_variants * repeats
    a_in = per_run_in * 2 * a_runs
    a_out = per_run_out * 2 * a_runs
    a_cost = (a_in / 1e6) * IN_PER_MTOK + (a_out / 1e6) * OUT_PER_MTOK

    h_runs = len(sel_hf) * n_arms * n_variants * repeats
    h_in = MEASURED_HF_IN_PER_RUN * h_runs
    h_out = MEASURED_HF_OUT_PER_RUN * h_runs

    return {
        "models_arg": models,
        "only_arg": only or "(none)",
        "arms": n_arms,
        "peer_variants": n_variants,
        "repeats": repeats,
        "anthropic_models_selected": sorted(sel_anthropic),
        "anthropic_model_runs": a_runs,
        "anthropic_input_tokens": a_in,
        "anthropic_output_tokens": a_out,
        "anthropic_cost_usd": round(a_cost, 4),
        "anthropic_upper_bound_usd": round(a_cost * SAFETY, 4),
        "hf_models_selected": sorted(sel_hf),
        "hf_model_runs": h_runs,
        "hf_input_tokens_projected": h_in,
        "hf_output_tokens_projected": h_out,
        "hf_projection_basis": MEASURED_SOURCE,
        "hf_cost_usd": "not priced here — per-provider router rates are not "
                       "read by this script; the token projection above is "
                       "measured, the dollar figure is not asserted",
        "priced_upper_bound_usd": round(a_cost * SAFETY, 4),
    }


def _main() -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default="all")
    ap.add_argument("--only", default="")
    ap.add_argument("--arms", default="all")
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--peer-variants", default="no_artifact")
    ap.add_argument("--ceiling", type=float, default=None,
                    help="fail if the PRICED upper bound exceeds this")
    args = ap.parse_args()

    plan = plan_estimate(args.models, args.only, args.arms, args.repeats,
                         args.peer_variants)
    w = max(len(k) for k in plan)
    for k, v in plan.items():
        print(f"  {k:<{w}} : {v}")
    if args.ceiling is not None:
        ub = plan["priced_upper_bound_usd"]
        if ub > args.ceiling:
            print(f"\n  BUDGET GATE FAILED: priced upper bound ${ub} exceeds "
                  f"${args.ceiling}")
            return 1
        print(f"\n  Budget gate passed: priced upper bound ${ub} <= "
              f"${args.ceiling}")
        if plan["hf_model_runs"]:
            print(f"  Hugging Face side is unpriced by design: "
                  f"{plan['hf_model_runs']} model-run(s), projected "
                  f"{plan['hf_input_tokens_projected']} in / "
                  f"{plan['hf_output_tokens_projected']} out tokens "
                  f"(basis: {plan['hf_projection_basis']}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
