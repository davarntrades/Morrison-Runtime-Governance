"""Price the run BEFORE any billed call, and fail the gate if it won't fit.

Estimated from local prompt text rather than via `messages.count_tokens`,
because that endpoint is itself a billed call and the whole point of this
file is to price the experiment without touching the API. ~4 chars/token,
then inflated by a safety factor, so the figure is an upper bound rather
than a best guess.

    python -m limits_audit.persuasion_redteam.estimate_cost \
        --rounds 20 --budget-credits 80
"""

from __future__ import annotations

import argparse

from . import agents as A
from . import strategies as ST
from .orchestrator import CREDIT_USD

CHARS_PER_TOKEN = 4.0

#: Inflation applied to the INPUT estimate only.
#:
#: Input is genuinely estimated (~4 chars/token over local prompt text), so it
#: carries error and deserves a margin. Output does NOT: `max_tokens` is a
#: hard ceiling the API enforces, so the most a call can emit is exactly that.
#: Multiplying a ceiling by a safety factor produces a number the run cannot
#: reach, which is not conservatism — it is a wrong upper bound, and it fails
#: gates that should pass. Output is therefore priced AT the cap, untouched.
INPUT_SAFETY = 1.6


def approx(text: str) -> int:
    return int(len(text) / CHARS_PER_TOKEN) + 1


def estimate(rounds: int = 20, effort: str = "medium",
             payload_chars: int = 900) -> dict:
    # Attacker: system + directive + a short history note each round.
    atk_in = approx(A.ATTACKER_SYSTEM) + 260
    atk_out = A.ATTACKER_MAX_TOKENS

    # Defender: system + tool surface + the attacker message + the artifact.
    def_in = (approx(A.DEFENDER_SYSTEM) + A.ATTACKER_MAX_TOKENS
              + approx("x" * payload_chars) + 80)
    # Thinking bills as output. Adaptive thinking at the chosen effort is the
    # dominant term and is NOT bounded by the visible reply length, so the
    # estimate assumes the cap is reached rather than hoping it is not.
    def_out = A.DEFENDER_MAX_TOKENS

    a_in, a_out = atk_in * rounds, atk_out * rounds
    d_in, d_out = def_in * rounds, def_out * rounds

    pa_in, pa_out = A.PRICES[A.ATTACKER_MODEL]
    pd_in, pd_out = A.PRICES[A.DEFENDER_MODEL]
    a_in_b, d_in_b = int(a_in * INPUT_SAFETY), int(d_in * INPUT_SAFETY)
    atk_cost = (a_in_b / 1e6) * pa_in + (a_out / 1e6) * pa_out
    def_cost = (d_in_b / 1e6) * pd_in + (d_out / 1e6) * pd_out
    raw = atk_cost + def_cost

    return {
        "rounds": rounds,
        "defender_effort": effort,
        "attacker_model": A.ATTACKER_MODEL,
        "defender_model": A.DEFENDER_MODEL,
        "kernel_model": "none — deterministic, $0.00",
        "attacker_tokens": f"{a_in_b} in (est x{INPUT_SAFETY}) / "
                           f"{a_out} out (at cap)",
        "defender_tokens": f"{d_in_b} in (est x{INPUT_SAFETY}) / "
                           f"{d_out} out (at cap)",
        "attacker_cost_usd": round(atk_cost, 4),
        "defender_cost_usd": round(def_cost, 4),
        "upper_bound_usd": round(raw, 4),
        "basis": "output priced at max_tokens (a hard ceiling); input "
                 "estimated from prompt text and inflated",
    }


def _main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=20)
    ap.add_argument("--effort", default="low")
    ap.add_argument("--budget-credits", type=float, default=80.0)
    ap.add_argument("--credit-usd", type=float, default=CREDIT_USD)
    args = ap.parse_args()

    est = estimate(args.rounds, args.effort)
    w = max(len(k) for k in est)
    print(f"\n  pre-flight estimate — {len(ST.LADDER)}-rung ladder, "
          f"{args.rounds} rounds\n")
    for k, v in est.items():
        print(f"    {k:<{w}} : {v}")

    ceiling = args.budget_credits * args.credit_usd
    ub = est["upper_bound_usd"]
    as_credits = ub / args.credit_usd
    print(f"\n    upper bound {ub:.4f} USD = {as_credits:.1f} credits "
          f"(at ${args.credit_usd}/credit)")
    if ub > ceiling:
        print(f"\n  BUDGET GATE FAILED: upper bound ${ub:.4f} exceeds "
              f"${ceiling:.4f} ({args.budget_credits} credits).")
        print(f"  Reduce --rounds to about "
              f"{int(args.rounds * ceiling / ub)} or lower --effort.\n")
        return 1
    print(f"\n  Budget gate passed: ${ub:.4f} <= ${ceiling:.4f}. "
          f"Headroom {ceiling - ub:.4f} USD "
          f"({(ceiling - ub) / args.credit_usd:.0f} credits).\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
