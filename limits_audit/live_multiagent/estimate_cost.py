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
    total_in = per_condition_in * 2               # UNGOVERNED + GOVERNED
    total_out = per_condition_out * 2

    raw = (total_in / 1e6) * IN_PER_MTOK + (total_out / 1e6) * OUT_PER_MTOK
    return {
        "model": A.MODEL,
        "turn_cap_per_agent": A.MAX_TURNS,
        "conditions": 2,
        "est_input_tokens": total_in,
        "est_output_tokens": total_out,
        "est_cost_usd": round(raw, 4),
        "upper_bound_usd": round(raw * SAFETY, 4),
        "worst_case_10_reruns_usd": round(raw * SAFETY * 10, 2),
    }


if __name__ == "__main__":
    e = estimate()
    w = max(len(k) for k in e)
    for k, v in e.items():
        print(f"  {k:<{w}} : {v}")
    print(f"\n  Budget check: upper bound ${e['upper_bound_usd']} per full run; "
          f"under $5 = {e['upper_bound_usd'] < 5}")
