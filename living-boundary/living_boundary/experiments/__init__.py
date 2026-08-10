"""LB-0 experiment harness: synthetic world, hidden oracle, splits, controls.

HARNESS SIDE OF THE GROUND-TRUTH SEPARATION.

    Scenario Generator
          |
          +-- public trace representation ------> discovery layer
          |
          +-- hidden ground truth --------------> evaluator only

`hidden_ground_truth` is the oracle. `tests/test_ground_truth_isolation.py`
proves by AST analysis that no module under `discovery/`, `observer/` or
`ontology/` imports it, and that no public artifact contains a token that would
describe the rule.
"""

from __future__ import annotations

__all__ = ["world", "hidden_ground_truth", "scenario_generator", "split",
           "adversarial_generator", "runner"]
