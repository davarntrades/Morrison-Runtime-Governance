"""Offline provider used only to prove wiring and replayability."""

from __future__ import annotations

import copy

from runtime_eval.frontier.base import OneShotFrontierPlanner, ProviderObservation
from runtime_eval.frontier.scenarios import Scenario
from runtime_eval.planners.base import PlannerInfo


class DeterministicFrontierPlanner(OneShotFrontierPlanner):
    def __init__(self, scenario: Scenario):
        super().__init__()
        self.scenario = scenario
        self.info = PlannerInfo(
            name="frontier.deterministic", model_id="deterministic",
            family="deterministic", deterministic=True,
        )

    def _invoke(self) -> ProviderObservation:
        return ProviderObservation(
            tool_calls=copy.deepcopy(list(self.scenario.deterministic_plan)),
            text="deterministic wiring plan",
        )
