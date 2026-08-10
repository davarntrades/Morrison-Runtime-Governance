"""Shared fixtures. Datasets are generated once per session — they are
deterministic, so sharing them cannot leak state between tests, and generating
2,400 trajectories per test would dominate the suite's runtime."""

from __future__ import annotations

import pytest

from living_boundary.experiments.scenario_generator import generate_dataset

SEED = 42


@pytest.fixture(scope="session")
def dataset():
    return generate_dataset(SEED)


@pytest.fixture(scope="session")
def discovery(dataset):                                # noqa: F811
    return dataset.split("discovery")


@pytest.fixture(scope="session")
def held_out(dataset):                                 # noqa: F811
    return dataset.split("held_out")
