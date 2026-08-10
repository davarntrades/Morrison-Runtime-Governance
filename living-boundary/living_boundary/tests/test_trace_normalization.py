"""Trace normalisation rejects rather than repairs."""

from __future__ import annotations

import json

import pytest

from living_boundary.observer.normalizer import (
    ALLOWED_EVENT_KEYS, BOUNDARY_CROSSING, BOUNDARY_INTERNAL,
    MalformedTraceError, normalise_event, normalise_events,
)
from living_boundary.observer.trace_reader import read_events, read_jsonl
from living_boundary.observer.trajectory_builder import build_trajectories


def _event(**overrides):
    base = {
        "trace_id": "t-1", "sequence_id": "seq-1", "step_index": 0,
        "capability": "data.read", "action": "read_customer_profile",
        "domain": "customer_data", "trust_boundary": "internal",
        "identity_id": "identity_01", "resource": "customer/cust_00001",
        "permission_scope": ["customer.read", "customer.read.pii"],
        "policy_decision": "allow", "execution_outcome": "success",
        "trajectory_outcome": "safe", "provenance": {"source": "test"},
    }
    base.update(overrides)
    return base


def test_normalises_a_well_formed_event():
    event = normalise_event(_event())
    assert event.capability == "data.read"
    assert event.permission_scope == ("customer.read", "customer.read.pii")
    assert event.subject == "cust_00001"
    assert event.resource_type == "customer"
    assert event.boundary_class == BOUNDARY_INTERNAL
    assert event.token == "data.read@customer_data@internal"


def test_boundary_class_collapses_every_non_internal_boundary():
    for boundary in ("partner", "external"):
        assert normalise_event(
            _event(trust_boundary=boundary)).boundary_class == BOUNDARY_CROSSING


def test_out_of_schema_keys_are_rejected_not_ignored():
    """The closed key set is what keeps this a discovery experiment.

    An ignored extra key would let a generator smuggle an annotation such as
    `rule_that_fired` into the discovery layer, turning the whole exercise into
    a retrieval test without anything visibly changing.
    """
    with pytest.raises(MalformedTraceError) as excinfo:
        normalise_event(_event(**{"rule_that_fired": "H1"}))
    assert "rule_that_fired" in str(excinfo.value)


def test_every_schema_key_is_accepted():
    full = _event(timestamp="2026-01-01T00:00:00Z", environment="lb0",
                  provider="p", region="r", session_tag="tag",
                  actor_id="agent_01", existing_ontology_labels=[])
    assert set(full) <= ALLOWED_EVENT_KEYS
    assert normalise_event(full).actor_id == "agent_01"


@pytest.mark.parametrize("bad", [
    {"step_index": -1},
    {"step_index": "0"},
    {"permission_scope": "customer.read"},
    {"policy_decision": "maybe"},
    {"execution_outcome": "probably"},
    {"trajectory_outcome": "risky"},
    {"capability": ""},
    {"provenance": "source=test"},
])
def test_malformed_fields_are_rejected(bad):
    with pytest.raises(MalformedTraceError):
        normalise_event(_event(**bad))


def test_missing_required_field_is_rejected():
    event = _event()
    del event["identity_id"]
    with pytest.raises(MalformedTraceError):
        normalise_event(event)


def test_non_contiguous_steps_are_rejected():
    """A trajectory missing a step is not the trajectory that ran."""
    events = normalise_events([_event(trace_id="a", step_index=0),
                               _event(trace_id="c", step_index=2)])
    with pytest.raises(MalformedTraceError) as excinfo:
        build_trajectories(events)
    assert "non-contiguous" in str(excinfo.value)


def test_conflicting_outcomes_in_one_sequence_are_rejected():
    events = normalise_events([
        _event(trace_id="a", step_index=0, trajectory_outcome="safe"),
        _event(trace_id="b", step_index=1, trajectory_outcome="unsafe")])
    with pytest.raises(MalformedTraceError):
        build_trajectories(events)


def test_trajectory_rollups(dataset):
    trajectory = dataset.split("discovery").trajectories[0]
    assert trajectory.trace_ids
    assert len(trajectory.tokens) == len(trajectory.events)
    assert trajectory.cumulative_scope
    assert trajectory.all_steps_allowed, (
        "every LB-0 step must be individually permitted — that premise is what "
        "makes the composition question meaningful")


def test_normalisation_is_deterministic(dataset):
    first = [e.as_dict() for e in dataset.split("discovery").trajectories[0].events]
    again = read_events(dataset.split("discovery").events[:len(first)])
    assert json.dumps(first, sort_keys=True) == json.dumps(
        [e.as_dict() for e in again], sort_keys=True)


def test_jsonl_round_trip(tmp_path, dataset):
    path = tmp_path / "trace.jsonl"
    rows = dataset.split("discovery").events[:20]
    path.write_text("\n".join(json.dumps(r, sort_keys=True) for r in rows),
                    encoding="utf-8")
    assert len(read_jsonl(path)) == len(rows)


def test_jsonl_rejects_a_corrupt_line(tmp_path):
    path = tmp_path / "trace.jsonl"
    path.write_text(f"{json.dumps(_event())}\n{{not json}}\n", encoding="utf-8")
    with pytest.raises(MalformedTraceError):
        read_jsonl(path)
