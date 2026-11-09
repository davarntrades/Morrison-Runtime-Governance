"""The Frontier Lab's deterministic execution-boundary scenarios."""

from runtime_eval.frontier.boundary import run_boundary_scenarios


def _by(record, scenario):
    return [s for s in record["steps"] if s["scenario"] == scenario]


def test_every_boundary_scenario_behaves_as_declared(tmp_path):
    record = run_boundary_scenarios(store_dir=str(tmp_path))
    failed = [(s["scenario"], s["label"], s["outcome"])
              for s in record["steps"] if not s["matches_expectation"]]
    assert not failed
    assert record["all_expectations_met"]
    assert record["execution_mode"] == "SIMULATED"
    assert all(s["execution_mode"] == "SIMULATED" for s in record["steps"])


def test_released_actions_are_exactly_the_authorised_actions(tmp_path):
    record = run_boundary_scenarios(store_dir=str(tmp_path))
    released = [s for s in record["steps"] if s["outcome"] == "executed_simulated"]
    assert released
    assert all(s["executed_action_hash"] == s["authorized_action_hash"]
               for s in released)


def test_approval_is_single_use_across_a_restart(tmp_path):
    before, after = _by(run_boundary_scenarios(store_dir=str(tmp_path)), "restart")
    assert before["outcome"] == "executed_simulated"
    assert after["outcome"] == "withheld_by_verdict"


def test_parts_never_contradict_the_whole(tmp_path):
    rank = {"PERMIT": 0, "ESCALATE": 1, "BLOCK": 2}
    for s in run_boundary_scenarios(store_dir=str(tmp_path))["steps"]:
        assert s["strictest_verdict"] == s["verdict"]
        assert rank[s["verdict"]] == max(rank[s["local_verdict"]],
                                         rank[s["global_verdict"]],
                                         rank[s["authorization_verdict"]])


def test_history_dependent_refusals_are_global_not_local(tmp_path):
    record = run_boundary_scenarios(store_dir=str(tmp_path))
    exfil = _by(record, "trajectory")[1]
    limit = _by(record, "revocation")[0]
    for step in (exfil, limit):
        assert step["verdict"] == "BLOCK"
        assert step["local_verdict"] == "PERMIT"
        assert step["global_verdict"] == "BLOCK"


def test_boundary_evidence_is_keyed_anchored_and_not_called_independent(tmp_path):
    record = run_boundary_scenarios(store_dir=str(tmp_path))
    assert record["evidence"]
    assert all(e["status"] == "ANCHOR_VERIFIED" for e in record["evidence"])
    assert "not independent" in record["evidence_note"]
