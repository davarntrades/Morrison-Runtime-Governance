"""Regulatory context is deterministic, cautious and downstream-only."""

from copy import deepcopy

from runtime_eval.frontier.regulatory import calculate_regulatory_exposure
from runtime_eval.frontier.regulatory.registry import REGULATORY_PROFILES
from runtime_eval.frontier.session import (
    GovernedSessionOrchestrator, SessionLimits, verify_session_evidence,
)
from runtime_eval.frontier.value_impact import calculate_session_value_impact
from runtime_eval.tests.test_frontier_sessions import _SequenceFactory, _scenario


def _step(tool="read_customer_record", verdict="BLOCK", *, rule="cross_tenant",
          layer="tenancy", capabilities=(), executed=False, number=1):
    return {
        "step": number,
        "normalized_call": {"tool": tool, "args": {
            "customer_id": "C-999"} if tool == "read_customer_record" else {}},
        "morrison_decision": {
            "verdict": verdict, "rule": rule, "layer": layer,
            "metadata": {"capabilities": list(capabilities)},
        },
        "execution_occurred": executed,
    }


def _profile(**overrides):
    profile = {
        "organization_id": "configured-demo",
        "jurisdictions": ["UK", "EU"],
        "data_categories": ["personal_data", "financial_data"],
        "regulated_entities": ["financial_services"],
        "frameworks_enabled": ["uk_gdpr", "eu_gdpr", "dora"],
        "entity_classifications": {},
        "ai_system_classification": {"eu_ai_act": "unknown"},
    }
    profile.update(overrides)
    return profile


def test_eu_ai_act_is_not_automatically_applied_to_every_event():
    result = calculate_regulatory_exposure(
        [_step(tool="read_account", verdict="PERMIT", rule="", layer="")],
        "guarded_pilot", _profile(
            frameworks_enabled=["eu_ai_act"],
            ai_system_classification={"eu_ai_act": "high_risk"}))
    assert "eu_ai_act" not in {row["framework_id"] for row in result["frameworks"]}


def test_eu_ai_act_requires_structured_runtime_trigger_and_configuration():
    result = calculate_regulatory_exposure(
        [_step(tool="custom", capabilities=("high_risk_ai_action",))],
        "guarded_pilot", _profile(
            frameworks_enabled=["eu_ai_act"],
            ai_system_classification={"eu_ai_act": "high_risk"}))
    ai_act = next(row for row in result["frameworks"]
                  if row["framework_id"] == "eu_ai_act")
    assert ai_act["applicability"] == "CONFIRMED_BY_CONFIGURATION"
    assert ai_act["triggering_capabilities"] == ["high_risk_ai_action"]


def test_uk_gdpr_only_surfaces_for_structured_data_relevance():
    irrelevant = calculate_regulatory_exposure(
        [_step(tool="prepare_summary", verdict="PERMIT", rule="", layer="")],
        "guarded_pilot", _profile(frameworks_enabled=["uk_gdpr"]))
    relevant = calculate_regulatory_exposure(
        [_step()], "guarded_pilot", _profile(frameworks_enabled=["uk_gdpr"]))
    assert not irrelevant["frameworks"]
    uk = next(row for row in relevant["frameworks"]
              if row["framework_id"] == "uk_gdpr")
    assert uk["applicability"] == "CONFIRMED_BY_CONFIGURATION"


def test_structured_customer_data_does_not_confirm_gdpr_without_configured_scope():
    result = calculate_regulatory_exposure(
        [_step()], "guarded_pilot", _profile(
            frameworks_enabled=["uk_gdpr"], data_categories=[]))
    uk = next(row for row in result["frameworks"]
              if row["framework_id"] == "uk_gdpr")
    assert uk["applicability"] == "POTENTIALLY_RELEVANT"
    assert uk["calculation"]["available"] is False


def test_missing_turnover_prevents_turnover_calculation():
    result = calculate_regulatory_exposure(
        [_step()], "guarded_pilot", _profile(
            frameworks_enabled=["uk_gdpr"],
            entity_classifications={"uk_gdpr_penalty_tier": "higher"}))
    calculation = next(row for row in result["frameworks"]
                       if row["framework_id"] == "uk_gdpr")["calculation"]
    assert calculation["available"] is False
    assert "INSUFFICIENT INFORMATION" in calculation["reason"]


def test_correct_uk_gdpr_ceiling_is_source_backed_and_not_summed():
    result = calculate_regulatory_exposure(
        [_step()], "guarded_pilot", _profile(
            frameworks_enabled=["uk_gdpr", "eu_gdpr"],
            annual_global_turnover={"amount": 2_000_000_000,
                                    "currency": "GBP", "year": 2025},
            entity_classifications={"uk_gdpr_penalty_tier": "higher",
                                    "eu_gdpr_penalty_tier": "higher"}))
    uk = next(row for row in result["frameworks"]
              if row["framework_id"] == "uk_gdpr")
    eu = next(row for row in result["frameworks"]
              if row["framework_id"] == "eu_gdpr")
    assert uk["calculation"]["maximum_context"] == {
        "amount": 80_000_000, "currency": "GBP"}
    assert eu["calculation"]["available"] is False  # no implicit FX conversion
    assert uk["source"]["authority"] == "Information Commissioner's Office"
    assert uk["profile_version"] == "1.0"
    assert result["statutory_maxima_aggregation"] == "NOT_SUMMED_ACROSS_FRAMEWORKS"


def test_shadow_does_not_claim_regulatory_loss_prevented():
    result = calculate_regulatory_exposure([_step()], "shadow", _profile())
    assert result["runtime_mitigation_language"].startswith(
        "REGULATORY EXPOSURE OBSERVED")
    assert "prevented" not in result["runtime_mitigation_language"].lower()


def test_guarded_pilot_does_not_claim_guaranteed_fine_avoidance():
    result = calculate_regulatory_exposure(
        [_step()], "guarded_pilot", _profile())
    assert all("guaranteed saving" in row["disclaimer"] for row in result["frameworks"])
    assert "fine avoided" not in str(result).lower()
    assert result["runtime_mitigation_recorded"] is True


def test_permitted_context_does_not_claim_runtime_mitigation():
    result = calculate_regulatory_exposure(
        [_step(verdict="PERMIT", rule="", layer="", executed=True)],
        "guarded_pilot", _profile())
    assert result["runtime_mitigation_recorded"] is False
    assert result["runtime_mitigation_language"].startswith(
        "REGULATORY CONTEXT SURFACED")


def test_non_statutory_pci_profile_never_calculates_a_fine():
    payment = _step(tool="transfer_funds", verdict="BLOCK", rule="payment.move_funds",
                    layer="capability_policy", capabilities=("payment.move_funds",))
    result = calculate_regulatory_exposure(
        [payment], "guarded_pilot", _profile(
            frameworks_enabled=["pci_dss"], data_categories=["payment_card_data"],
            contractual_frameworks=["pci_dss"]))
    pci = next(row for row in result["frameworks"]
               if row["framework_id"] == "pci_dss")
    assert pci["framework_id"] == "pci_dss"
    assert "STATUTORY_PENALTY" not in pci["exposure_types"]
    assert pci["calculation"]["available"] is False


def test_one_runtime_event_can_surface_multiple_regimes_without_adding_maxima():
    result = calculate_regulatory_exposure([_step()], "guarded_pilot", _profile())
    ids = {row["framework_id"] for row in result["frameworks"]}
    assert {"uk_gdpr", "eu_gdpr"} <= ids
    assert not result["highest_statutory_context_by_currency"]


def test_projection_cannot_change_verdict_or_cause_execution():
    rows = [_step()]
    original = deepcopy(rows)
    calculate_regulatory_exposure(rows, "guarded_pilot", _profile())
    assert rows == original
    assert rows[0]["morrison_decision"]["verdict"] == "BLOCK"
    assert rows[0]["execution_occurred"] is False


def test_regulatory_profile_version_is_sealed_in_session_evidence():
    factory = _SequenceFactory([
        {"tool": "read_customer_record", "args": {"customer_id": "C-999"}},
        None,
    ])
    session = GovernedSessionOrchestrator(
        provider="deterministic", model="deterministic", objective="test",
        scenario=_scenario(), planner_factory=factory,
        limits=SessionLimits(max_steps=2, max_runtime_s=30, max_model_calls=2),
        organization_profile=_profile(frameworks_enabled=["uk_gdpr"]),
    )
    session.start()
    while session.advance():
        pass
    snapshot = session.snapshot()
    regulatory = snapshot["regulatory_exposure"]
    assert regulatory["frameworks"][0]["profile_version"] == "1.0"
    assert snapshot["session_evidence_record"]["regulatory_exposure"] == regulatory
    assert verify_session_evidence(snapshot)
    assert snapshot["steps"][0]["morrison_decision"]["verdict"] == "BLOCK"
    assert not snapshot["steps"][0]["execution_occurred"]


def test_all_profiles_have_versioned_authoritative_source_metadata():
    for framework_id, profile in REGULATORY_PROFILES.items():
        assert framework_id
        assert profile["framework_name"]
        assert profile["profile_version"]
        assert profile["effective_from"]
        assert "effective_to" in profile
        assert profile["source_last_verified"]
        source = profile["source"]
        assert source["authority"]
        assert source["name"]
        assert source["reference"]
        assert source["url"].startswith("https://")


def test_statutory_context_is_not_counted_as_direct_protected_value():
    monetary_step = {
        "step": 2,
        "normalized_call": {
            "tool": "transfer_funds",
            "args": {"amount": 100_000,
                     "destination_account": "PROMPT_INJECTION_CANARY"},
        },
        "morrison_decision": {
            "verdict": "BLOCK",
            "rule": "payment.move_funds",
            "layer": "capability_policy",
            "metadata": {"capabilities": ["payment.move_funds"]},
        },
        "execution_occurred": False,
    }
    steps = [_step(), monetary_step]
    organization = _profile(
        frameworks_enabled=["uk_gdpr"],
        annual_global_turnover={"amount": 2_000_000_000,
                                "currency": "GBP", "year": 2025},
        entity_classifications={"uk_gdpr_penalty_tier": "higher"},
    )

    regulatory = calculate_regulatory_exposure(
        steps, "guarded_pilot", organization)
    value = calculate_session_value_impact(steps, "guarded_pilot")
    uk_gdpr = next(row for row in regulatory["frameworks"]
                   if row["framework_id"] == "uk_gdpr")
    statutory = uk_gdpr["calculation"]["maximum_context"]

    assert statutory == {"amount": 80_000_000, "currency": "GBP"}
    assert value["direct_simulated_exposure_prevented"] == 100_000
    assert value["measurement_type"] == "illustrative"
    assert regulatory["measurement_type"] == "contextual"
    assert all("statutory" not in key.lower() for key in value)
    assert regulatory["statutory_maxima_aggregation"] == (
        "NOT_SUMMED_ACROSS_FRAMEWORKS")


def test_non_statutory_disclaimer_is_not_a_statutory_fine_claim():
    payment = _step(
        tool="transfer_funds", verdict="BLOCK", rule="payment.move_funds",
        layer="capability_policy", capabilities=("payment.move_funds",))
    result = calculate_regulatory_exposure(
        [payment], "guarded_pilot", _profile(
            frameworks_enabled=["pci_dss"],
            data_categories=["payment_card_data"],
            contractual_frameworks=["pci_dss"]))
    pci = next(row for row in result["frameworks"]
               if row["framework_id"] == "pci_dss")
    assert "no statutory fine is calculated" in pci["disclaimer"].lower()
