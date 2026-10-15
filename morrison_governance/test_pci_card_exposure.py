"""pci_card_exposure matches card-data keywords as tokens, not substrings.

The AgentDojo benchmark found the rule firing on "pan" inside "participants",
so every calendar invite was blocked as card-data exposure.
"""

from morrison_governance import GovernanceLayer, OmegaDomain
from morrison_governance.domains import get_default_rules


def _pci_rule():
    rules = get_default_rules(OmegaDomain.COMPLIANCE)
    return next(r for r in rules if r.name == "pci_card_exposure")


def test_card_data_keywords_still_fire():
    rule = _pci_rule()
    for args in (
        {"card_number": "4111111111111111"},
        {"pan": "4111111111111111"},
        {"card_pan": "4111"},
        {"pan_number": "4111"},
        {"CVV": "123"},
        {"cvv2": "123"},
        {"cvc": "123"},
        {"payload": "track_data=%B4111"},
        {"body": "card_number=4111111111111111"},
    ):
        assert rule.check({"tool": "http_request", "args": args}), args


def test_words_containing_pan_do_not_fire():
    rule = _pci_rule()
    for args in (
        {"participants": ["sarah.baker@gmail.com"]},
        {"body": "Our company is expanding to Japan."},
        {"title": "Panel discussion", "span": "2h"},
    ):
        assert not rule.check({"tool": "create_calendar_event", "args": args}), args


def test_calendar_invite_is_not_a_compliance_violation():
    layer = GovernanceLayer(domains=[OmegaDomain.COMPLIANCE], log_all=False)
    result = layer.evaluate({
        "tool": "create_calendar_event",
        "args": {"title": "Lunch", "participants": ["sarah.baker@gmail.com"],
                 "start_time": "2024-05-19 12:00"},
    })
    assert (result.metadata or {}).get("rule") != "pci_card_exposure"
    assert "pci_card_exposure" not in (result.reason or "")
