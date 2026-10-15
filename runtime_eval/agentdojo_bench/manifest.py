"""Deployment configuration for running Morrison over the AgentDojo suites.

This is the configuration an operator would write when putting Morrison in
front of each AgentDojo agent: a capability manifest for every tool the agent
can call, plus the trusted destination allowlists (which email domains and
URL hosts are inside the organisation).

It is derived ONLY from what each tool does and who the agent works for. It
is never derived from AgentDojo's injection tasks, their attacker addresses,
or their ground truth. A manifest tuned to the attacks would make the result
meaningless, so the classification rules below are deliberately coarse:

  * reads of the agent's own data             -> data.read
  * anything that sends data to a recipient    -> data.external_move
    (Morrison then decides per call whether the destination is external)
  * moving money                               -> payment.move_funds
  * changing a credential                      -> credential.change
  * deleting user data                         -> data.destructive
  * workspace membership changes               -> iam.privileged
  * local writes that leave the trust boundary
    with nothing (create a file, book a table) -> no capability

Known, deliberate gaps (reported in results rather than patched over):
travel reservations and in-workspace Slack messages carry no capability, so
an injection whose goal is "book this hotel" or "DM this colleague" is outside
what this configuration governs.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from morrison_governance.kernel import capabilities as C

READ = [C.CAP_DATA_READ]
EGRESS = [C.CAP_EXTERNAL_DATA_MOVE]
PAYMENT = [C.CAP_PAYMENT]
NONE: list[str] = []


@dataclass(frozen=True)
class SuiteProfile:
    suite: str
    tool_manifest: dict[str, list[str]]
    internal_email_domains: tuple[str, ...] = ()
    internal_url_hosts: tuple[str, ...] = ()
    notes: str = ""
    extra: dict = field(default_factory=dict)


_CALENDAR_READ = {
    "get_current_day": READ,
    "search_calendar_events": READ,
    "get_day_calendar_events": READ,
}

WORKSPACE = SuiteProfile(
    suite="workspace",
    tool_manifest={
        # email
        "send_email": EGRESS,
        "delete_email": [C.CAP_DATA_DESTRUCTIVE],
        "get_unread_emails": READ,
        "get_sent_emails": READ,
        "get_received_emails": READ,
        "get_draft_emails": READ,
        "search_emails": READ,
        "search_contacts_by_name": READ,
        "search_contacts_by_email": READ,
        # calendar — invitations deliver event details to every participant
        **_CALENDAR_READ,
        "create_calendar_event": EGRESS,
        "cancel_calendar_event": NONE,
        "reschedule_calendar_event": NONE,
        "add_calendar_event_participants": EGRESS,
        # cloud drive
        "append_to_file": NONE,
        "search_files_by_filename": READ,
        "create_file": NONE,
        "delete_file": [C.CAP_DATA_DESTRUCTIVE],
        "get_file_by_id": READ,
        "list_files": READ,
        "share_file": EGRESS,
        "search_files": READ,
    },
    # The agent works for an employee of Blue Sparrow Tech.
    internal_email_domains=("bluesparrowtech.com",),
    notes="Employee assistant for bluesparrowtech.com: email, calendar, drive.",
)

TRAVEL = SuiteProfile(
    suite="travel",
    tool_manifest={
        "get_user_information": READ,
        "get_all_hotels_in_city": READ,
        "get_hotels_prices": READ,
        "get_rating_reviews_for_hotels": READ,
        "get_hotels_address": READ,
        "get_all_restaurants_in_city": READ,
        "get_cuisine_type_for_restaurants": READ,
        "get_restaurants_address": READ,
        "get_rating_reviews_for_restaurants": READ,
        "get_dietary_restrictions_for_all_restaurants": READ,
        "get_contact_information_for_restaurants": READ,
        "get_price_for_restaurants": READ,
        "check_restaurant_opening_hours": READ,
        "get_all_car_rental_companies_in_city": READ,
        "get_car_types_available": READ,
        "get_rating_reviews_for_car_rental": READ,
        "get_car_fuel_options": READ,
        "get_car_rental_address": READ,
        "get_car_price_per_day": READ,
        "get_flight_information": READ,
        "search_calendar_events": READ,
        "get_day_calendar_events": READ,
        "create_calendar_event": EGRESS,
        "cancel_calendar_event": NONE,
        "reserve_hotel": NONE,
        "reserve_car_rental": NONE,
        "reserve_restaurant": NONE,
        "send_email": EGRESS,
    },
    notes="Personal travel assistant; no organisational email domain.",
)

BANKING = SuiteProfile(
    suite="banking",
    tool_manifest={
        "get_iban": READ,
        "send_money": PAYMENT,
        "schedule_transaction": PAYMENT,
        "update_scheduled_transaction": PAYMENT,
        "get_balance": READ,
        "get_most_recent_transactions": READ,
        "get_scheduled_transactions": READ,
        "read_file": READ,
        "get_user_info": READ,
        "update_password": [C.CAP_CREDENTIAL_CHANGE],
        "update_user_info": NONE,
    },
    notes="Retail banking assistant.",
)

SLACK = SuiteProfile(
    suite="slack",
    tool_manifest={
        "get_channels": READ,
        "add_user_to_channel": [C.CAP_IAM_PRIVILEGED],
        "read_channel_messages": READ,
        "read_inbox": READ,
        "send_direct_message": NONE,
        "send_channel_message": NONE,
        "get_users_in_channel": READ,
        "invite_user_to_slack": [C.CAP_IAM_PRIVILEGED],
        "remove_user_from_slack": [C.CAP_IAM_PRIVILEGED],
        "get_webpage": READ,
        "post_webpage": EGRESS,
    },
    notes="Slack workspace assistant; every web host is outside the org.",
)

PROFILES: dict[str, SuiteProfile] = {
    p.suite: p for p in (WORKSPACE, TRAVEL, BANKING, SLACK)
}


def profile_for(suite_name: str) -> SuiteProfile:
    try:
        return PROFILES[suite_name]
    except KeyError:
        raise ValueError(
            f"no Morrison deployment profile for AgentDojo suite "
            f"{suite_name!r}; known: {sorted(PROFILES)}") from None
