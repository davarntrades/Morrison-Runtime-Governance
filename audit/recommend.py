"""Integration recommendations derived from audit findings.

Deterministic, evidence-driven: recommendations are emitted only when
the findings warrant them (which layers fired, which domains reached Ω,
whether allowlists are configured, whether hardening was used). No
generic boilerplate — each recommendation cites the finding that
motivates it."""

from __future__ import annotations


def integration_recommendations(result, package) -> list:
    recs: list = []
    blocked = [f for f in result.findings if f.blocked]
    layers_fired = {layer for f in blocked for layer in
                    f.layers_that_would_object}

    # placement: always the core middleware seam
    recs.append({
        "id": "place_middleware_pre_execution",
        "priority": "required",
        "recommendation": (
            "Insert the governance layer as pre-execution middleware "
            "between the planner and the tool runtime; evaluate "
            "history+candidate (prefix-aware) and execute only PERMIT."),
        "evidence": "core integration pattern"})

    # which Ω domains are reachable → keep those domains loaded
    reachable_domains = sorted({f.omega_domain for f in blocked
                                if f.omega_domain})
    if reachable_domains:
        recs.append({
            "id": "load_reachable_domains",
            "priority": "required",
            "recommendation": (
                "Keep the Ω domains that fired loaded in production: "
                + ", ".join(reachable_domains) + "."),
            "evidence": f"{len(blocked)} trajectories reached Ω in these "
                        f"domains"})

    # taint / multi-step reachable → recommend taint + forecast on
    if {"V2", "V3"} & layers_fired:
        recs.append({
            "id": "enable_taint_and_forecast",
            "priority": "required",
            "recommendation": (
                "Keep V2 source→sink taint and V3 reachability "
                "forecasting enabled — multi-step / forecasted Ω was "
                "reachable in the supplied trajectories."),
            "evidence": "V2/V3 fired on submitted trajectories"})

    # egress reached but no allowlist configured → recommend allowlist
    egress_taint = any(f.rule in ("taint_flow", "taint_flow_structural")
                       for f in blocked)
    if egress_taint and not (package.internal_url_hosts
                             or package.internal_email_domains):
        recs.append({
            "id": "configure_internal_allowlists",
            "priority": "recommended",
            "recommendation": (
                "Configure internal_url_hosts / internal_email_domains so "
                "legitimate internal egress is not blocked under "
                "deny-by-default; leave external destinations denied."),
            "evidence": "source→sink taint fired and no allowlist is set"})

    # hardening surfaces (decode/lift/recursion) recommended if not used
    if not package.use_hardening:
        recs.append({
            "id": "enable_hardening_pipeline",
            "priority": "recommended",
            "recommendation": (
                "Enable the runtime_eval HardeningPipeline (payload "
                "decode + semantic lifting + recursive-coercion "
                "flattening + schema validation) to close synonym / "
                "encoded / nested-delegation surfaces."),
            "evidence": "hardening was disabled for this audit"})

    # single-point trust risk → recommend quorum for high-stakes domains
    high_stakes = {"finance", "banking", "healthcare", "data_privacy"} \
        & set(package.domains)
    if high_stakes:
        recs.append({
            "id": "deny_by_default_quorum",
            "priority": "recommended",
            "recommendation": (
                "For high-stakes domains (" + ", ".join(sorted(high_stakes))
                + ") run a deny-by-default quorum of diverse governance "
                "replicas so no single lenient configuration is a point of "
                "failure (see global_governance.DistributedGovernance)."),
            "evidence": "high-blast-radius domains in scope"})

    # multi-agent / cross-system if more than a few tools or any
    # delegation-shaped tool present
    if len(package.tool_names()) >= 4:
        recs.append({
            "id": "joint_trajectory_governance",
            "priority": "consider",
            "recommendation": (
                "If multiple agents / services share state, govern the "
                "JOINT trajectory (multi_agent_eval shared-global mode) so "
                "an acquire by one component and an egress by another are "
                "one reachable set."),
            "evidence": f"{len(package.tool_names())} tools in scope"})

    # unmet client expectations → flag for review
    mismatches = [f.trajectory_id for f in result.findings
                  if f.expectation_met is False]
    if mismatches:
        recs.append({
            "id": "review_expectation_mismatches",
            "priority": "required",
            "recommendation": (
                "Review trajectories whose governance verdict differs "
                "from the client's stated expectation: "
                + ", ".join(mismatches) + "."),
            "evidence": "client-supplied expectation not met"})

    return recs
