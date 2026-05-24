"""48-Hour Runtime Governance Audit toolkit suite.

Validates intake parsing/validation, the analyzer's findings, risk
ranking, recommendations, deterministic artifacts, and the CLI — all on
the bundled example client package. Deterministic, no GPU.

Run:  python3 audit/tests/test_audit.py
"""

import os
import sys
import tempfile

sys.path.insert(0,
    os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))))

from audit import (
    parse_package, load_package, analyze, rank_findings,
    integration_recommendations, render_markdown, render_findings_json,
    render_audit_log,
)

_EXAMPLE = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "templates", "audit_package.example.json")


def _pkg():
    return load_package(_EXAMPLE)


# ── intake ───────────────────────────────────────────────────

def test_intake_parses_example():
    p = _pkg()
    assert p.org and p.domains and p.trajectories
    assert len(p.trajectories) == 6


def test_intake_rejects_unknown_domain():
    try:
        parse_package({"org": "X", "domains": ["not_a_domain"],
                       "trajectories": [{"id": "t",
                                          "steps": [{"tool": "x"}]}]})
        assert False, "should have rejected unknown domain"
    except ValueError as e:
        assert "unknown domain" in str(e)


def test_intake_rejects_empty_trajectories():
    try:
        parse_package({"org": "X", "domains": ["finance"],
                       "trajectories": []})
        assert False
    except ValueError as e:
        assert "trajectories" in str(e)


def test_intake_rejects_step_without_tool():
    try:
        parse_package({"org": "X", "domains": ["finance"],
                       "trajectories": [{"id": "t",
                                          "steps": [{"args": {}}]}]})
        assert False
    except ValueError as e:
        assert "tool" in str(e)


# ── analyzer ─────────────────────────────────────────────────

def test_analyze_partitions_correctly():
    result = analyze(_pkg())
    by_id = {f.trajectory_id: f for f in result.findings}
    # benign permitted
    assert not by_id["daily_report"].blocked
    assert not by_id["approved_vendor_payment"].blocked
    assert not by_id["internal_status_email"].blocked   # allowlisted domain
    # unsafe blocked
    assert by_id["customer_exfiltration"].blocked
    assert by_id["unauthorized_wire"].blocked
    assert by_id["credential_drop"].blocked


def test_analyze_reaches_expected_omega_states():
    result = analyze(_pkg())
    by_id = {f.trajectory_id: f for f in result.findings}
    # exfil chain blocks at V2 source→sink taint
    assert by_id["customer_exfiltration"].layer == "V2"
    # unauthorized transfer blocks at A_safe
    assert by_id["unauthorized_wire"].layer == "A_safe"


def test_all_client_expectations_met():
    result = analyze(_pkg())
    unmet = [f.trajectory_id for f in result.findings
             if f.expectation_met is False]
    assert not unmet, unmet


def test_summary_counts():
    s = analyze(_pkg()).summary()
    assert s["trajectories"] == 6
    assert s["blocked"] == 3 and s["permitted"] == 3
    assert s["reachable_omega_states"]      # non-empty


# ── risk ─────────────────────────────────────────────────────

def test_risk_ranking_blocked_first_and_by_severity():
    result = analyze(_pkg())
    ranked = rank_findings(result.findings)
    # the top finding is blocked + high/critical
    assert ranked[0].blocked
    assert ranked[0].severity_band in ("critical", "high")
    # severities are non-increasing
    sev = [f.severity for f in ranked]
    assert sev == sorted(sev, reverse=True)


# ── recommendations ──────────────────────────────────────────

def test_recommendations_are_evidence_driven():
    pkg = _pkg()
    recs = integration_recommendations(analyze(pkg), pkg)
    ids = {r["id"] for r in recs}
    assert "place_middleware_pre_execution" in ids
    assert "load_reachable_domains" in ids
    assert "enable_taint_and_forecast" in ids        # V2/V3 fired
    assert "deny_by_default_quorum" in ids           # finance in scope
    # allowlist already configured in the example → no allowlist rec
    assert "configure_internal_allowlists" not in ids


# ── report artifacts ─────────────────────────────────────────

def test_markdown_has_all_six_deliverables():
    md = render_markdown(analyze(_pkg()), _pkg())
    for header in ("## 1. Executable trajectory analysis",
                   "## 2. Reachable Ω states",
                   "## 3. Blocked vs. permitted paths",
                   "## 4. Audit log",
                   "## 5. Risk summary",
                   "## 6. Integration recommendations"):
        assert header in md, header


def test_audit_log_is_jsonl_per_decision():
    import json
    result = analyze(_pkg())
    log = render_audit_log(result)
    rows = [json.loads(l) for l in log.splitlines() if l.strip()]
    # one row per step across all trajectories
    total_steps = sum(len(f.per_step) for f in result.findings)
    assert len(rows) == total_steps
    for r in rows:
        for k in ("trajectory_id", "step", "tool", "verdict", "layer"):
            assert k in r


# ── determinism ──────────────────────────────────────────────

def test_artifacts_byte_identical_on_replay():
    a_md = render_markdown(analyze(_pkg()), _pkg())
    b_md = render_markdown(analyze(_pkg()), _pkg())
    assert a_md == b_md
    a_j = render_findings_json(analyze(_pkg()), _pkg())
    b_j = render_findings_json(analyze(_pkg()), _pkg())
    assert a_j == b_j
    a_l = render_audit_log(analyze(_pkg()))
    b_l = render_audit_log(analyze(_pkg()))
    assert a_l == b_l


# ── CLI ──────────────────────────────────────────────────────

def test_cli_run_writes_three_artifacts():
    from audit.cli import main
    with tempfile.TemporaryDirectory() as tmp:
        rc = main(["run", "--input", _EXAMPLE, "--out", tmp])
        assert rc == 0           # all expectations met → exit 0
        for fn in ("audit_report.md", "audit_findings.json",
                   "audit_log.jsonl"):
            assert os.path.exists(os.path.join(tmp, fn)), fn


def test_cli_validate():
    from audit.cli import main
    assert main(["validate", "--input", _EXAMPLE]) == 0


if __name__ == "__main__":
    T = [
        test_intake_parses_example,
        test_intake_rejects_unknown_domain,
        test_intake_rejects_empty_trajectories,
        test_intake_rejects_step_without_tool,
        test_analyze_partitions_correctly,
        test_analyze_reaches_expected_omega_states,
        test_all_client_expectations_met,
        test_summary_counts,
        test_risk_ranking_blocked_first_and_by_severity,
        test_recommendations_are_evidence_driven,
        test_markdown_has_all_six_deliverables,
        test_audit_log_is_jsonl_per_decision,
        test_artifacts_byte_identical_on_replay,
        test_cli_run_writes_three_artifacts,
        test_cli_validate,
    ]
    print("\n" + "═" * 64 +
          "\n  48-Hour Runtime Governance Audit — toolkit suite\n" +
          "═" * 64 + "\n")
    p = f = 0
    for t in T:
        try:
            t(); print(f"  ✓ {t.__name__}"); p += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {type(e).__name__}: {e}"); f += 1
    print(f"\n  {p} passed, {f} failed\n" + "═" * 64)
    sys.exit(1 if f else 0)
