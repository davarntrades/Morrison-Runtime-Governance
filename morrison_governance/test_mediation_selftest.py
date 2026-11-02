"""The deployer self-test finds obvious bypasses and never leaks a secret.

Each check is exercised in both directions against a controlled fixture: a
temporary home directory, a synthetic environment, and local listeners.
"""

import http.server
import json
import socket
import threading

from morrison_governance import mediation_selftest as M


def test_secret_environment_is_named_not_printed():
    env = {"DATABASE_URL": "postgres://u:hunter2@db/x", "GITHUB_TOKEN": "ghp_abc",
           "AWS_REGION": "eu-west-1", "PATH": "/usr/bin", "API_KEY_FILE": "/run/x"}
    finding = M.check_environment(env)
    assert finding.status == M.FAIL
    assert finding.details == ["DATABASE_URL", "GITHUB_TOKEN"]
    assert "hunter2" not in json.dumps(finding.__dict__)
    assert "ghp_abc" not in json.dumps(finding.__dict__)


def test_clean_environment_passes():
    assert M.check_environment({"PATH": "/usr/bin", "HOME": "/home/agent"}).status == M.PASS


def test_readable_credential_file_fails(tmp_path):
    (tmp_path / ".aws").mkdir()
    (tmp_path / ".aws" / "credentials").write_text("[default]\nsecret=x\n")
    finding = M.check_credential_files(("~/.aws/credentials", "~/.netrc"), home=str(tmp_path))
    assert finding.status == M.FAIL
    assert finding.details == [str(tmp_path / ".aws" / "credentials")]


def test_no_credential_files_passes(tmp_path):
    assert M.check_credential_files(("~/.aws/credentials",), home=str(tmp_path)).status == M.PASS


def test_writable_governance_path_fails(tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text("{}")
    assert M.check_governance_paths([str(tmp_path)]).status == M.FAIL


def test_mcp_server_outside_the_gateway_is_reported(tmp_path):
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {
        "governed": {"url": "https://morrison-gateway.internal/mcp/db"},
        "direct": {"command": "npx", "args": ["some-db-server"]}}}))
    finding = M.check_mcp([str(cfg)], gateway="morrison-gateway.internal")
    assert finding.status == M.WARN
    assert finding.details == [f"{cfg}:direct"]
    assert M.check_mcp([str(cfg)], gateway="").status == M.WARN


def test_mcp_all_through_gateway_passes(tmp_path):
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {
        "db": {"url": "https://morrison-gateway.internal/mcp/db"}}}))
    assert M.check_mcp([str(cfg)], gateway="morrison-gateway.internal").status == M.PASS


def test_direct_egress_is_detected():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    try:
        findings = M.check_egress([("127.0.0.1", port)], timeout=1.0, metadata=())
    finally:
        listener.close()
    direct = next(f for f in findings if f.check == "egress.direct")
    assert direct.status == M.FAIL


def test_refused_egress_passes():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()                                         # nothing listening now
    findings = M.check_egress([("127.0.0.1", port)], timeout=0.5, metadata=())
    assert next(f for f in findings if f.check == "egress.direct").status == M.PASS


def _serve(code):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):                           # noqa: N802 - http.server API
            self.send_response(code)
            self.end_headers()

        def log_message(self, *args):
            pass
    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_resource_that_accepts_a_leaseless_request_fails():
    server = _serve(200)
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/mutate"
        assert M.check_resource(url).status == M.FAIL
    finally:
        server.shutdown()


def test_resource_that_refuses_a_leaseless_request_passes():
    server = _serve(403)
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/mutate"
        assert M.check_resource(url).status == M.PASS
    finally:
        server.shutdown()


def test_tool_registry_audit_finds_ungoverned_tools():
    from morrison_governance import GovernanceLayer, OmegaDomain
    from morrison_governance.integrations import GovernanceGuard, _govern_bound
    from morrison_governance.kernel import Principal, SecurityContext

    guard = GovernanceGuard(GovernanceLayer(domains=[OmegaDomain.CYBERSECURITY],
                                            log_all=False),
                            security_context=SecurityContext(
                                principal=Principal(id="a", tenant="t")))

    def read_file(path):
        return path

    governed = _govern_bound(guard, "read_file", read_file)
    finding = M.audit_tools({"read_file": governed, "shell": lambda cmd: cmd})
    assert finding.status == M.FAIL
    assert finding.details == ["shell"]
    assert M.audit_tools({"read_file": governed}).status == M.PASS


def test_cli_json_reports_and_exit_code(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(M, "_CREDENTIAL_FILES", ())
    monkeypatch.setattr(M, "check_environment", lambda env=None: M.Finding(
        "credentials.environment", M.PASS, "clean"))
    monkeypatch.setattr(M, "check_shell", lambda expect_none=False: M.Finding(
        "shell", M.PASS, "none"))
    code = M.main(["--json", "--mcp-config", str(tmp_path / "absent.json")])
    out = json.loads(capsys.readouterr().out)
    assert code == out["exit"]
    assert {f["check"] for f in out["findings"]} >= {"credentials.environment", "mcp", "egress"}
