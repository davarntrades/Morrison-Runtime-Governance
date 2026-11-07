"""R2-F — tenant key spellings and encoded qualified references escape.

Declared invariant (source):
    kernel/gate.py, `_cross_tenant`: tenant-scoped identifiers in the action
    are compared against the principal's tenant, and qualified resource
    references ("tenant_b.customers", "s3://tenant-b/...") are cross-tenant.
    kernel/gate.py:_TENANT_KEYS and _TENANT_REF_RE are the whole surface.

Observed (principal tenant = "acme"):
    Tenant-key aliases not in _TENANT_KEYS are not compared:
      {"organization": "globex"}, {"customer": "globex"},
      {"account": "globex"}, {"org_name": "globex"},
      {"tenant_name": "globex"}, {"tenant_ids": ["globex"]}
      -> _cross_tenant=None, PERMIT, recorder receives the call.

    The qualified-reference regex requires a literal lowercase
    `tenant|customer|org` followed by `-` or `_` and [a-z0-9]+. Encoding or
    zero-width obfuscation defeats it before the comparison:
      "tenant%5Fglobex/customers.csv"
      "tenant%2Dglobex/customers.csv"
      "tenant\\u200b_globex/customers.csv"
      "s3://tenant%2Dglobex/b"
      -> _cross_tenant=None, PERMIT.

    Control: "tenant_globex/customers.csv" is refused with
    "resource reference ... outside the principal's tenant".

Whether the alias itself names a tenant is a property of the executor's
schema; the kernel-level coverage gap is reproduced. The encoded-reference
cases are the stronger form: they are unambiguously the same qualified
reference the control refuses.

Severity: P2 (conditional on executor/IDP naming; the encoded form is a
parser gap).
Classification: REPRODUCED (encoded refs) / SOURCE-SUPPORTED (aliases).
"""

from __future__ import annotations

import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.dirname(
    _os.path.abspath(__file__)))))
from redteam.deepseek_redteam_round2 import _common as K
from morrison_governance.kernel.gate import _cross_tenant
from morrison_governance.kernel.trust import quarantine_authority


def _check(args: dict):
    call = {"tool": "read_file", "args": args}
    clean, quarantined = quarantine_authority(call)
    cross = _cross_tenant(clean, K.make_context(), quarantined)
    k = K.make_kernel()
    rec = K.Recorder()
    d = k.authorize(call)
    executed = K.run(d, k, rec)
    return {"args": args, "cross_tenant": cross, "verdict": d.verdict,
            "rule": d.rule, "executed": executed[0]}


ALIASES = [
    {"organization": "globex", "path": "/x"},
    {"customer": "globex", "path": "/x"},
    {"account": "globex", "path": "/x"},
    {"org_name": "globex", "path": "/x"},
    {"tenant_name": "globex", "path": "/x"},
    {"tenant_ids": ["globex"], "path": "/x"},
]

REFS = [
    "tenant%5Fglobex/customers.csv",
    "tenant%2Dglobex/customers.csv",
    "tenant\u200b_globex/customers.csv",
    "s3://tenant%2Dglobex/b",
]

CONTROLS = [
    "tenant_globex/customers.csv",
    "s3://tenant-globex/b",
]


def main() -> dict:
    K.header("R2-F tenant key spellings and encoded qualified references")

    aliases = [_check(a) for a in ALIASES]
    refs = [_check({"path": r}) for r in REFS]
    controls = [_check({"path": r}) for r in CONTROLS]

    for row in aliases:
        print(f"alias   {str(row['args'])[:52]:52s} -> "
              f"cross={row['cross_tenant']} {row['verdict']}")
    for row in refs:
        print(f"encoded {row['args']['path']:42s} -> "
              f"cross={row['cross_tenant']} {row['verdict']}")
    for row in controls:
        print(f"control {row['args']['path']:42s} -> "
              f"cross={row['cross_tenant']} {row['verdict']}")

    alias_escape = all(r["cross_tenant"] is None and r["verdict"] == "PERMIT"
                       for r in aliases)
    ref_escape = all(r["cross_tenant"] is None and r["verdict"] == "PERMIT"
                     for r in refs)
    control_stops = all(r["cross_tenant"] is not None for r in controls)

    return K.emit({
        "id": "R2-F",
        "title": "Tenant aliases and encoded qualified references escape the tenant check",
        "invariant": ("A tenant-scoped identifier or qualified resource "
                      "reference in the action is attributed to a tenant and "
                      "compared with the principal's own tenant."),
        "source": [
            "morrison_governance/kernel/gate.py:_TENANT_KEYS",
            "morrison_governance/kernel/gate.py:_TENANT_REF_RE",
            "morrison_governance/kernel/gate.py:_cross_tenant",
            "morrison_governance/kernel/normalize.py:normalize_text (not applied)",
        ],
        "severity": "P2",
        "classification": "REPRODUCED (encoded refs) / SOURCE-SUPPORTED (aliases)",
        "falsified": bool(ref_escape and control_stops),
        "aliases": aliases,
        "encoded_refs": refs,
        "controls": controls,
        "note": (
            "The encoded-reference branch is the kernel-level falsification: "
            "the same reference refused in literal form is permitted when "
            "percent-encoded or interleaved with a zero-width character. "
            "`normalize_text()` exists but is not applied before this "
            "comparison. The alias branch depends on the executor's field "
            "schema, so it is recorded as SOURCE-SUPPORTED rather than a "
            "standalone exploit."),
        "alias_escape": alias_escape,
        "encoded_ref_escape": ref_escape,
        "control_stops": control_stops,
    })


if __name__ == "__main__":
    main()
