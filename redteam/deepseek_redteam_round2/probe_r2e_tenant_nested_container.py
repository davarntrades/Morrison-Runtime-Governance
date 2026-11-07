"""R2-E — cross-tenant check skips container values under authority keys.

Declared invariant (source):
    kernel/gate.py, `_cross_tenant` docstring:
        "The comparison walks the WHOLE payload. It used to inspect only
         top-level argument names, so {"request": {"tenant": "globex"}} ...
         reached another tenant."
    kernel/gate.py, `_tenant_pairs`:
        quarantined values are appended as-is; `scalars()` yields only
        str/int/float and skips dict/list.

Observed (principal tenant = "acme"):
    read_file {"tenant": {"id": "globex"}, "path": "/x"}
      -> _cross_tenant=None, verdict PERMIT, recorder receives the call.
    Also escapes:
      {"tenant": {"tenant_id": "globex"}}
      {"tenant": ["globex"]}
      {"tenant": [{"tenant_id": "globex"}]}
      {"request": {"tenant": {"tenant_id": "globex"}}}
      {"policy": {"tenant_id": "globex"}}
      {"metadata": {"tenant": {"id": "globex"}}}

    Quarantine removes the whole authority-shaped key and stores its value
    under a JSON-pointer path. When that value is a dict or list, the
    container is appended to `pairs` but skipped by `scalars()`, so no leaf
    is ever compared. The same happens for any nested authority key whose
    value is a container.

Control: {"tenant": "globex"} and {"request": {"tenant": "globex"}} are
refused with `cross_tenant`.

Severity: P1 (cross-tenant data access).
Classification: REPRODUCED.
"""

from __future__ import annotations

import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.dirname(
    _os.path.abspath(__file__)))))
from redteam.deepseek_redteam_round2 import _common as K
from morrison_governance.kernel.gate import _cross_tenant
from morrison_governance.kernel.trust import quarantine_authority


def _case(args: dict):
    call = {"tool": "read_file", "args": args}
    clean, quarantined = quarantine_authority(call)
    ctx = K.make_context()
    cross = _cross_tenant(clean, ctx, quarantined)
    k = K.make_kernel()
    rec = K.Recorder()
    d = k.authorize(call)
    executed = K.run(d, k, rec)
    return {
        "args": args,
        "clean_args": clean["args"],
        "quarantined": quarantined,
        "cross_tenant": cross,
        "verdict": d.verdict,
        "rule": d.rule,
        "executed": executed[0],
        "recorder_last": rec.last(),
    }


ESCAPES = [
    {"tenant": {"id": "globex"}, "path": "/x"},
    {"tenant": {"tenant_id": "globex"}, "path": "/x"},
    {"tenant": ["globex"], "path": "/x"},
    {"tenant": [{"tenant_id": "globex"}], "path": "/x"},
    {"request": {"tenant": {"tenant_id": "globex"}}, "path": "/x"},
    {"policy": {"tenant_id": "globex"}, "path": "/x"},
    {"metadata": {"tenant": {"id": "globex"}}, "path": "/x"},
]

CONTROLS = [
    {"tenant": "globex", "path": "/x"},
    {"request": {"tenant": "globex"}, "path": "/x"},
    {"metadata": {"tenant_id": "globex"}, "path": "/x"},
]


def main() -> dict:
    K.header("R2-E cross-tenant nested container gap")

    escapes = [_case(a) for a in ESCAPES]
    controls = [_case(a) for a in CONTROLS]

    for row in escapes:
        print(f"escape {str(row['args'])[:58]:58s} -> "
              f"cross={row['cross_tenant']} {row['verdict']} "
              f"executed={row['executed']}")
    for row in controls:
        print(f"control {str(row['args'])[:58]:58s} -> "
              f"cross={row['cross_tenant']} {row['verdict']} "
              f"executed={row['executed']}")

    escaped = [r for r in escapes
               if r["cross_tenant"] is None and r["verdict"] == "PERMIT"
               and r["executed"]]
    stopped = [r for r in controls if r["cross_tenant"] is not None]
    falsified = len(escaped) == len(escapes) and len(stopped) == len(controls)

    return K.emit({
        "id": "R2-E",
        "title": "Cross-tenant check ignores dict/list values under authority keys",
        "invariant": ("A tenant-scoped identifier anywhere in the payload is "
                      "compared against the principal's tenant, at every "
                      "nesting depth."),
        "source": [
            "morrison_governance/kernel/gate.py:_tenant_pairs",
            "morrison_governance/kernel/gate.py:_cross_tenant",
            "morrison_governance/kernel/trust.py:quarantine_authority",
        ],
        "severity": "P1",
        "classification": "REPRODUCED",
        "falsified": bool(falsified),
        "escapes": escapes,
        "controls": controls,
        "note": (
            "The gap is container values under a quarantined authority key. "
            "A scalar under the same key is caught; an ordinary nested "
            "non-authority key (metadata.tenant_id) is caught because "
            "iter_pairs recurses into it. The fix direction is to traverse "
            "the quarantined value (or classification_view) instead of "
            "appending the container as a single unscannable pair."),
    })


if __name__ == "__main__":
    main()
