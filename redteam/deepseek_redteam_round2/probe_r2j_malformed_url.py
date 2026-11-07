"""R2-J — malformed URLs raise out of authorize() instead of producing a Decision.

Declared invariant (source):
    kernel/normalize.py, `normalize_action`:
        "Never raises" (the module's normal-form contract).
    kernel/gate.py, `authorize`:
        every proposed transition receives a Decision; unknown/unresolvable
        input is denied by default.
    interception.py, `check`:
        any governance exception becomes BLOCK / fail_closed.

Observed:
    authorize({"tool": "http_request", "args": {"url": "http://[::1"}})
        -> ValueError: Invalid IPv6 URL
    authorize({"tool": "http_request", "args": {"url": "http://[]/x"}})
        -> ValueError: '' does not appear to be an IPv4 or IPv6 address
    classify_destination(...) and normalize_action(...) raise the same.

    Direct kernel callers see an exception rather than a closed Decision.
    GovernanceInterceptor.check catches it and returns
    (False, "BLOCK", "fail_closed", ...), so the wrapper fails closed.

Control: a well-formed URL yields a Decision; a malformed URL through the
interceptor is BLOCK and the runtime is not called.

Severity: P2/P3 (availability/contract violation; the interceptor path is
fail-closed).
Classification: REPRODUCED.
"""

from __future__ import annotations

import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.dirname(
    _os.path.abspath(__file__)))))
from redteam.deepseek_redteam_round2 import _common as K
from morrison_governance.interception import GovernanceInterceptor
from morrison_governance.kernel.destinations import classify_destination
from morrison_governance.kernel.normalize import normalize_action

MALFORMED = ["http://[::1", "http://[]/x", "http://[::ffff:1.2.3.4/x"]


def _authorize(url):
    k = K.make_kernel()
    try:
        d = k.authorize({"tool": "http_request", "args": {"url": url}})
        return {"raised": None, "verdict": d.verdict, "reason": d.reason}
    except Exception as e:                       # noqa: BLE001 — observing it
        return {"raised": f"{type(e).__name__}: {e}"}


def _helpers(url):
    out = {}
    try:
        classify_destination({"tool": "http_request", "args": {"url": url}})
        out["classify_destination"] = "ok"
    except Exception as e:                       # noqa: BLE001
        out["classify_destination"] = f"{type(e).__name__}: {e}"
    try:
        normalize_action({"tool": "http_request", "args": {"url": url}})
        out["normalize_action"] = "ok"
    except Exception as e:                       # noqa: BLE001
        out["normalize_action"] = f"{type(e).__name__}: {e}"
    return out


def main() -> dict:
    K.header("R2-J malformed URL exceptions")

    cases = []
    for url in MALFORMED:
        row = {"url": url, "authorize": _authorize(url), "helpers": _helpers(url)}
        cases.append(row)
        print(f"{url:28s} authorize -> {row['authorize']['raised']}")

    control = _authorize("http://[::1]/")
    print("control valid URL ->", control)

    layer = K.GovernanceLayer(domains=K.DOMAINS, log_all=False)
    interceptor = GovernanceInterceptor(layer, kernel=K.make_kernel())
    intercepted = []
    for url in MALFORMED:
        allowed, verdict, layer_name, reason = interceptor.check(
            {"tool": "http_request", "args": {"url": url}})
        intercepted.append({"url": url, "allowed": allowed,
                            "verdict": verdict, "layer": layer_name,
                            "reason": reason})
    for row in intercepted:
        print(f"interceptor {row['url']:20s} -> {row['verdict']} "
              f"allowed={row['allowed']}")

    falsified = (
        all(row["authorize"]["raised"] for row in cases)
        and control["raised"] is None
        and all(row["verdict"] == "BLOCK" and not row["allowed"]
                for row in intercepted)
    )

    return K.emit({
        "id": "R2-J",
        "title": "Malformed IPv6 URLs raise ValueError out of authorize()",
        "invariant": ("Every proposed transition receives a closed Decision; "
                      "normalize_action never raises; the interceptor converts "
                      "governance errors to BLOCK/fail_closed."),
        "source": [
            "morrison_governance/kernel/destinations.py:classify_destination",
            "morrison_governance/kernel/normalize.py:normalize_action",
            "morrison_governance/kernel/gate.py:authorize",
            "morrison_governance/interception.py:GovernanceInterceptor.check",
        ],
        "severity": "P2/P3",
        "classification": "REPRODUCED",
        "falsified": bool(falsified),
        "cases": cases,
        "control": control,
        "interceptor": intercepted,
        "note": (
            "`urlparse().hostname` can raise for malformed IPv6 literals and "
            "for `[]`. The kernel has no try/except around normalization or "
            "destination resolution, so a direct API caller gets an exception "
            "instead of a BLOCK Decision. The interceptor wraps the call and "
            "does fail closed, so the production seam is not open."),
    })


if __name__ == "__main__":
    main()
