"""
Ed25519 signature VERIFICATION — pure Python standard library (RFC 8032).

Vendored into the governance kernel so independent evidence attestation
(kernel/attestation.py) is self-contained and stdlib-only. Kept byte-compatible
with governance-service/ed25519_verify.py.

Why this exists: Guardian OS Sovereign ships signed policy bundles into
air-gapped environments. The engine must be able to prove a bundle came from the
publisher before it compiles a single Ω rule from it — and the engine takes no
third-party dependencies (see requirements.txt: fastapi/uvicorn/pydantic for the
service; the governance kernel itself is stdlib-only). `cryptography` is not
available and must not become required, so the RFC 8032 §5.1.7 verification
routine is implemented here directly over `int` arithmetic and `hashlib`.

VERIFY ONLY. There is deliberately no signing routine: a sovereign runtime never
needs a private key, and not having one in the codebase is a supply-chain
property worth keeping. Bundles are signed by the publisher with Node's
`crypto.sign` (lib/sovereign/bundle.js); CI proves the two interoperate
(scripts/sovereign/crosslang.test.cjs).

NOT constant-time. Verification operates purely on public values (public key,
message, signature), so timing carries no secret. Do not repurpose this module
for anything involving a private key.
"""

from __future__ import annotations

import hashlib

# Curve25519 / edwards25519 parameters (RFC 8032 §5.1).
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _sha512(b: bytes) -> bytes:
    return hashlib.sha512(b).digest()


# Points are extended homogeneous coordinates (X, Y, Z, T) with x = X/Z,
# y = Y/Z, x*y = T/Z — addition is then complete (no special cases).
def _point_add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _point_mul(s: int, p):
    q = (0, 1, 1, 0)  # neutral element
    while s > 0:
        if s & 1:
            q = _point_add(q, p)
        p = _point_add(p, p)
        s >>= 1
    return q


def _point_equal(p, q) -> bool:
    # x1/z1 == x2/z2  and  y1/z1 == y2/z2, compared without division.
    if (p[0] * q[2] - q[0] * p[2]) % _P != 0:
        return False
    if (p[1] * q[2] - q[1] * p[2]) % _P != 0:
        return False
    return True


def _recover_x(y: int, sign: int):
    """The x coordinate matching y on the curve, with the requested sign bit."""
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None  # not a square → not a curve point
    if (x & 1) != sign:
        x = _P - x
    return x


_G_Y = 4 * pow(5, _P - 2, _P) % _P
_G_X = _recover_x(_G_Y, 0)
_G = (_G_X, _G_Y, 1, _G_X * _G_Y % _P)


def _point_decompress(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True iff `signature` is a valid Ed25519 signature of `message` under the
    raw 32-byte `public_key`. Never raises — a malformed key or signature is
    simply not a valid signature (fail-closed at the call site)."""
    try:
        if len(public_key) != 32 or len(signature) != 64:
            return False
        a = _point_decompress(public_key)
        if a is None:
            return False
        r_bytes, s_bytes = signature[:32], signature[32:]
        r = _point_decompress(r_bytes)
        if r is None:
            return False
        s = int.from_bytes(s_bytes, "little")
        if s >= _L:  # non-canonical S — reject (RFC 8032 §5.1.7)
            return False
        h = int.from_bytes(_sha512(r_bytes + public_key + message), "little") % _L
        return _point_equal(_point_mul(s, _G), _point_add(r, _point_mul(h, a)))
    except Exception:  # noqa: BLE001 — any parse failure is "not verified"
        return False
