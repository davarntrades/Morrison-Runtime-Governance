"""TEST-ONLY Ed25519 signer (RFC 8032 §5.1.6).

The production package is deliberately private-key-free: `kernel/ed25519.py` is
verify-only, mirroring the supply-chain stance of the sovereign bundle verifier.
Attestations are signed by an EXTERNAL notary, not by anything shipped here.

This module exists solely so the test suite can mint an attestation to verify
against. It is not imported by any runtime code path — importing it from
production code would defeat the property it is protecting.
"""

from __future__ import annotations

import hashlib

from morrison_governance.kernel.ed25519 import (
    _L, _P, _point_add, _point_mul, _sha512,
)

# Base point B (RFC 8032 §5.1).
_G_Y = 4 * pow(5, _P - 2, _P) % _P
_D = -121665 * pow(121666, _P - 2, _P) % _P


def _recover_x(y: int, sign: int):
    from morrison_governance.kernel.ed25519 import _recover_x as rx
    return rx(y, sign)


_G_X = _recover_x(_G_Y, 0)
_B = (_G_X, _G_Y, 1, _G_X * _G_Y % _P)


def _compress(p) -> bytes:
    zinv = pow(p[2], _P - 2, _P)
    x = p[0] * zinv % _P
    y = p[1] * zinv % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _secret_expand(secret: bytes):
    h = _sha512(secret)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(secret: bytes) -> bytes:
    """Raw 32-byte public key for a 32-byte seed."""
    a, _ = _secret_expand(secret)
    return _compress(_point_mul(a, _B))


def sign(secret: bytes, message: bytes) -> bytes:
    """64-byte Ed25519 signature. TEST USE ONLY."""
    a, prefix = _secret_expand(secret)
    pub = _compress(_point_mul(a, _B))
    r = int.from_bytes(_sha512(prefix + message), "little") % _L
    big_r = _compress(_point_mul(r, _B))
    k = int.from_bytes(_sha512(big_r + pub + message), "little") % _L
    s = (r + k * a) % _L
    return big_r + int.to_bytes(s, 32, "little")
