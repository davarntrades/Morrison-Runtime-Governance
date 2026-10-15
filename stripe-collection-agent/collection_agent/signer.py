"""External Ed25519 lease signer.

Morrison's kernel is deliberately private-key-free (`kernel/ed25519.py` is
verify-only) and `GovernanceKernel.mint_lease` requires an EXTERNAL signer.
This is that signer, held only by the governance service. The Stripe executor
receives the public key alone.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat,
)


class LeaseSigner:
    def __init__(self) -> None:
        self._key = Ed25519PrivateKey.generate()

    def __call__(self, payload: bytes) -> bytes:
        return self._key.sign(payload)

    @property
    def public_key(self) -> bytes:
        return self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
