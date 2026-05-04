"""Ed25519 keypair generation and serialization helpers.

AGP v0.1 uses Ed25519 only; see ADR 0001. Keys are stored as raw 32-byte
seeds (private) / 32-byte public-key bytes. Higher-level identity, key
rotation, and registry interaction live elsewhere — this module only
manufactures and (de)serializes raw key material.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


@dataclass(frozen=True)
class KeyPair:
    """Ed25519 keypair. `private_key_b64` and `public_key_b64` are
    standard-base64-encoded raw key bytes (32 bytes each, 44 base64 chars
    with padding). Use these as the source of truth for storage and
    `.well-known/agp` discovery documents.
    """

    private_key_b64: str
    public_key_b64: str


def generate_keypair() -> KeyPair:
    """Generate a fresh Ed25519 keypair.

    Returned bytes are NOT secret-derived from any deterministic seed —
    real callers should manage keys via a KMS / HSM. This helper exists for
    SDK examples and tests.
    """
    sk = Ed25519PrivateKey.generate()
    private_raw = sk.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    public_raw = sk.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    return KeyPair(
        private_key_b64=base64.b64encode(private_raw).decode("ascii"),
        public_key_b64=base64.b64encode(public_raw).decode("ascii"),
    )


def _load_private(private_key_b64: str) -> Ed25519PrivateKey:
    raw = base64.b64decode(private_key_b64.encode("ascii"))
    return Ed25519PrivateKey.from_private_bytes(raw)


def _load_public(public_key_b64: str) -> Ed25519PublicKey:
    raw = base64.b64decode(public_key_b64.encode("ascii"))
    return Ed25519PublicKey.from_public_bytes(raw)
