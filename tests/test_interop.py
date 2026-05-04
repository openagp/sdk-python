"""Cross-language interop assertions against the spec's canonical vectors.

The vectors in `openagp/spec/test-vectors/` are the contract that makes
signatures interoperate across Python, TypeScript, and any future SDK.
They are generated from the Python reference implementation; if Python
output ever diverges from the committed vectors, this test fails — which
means a refactor accidentally changed the protocol's wire bytes.

The TypeScript SDK has a parallel test (tests/roundtrip.test.ts) that
asserts the same things against the same files. If either test fails,
cross-language interop is broken and the corresponding SDK is non-conformant.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from openagp import sign, verify
from openagp._canonical import canonicalize
from openagp.events import _build_signing_input


VECTORS_DIR = Path(__file__).resolve().parents[2] / "spec" / "test-vectors"


def _load(name: str) -> dict:
    return json.loads((VECTORS_DIR / name).read_text(encoding="utf-8"))


def test_vectors_directory_present() -> None:
    assert VECTORS_DIR.is_dir(), (
        f"expected test vectors at {VECTORS_DIR} — check that openagp/spec is "
        f"a sibling of openagp/sdk-python"
    )


@pytest.mark.parametrize(
    "vector",
    _load("v0.1-canonicalization.json")["vectors"]
    if VECTORS_DIR.is_dir()
    else [],
    ids=lambda v: v["name"],
)
def test_canonicalization_vector_matches(vector: dict) -> None:
    """Canonical bytes for each vector must match the committed reference."""
    got = canonicalize(vector["input"])
    assert got.hex() == vector["expected_canonical_utf8_hex"], (
        f"canonicalization drift on vector {vector['name']!r}"
    )


@pytest.mark.parametrize(
    "vector",
    _load("v0.1-signatures.json")["vectors"]
    if VECTORS_DIR.is_dir()
    else [],
    ids=lambda v: v["name"],
)
def test_signing_input_bytes_match(vector: dict) -> None:
    """Bytes fed to Ed25519 sign() must match the committed reference."""
    signing_input = _build_signing_input(vector["input"], key_id=vector["key_id"])
    assert signing_input.hex() == vector["expected_signing_input_utf8_hex"], (
        f"signing-input drift on vector {vector['name']!r}"
    )


@pytest.mark.parametrize(
    "vector",
    _load("v0.1-signatures.json")["vectors"]
    if VECTORS_DIR.is_dir()
    else [],
    ids=lambda v: v["name"],
)
def test_signature_bytes_match(vector: dict) -> None:
    """Ed25519 signatures are deterministic — same key + same input MUST
    produce the same signature in every conformant implementation."""
    test_data = _load("v0.1-signatures.json")
    keypair = test_data["test_keypair"]

    signed = sign(
        vector["input"],
        private_key_b64=keypair["private_key_b64"],
        key_id=vector["key_id"],
        kind="event",
    )
    assert signed["signature"]["value"] == vector["expected_signature_b64"], (
        f"signature drift on vector {vector['name']!r}"
    )

    # Also verify the committed signature roundtrips (catches the case where
    # we accidentally change the protocol such that we still produce a valid
    # signature, but a different one).
    verify(signed, public_key_b64=keypair["public_key_b64"], kind="event")
