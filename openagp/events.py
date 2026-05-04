"""AGP signed-event handling: sign and verify per ADR 0001.

The signing protocol — every byte of it — is specified in
`openagp/spec/decisions/0001-signature-canonicalization.md`. This module is
the canonical reference Python implementation. Cross-language interop is
verified against this implementation.
"""

from __future__ import annotations

import base64
import copy
from typing import Any

from cryptography.exceptions import InvalidSignature as _CryptoInvalidSignature

from openagp._canonical import canonicalize
from openagp._schema import SchemaValidationError, validate
from openagp.keys import _load_private, _load_public

SIG_ALG = "Ed25519"


class InvalidSignature(ValueError):
    """Raised when a message's signature does not verify."""


def _build_signing_input(message: dict[str, Any], *, key_id: str) -> bytes:
    """Construct the canonical signing input per ADR 0001 §To sign step 1-2.

    Sets `signature` to `{"key_id": ..., "alg": "Ed25519"}` (no value field),
    then JCS-canonicalizes the entire message. Returned bytes are what
    Ed25519 signs over.
    """
    msg = copy.deepcopy(message)
    msg["signature"] = {"key_id": key_id, "alg": SIG_ALG}
    return canonicalize(msg)


def sign(
    message: dict[str, Any],
    *,
    private_key_b64: str,
    key_id: str,
    kind: str = "event",
) -> dict[str, Any]:
    """Sign an AGP message in place per ADR 0001.

    Returns a new dict with `signature.value` populated. Does not mutate the
    input. The message is schema-validated AFTER signing — if you want
    pre-validation, call validate(message, kind=kind) yourself first (with
    a placeholder signature).

    `kind` controls which schema the result must match. Default is 'event'.
    """
    if not isinstance(message, dict):
        raise TypeError("message must be a dict")

    sk = _load_private(private_key_b64)
    signing_input = _build_signing_input(message, key_id=key_id)
    sig_bytes = sk.sign(signing_input)
    sig_b64 = base64.b64encode(sig_bytes).decode("ascii")

    signed = copy.deepcopy(message)
    signed["signature"] = {
        "key_id": key_id,
        "alg": SIG_ALG,
        "value": sig_b64,
    }

    validate(signed, kind=kind)
    return signed


def verify(
    message: dict[str, Any],
    *,
    public_key_b64: str,
    kind: str = "event",
) -> None:
    """Verify an AGP message per ADR 0001.

    Steps:
    1. Schema-validate the message.
    2. Reject unsupported signature.alg values.
    3. Reconstruct the canonical signing input (signature without value).
    4. Verify the Ed25519 signature against `public_key_b64`.

    Raises:
        SchemaValidationError: message is malformed.
        InvalidSignature:      signature does not verify or is missing.
    """
    if not isinstance(message, dict):
        raise TypeError("message must be a dict")

    validate(message, kind=kind)

    sig = message.get("signature")
    if not isinstance(sig, dict) or "value" not in sig:
        raise InvalidSignature("message has no signature.value")
    if sig.get("alg") != SIG_ALG:
        raise InvalidSignature(
            f"unsupported signature.alg {sig.get('alg')!r}; v0.1 requires {SIG_ALG!r}"
        )

    try:
        sig_bytes = base64.b64decode(sig["value"].encode("ascii"), validate=True)
    except (ValueError, TypeError) as exc:
        raise InvalidSignature(f"signature.value is not valid base64: {exc}") from exc

    pk = _load_public(public_key_b64)
    signing_input = _build_signing_input(message, key_id=sig["key_id"])

    try:
        pk.verify(sig_bytes, signing_input)
    except _CryptoInvalidSignature as exc:
        raise InvalidSignature("Ed25519 verification failed") from exc


__all__ = [
    "sign",
    "verify",
    "InvalidSignature",
    "SchemaValidationError",
    "SIG_ALG",
]
