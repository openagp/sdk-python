"""RFC 8785 JCS (JSON Canonicalization Scheme) — thin wrapper.

Per ADR 0001, AGP uses RFC 8785 to produce deterministic byte sequences for
signing. This module wraps the `rfc8785` PyPI library so the rest of the SDK
imports `canonicalize` from one place; if we ever need to swap the
implementation, only this file changes.
"""

from __future__ import annotations

import rfc8785


def canonicalize(obj: object) -> bytes:
    """Return the RFC 8785 canonical JSON encoding of `obj` as UTF-8 bytes.

    The returned bytes are the input to AGP's signing algorithm. Cross-language
    interop requires every implementation to produce identical bytes for the
    same input — that's RFC 8785's whole purpose.
    """
    return rfc8785.dumps(obj)
