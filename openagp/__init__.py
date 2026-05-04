"""OpenAGP — reference Python SDK for the Agent Governance Protocol.

Public API for v0.1:
    from openagp import sign, verify, generate_keypair, InvalidSignature
    from openagp import canonicalize, validate

The signing protocol is specified in ADR 0001 of openagp/spec.
"""

from openagp._canonical import canonicalize
from openagp._schema import validate
from openagp.events import (
    InvalidSignature,
    SchemaValidationError,
    sign,
    verify,
)
from openagp.keys import generate_keypair

__version__ = "0.0.0"

__all__ = [
    "__version__",
    "sign",
    "verify",
    "generate_keypair",
    "canonicalize",
    "validate",
    "InvalidSignature",
    "SchemaValidationError",
]
