"""End-to-end sign/verify roundtrip tests.

Exercises the full ADR 0001 protocol against the canonical event fixtures
shipped in the spec repo. Each fixture's placeholder signature is replaced
with one produced by a fresh test keypair, then verified.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from openagp import (
    InvalidSignature,
    SchemaValidationError,
    canonicalize,
    generate_keypair,
    sign,
    verify,
)
from openagp._canonical import canonicalize as _canonicalize

# Fixtures live in the sibling spec repo's `fixtures/events/` directory,
# checked out at /openagp/spec/. We resolve relative to this test file.
SPEC_FIXTURES = (
    Path(__file__).resolve().parents[2] / "spec" / "fixtures" / "events"
)

EVENT_FIXTURES = sorted(SPEC_FIXTURES.glob("[0-9][0-9]-*.json"))


def _load(fixture: Path) -> dict:
    return json.loads(fixture.read_text(encoding="utf-8"))


def test_fixtures_directory_resolved() -> None:
    """If this test fails, the spec repo isn't checked out at the expected
    sibling path. Other tests in this module are skipped in that case."""
    assert SPEC_FIXTURES.is_dir(), (
        f"expected spec fixtures at {SPEC_FIXTURES} — check that openagp/spec "
        f"is a sibling of openagp/sdk-python"
    )
    assert EVENT_FIXTURES, f"no event fixtures found in {SPEC_FIXTURES}"


@pytest.mark.parametrize(
    "fixture",
    EVENT_FIXTURES,
    ids=[f.name for f in EVENT_FIXTURES],
)
def test_fixture_passes_schema(fixture: Path) -> None:
    """Every shipped fixture must validate against the bundled event schema
    even with its placeholder signature.value."""
    from openagp._schema import validate

    event = _load(fixture)
    validate(event, kind="event")


@pytest.mark.parametrize(
    "fixture",
    EVENT_FIXTURES,
    ids=[f.name for f in EVENT_FIXTURES],
)
def test_sign_verify_roundtrip(fixture: Path) -> None:
    """Replace each fixture's placeholder signature with a real Ed25519
    signature from a fresh keypair, then verify it. End-to-end exercises
    canonicalization, sign, verify, and schema validation."""
    event = _load(fixture)
    keypair = generate_keypair()

    signed = sign(
        event,
        private_key_b64=keypair.private_key_b64,
        key_id=event["signature"]["key_id"],
        kind="event",
    )

    # The signature value must have changed away from the fixture placeholder.
    assert signed["signature"]["value"] != event["signature"]["value"]
    assert len(signed["signature"]["value"]) == 88

    verify(signed, public_key_b64=keypair.public_key_b64, kind="event")


def test_tamper_detection_field_change() -> None:
    """If a single byte of the signed message changes after signing, verify
    must fail. This is the core security property of the protocol."""
    event = _load(EVENT_FIXTURES[0])
    keypair = generate_keypair()

    signed = sign(
        event,
        private_key_b64=keypair.private_key_b64,
        key_id="test-key",
        kind="event",
    )

    # Tamper with a non-signature field.
    tampered = copy.deepcopy(signed)
    tampered["action"]["tool_name"] = "evil.tool"

    with pytest.raises(InvalidSignature):
        verify(tampered, public_key_b64=keypair.public_key_b64, kind="event")


def test_tamper_detection_wrong_public_key() -> None:
    """Verifying with the wrong public key must fail — even if the message
    is otherwise pristine."""
    event = _load(EVENT_FIXTURES[0])
    signer_keys = generate_keypair()
    other_keys = generate_keypair()

    signed = sign(
        event,
        private_key_b64=signer_keys.private_key_b64,
        key_id="test-key",
        kind="event",
    )

    with pytest.raises(InvalidSignature):
        verify(signed, public_key_b64=other_keys.public_key_b64, kind="event")


def test_unsupported_alg_rejected() -> None:
    """v0.1 supports Ed25519 only. Any other alg value must be rejected at
    verification time, before signature validation runs."""
    event = _load(EVENT_FIXTURES[0])
    keypair = generate_keypair()

    signed = sign(
        event,
        private_key_b64=keypair.private_key_b64,
        key_id="test-key",
        kind="event",
    )
    signed["signature"]["alg"] = "RS256"

    with pytest.raises(
        (InvalidSignature, SchemaValidationError)
    ):
        verify(signed, public_key_b64=keypair.public_key_b64, kind="event")


def test_canonicalize_is_deterministic() -> None:
    """RFC 8785 produces identical bytes for semantically-equal objects
    regardless of source key order. This is the property AGP signatures
    depend on."""
    a = {"b": 2, "a": 1, "c": [3, 2, 1]}
    b = {"a": 1, "c": [3, 2, 1], "b": 2}
    assert canonicalize(a) == canonicalize(b)


def test_canonicalize_strips_insignificant_whitespace() -> None:
    """Two JSON forms differing only in whitespace must canonicalize to
    identical bytes — otherwise different vendors' serializers would produce
    incompatible signatures."""
    a = json.loads('{"a":1,"b":2}')
    b = json.loads('   {  "a"  :  1 ,  "b"  :  2  }   ')
    assert _canonicalize(a) == _canonicalize(b)


def test_signing_input_omits_signature_value() -> None:
    """ADR 0001 §To sign step 1: the value field MUST be absent during
    canonicalization. If a Python implementation accidentally included the
    placeholder value, signatures would not interoperate cross-language."""
    from openagp.events import _build_signing_input

    event_with_placeholder = {
        "agp_version": "0.1",
        "event_id": "evt_x",
        "actor": {"vendor": "x", "agent_id": "y"},
        "action": {"type": "tool_call"},
        "signature": {
            "key_id": "k1",
            "alg": "Ed25519",
            "value": "PLACEHOLDER",
        },
    }
    event_without = copy.deepcopy(event_with_placeholder)
    event_without["signature"].pop("value")

    a = _build_signing_input(event_with_placeholder, key_id="k1")
    b = _build_signing_input(event_without, key_id="k1")
    assert a == b, "signing input must be identical regardless of pre-existing signature.value"
