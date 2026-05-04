# openagp/sdk-python

**Reference Python SDK for AGP — vendor-side and plane-side.**

[![PyPI](https://img.shields.io/pypi/v/openagp.svg?style=flat-square&color=2a6db8)](https://pypi.org/project/openagp/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg?style=flat-square)](LICENSE)
[![Spec](https://img.shields.io/badge/spec-v0.1%20draft-blue.svg?style=flat-square)](https://github.com/openagp/spec/blob/main/concept-and-spec.md)

## Install

```bash
pip install openagp
```

Python 3.10+. Runtime depends on `cryptography`, `rfc8785`, `jsonschema`, `referencing`.

## Quick start

```python
from openagp import generate_keypair, sign, verify, InvalidSignature

# vendor side
keys = generate_keypair()

event = {
    "agp_version": "0.1",
    "schema_version": "1.0",
    "event_id": "evt_01JFXY8B5Z9RHQXM3WTNPK4VG2",
    "occurred_at": "2026-08-12T14:23:11.412Z",
    "actor": {
        "vendor": "yourcompany.com",
        "agent_id": "agt_42",
    },
    "action": {
        "type": "tool_call",
        "tool_name": "browser.navigate",
    },
}

signed = sign(event, private_key_b64=keys.private_key_b64, key_id="yourcompany-2026-q2")

# plane side
verify(signed, public_key_b64=keys.public_key_b64)   # raises InvalidSignature on tamper
```

## What the SDK does (and doesn't)

**Implements** — per [ADR 0001](https://github.com/openagp/spec/blob/main/decisions/0001-signature-canonicalization.md):
- RFC 8785 JCS canonicalization
- Ed25519 sign / verify
- JSON Schema validation against bundled v0.1 schemas (Draft 2020-12)
- Tamper detection via signature
- Algorithm-substitution rejection (only `Ed25519` is accepted)

**Does NOT implement yet** (Phase 1+):
- HTTP client / server scaffolds (FastAPI vendor + plane apps)
- Policy DSL evaluation
- Real-time decision callback (Flow C)
- Registry resolution and key rotation
- Replay-cache / `event_id` deduplication

## Schemas

The SDK ships a bundled copy of every AGP JSON Schema under `openagp/_schemas/`. These are kept in lockstep with the canonical schemas in [`openagp/spec`](https://github.com/openagp/spec/tree/main/schemas) — CI fails if they drift. To sync after pulling the latest spec:

```bash
scripts/sync-schemas.sh
```

## Tests

```bash
pip install -e ".[dev]"
pytest
```

Tests load fixtures from a sibling checkout of `openagp/spec`. CI clones both repos automatically.

## CLI

A small validator CLI ships with the SDK:

```bash
python -m openagp.tools.validate --kind event --instance path/to/event.json
python -m openagp.tools.validate --schema schemas/event.json --instance fixtures/events/01-tool-call-allowed.json
```

## Status

Scaffold + Phase 0 sign/verify roundtrip. The full Phase 1 SDK is in progress (see [§4.2 Phase 1](https://github.com/openagp/spec/blob/main/concept-and-spec.md#42-build-order--what-claude-code-should-build-first) of the spec).

## License

[Apache-2.0](LICENSE).
