# Changelog

All notable changes to `openagp` (Python SDK) are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the SDK is pre-1.0, breaking changes are possible on any minor version bump. Pinning to an exact version (`==0.0.1`) is recommended for production. See [`openagp/spec`](https://github.com/openagp/spec) for the protocol-level compatibility story.

## [Unreleased]

_Nothing yet._

## [0.0.2] — 2026-06-15

### Added

- **`actor` message kind.** `validate`, `sign`, and `verify` now accept `kind="actor"` for signing and validating registry actor entries, against the new bundled `actor.json` schema (synced from `openagp/spec`). This is the schema the public [registry](https://github.com/openagp/registry) validates entries against, and lets an actor self-sign its entry with the same ADR-0001 protocol used for events and policies.

## [0.0.1] — 2026-05-04

Initial public release alongside AGP spec `v0.1.0-rc.1`.

### Added

- **Phase 0 — sign / verify roundtrip.**
  - RFC 8785 JCS canonicalization.
  - Ed25519 sign / verify per [ADR 0001](https://github.com/openagp/spec/blob/main/decisions/0001-signature-canonicalization.md).
  - Bundled v0.1 JSON Schemas (`event`, `policy`, `decision-request`, `decision-response`, `discovery`, `common`) under `openagp/_schemas/`, kept in lockstep with the canonical schemas via `scripts/sync-schemas.sh`.
  - `generate_keypair`, `sign`, `verify`, `InvalidSignature` public surface.
  - Algorithm-substitution rejection — only `Ed25519` is accepted.
  - Tamper detection via signature verification.
  - JSON Schema validation against bundled Draft 2020-12 schemas.
  - `python -m openagp.tools.validate` CLI for ad-hoc schema validation.
- **Phase β — policy DSL evaluator (Flow B / L2).**
  - Policy-descriptor evaluator that takes an event and a policy and emits a `Decision`.
  - Test coverage against the cross-language policy decision vectors in `openagp/spec/test-vectors/v0.1-policy-decisions.json`.
- **Cross-language interop.** Test assertions against `openagp/spec/test-vectors/` ensure byte-for-byte parity with the TypeScript SDK and `agp-cts`.
- Apache 2.0 license.

### Known limitations

The following are deliberately out of scope for 0.0.1 and tracked for Phase 1 in [`openagp/spec` §4.2](https://github.com/openagp/spec/blob/main/concept-and-spec.md#42-build-order--what-claude-code-should-build-first):

- HTTP client / server scaffolds (FastAPI vendor + plane apps).
- Real-time decision callback (Flow C / L3).
- Registry resolution and key rotation.
- Replay-cache / `event_id` deduplication.

[Unreleased]: https://github.com/openagp/sdk-python/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/openagp/sdk-python/releases/tag/v0.0.1
