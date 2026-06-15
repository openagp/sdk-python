"""JSON Schema loading and validation for AGP messages.

Schemas are bundled with the SDK under `openagp/_schemas/` and kept in sync
with `openagp/spec/schemas/` via `scripts/sync-schemas.sh`. CI fails if the
two diverge.
"""

from __future__ import annotations

import json
from importlib import resources
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource


class SchemaValidationError(ValueError):
    """Raised when a message does not match its JSON Schema."""


_SCHEMA_NAMES = (
    "common.json",
    "event.json",
    "policy.json",
    "decision-request.json",
    "decision-response.json",
    "discovery.json",
    "actor.json",
)


def _load_bundled(name: str) -> dict[str, Any]:
    files = resources.files("openagp._schemas")
    text = (files / name).read_text(encoding="utf-8")
    return json.loads(text)


def _build_registry() -> Registry:
    """Build a referencing.Registry that resolves `common.json#/$defs/...`
    references against the bundled common schema. The other schemas use bare
    `common.json` references (no host), so we map both `common.json` and the
    canonical `https://openagp.io/...` URI to the bundled copy.
    """
    common = _load_bundled("common.json")
    common_resource = Resource.from_contents(common)
    return Registry().with_resources([
        ("common.json", common_resource),
        (common.get("$id", ""), common_resource),
    ])


_REGISTRY = _build_registry()


def _validator_for(schema_name: str) -> Draft202012Validator:
    schema = _load_bundled(schema_name)
    return Draft202012Validator(schema, registry=_REGISTRY)


def validate(message: dict[str, Any], *, kind: str = "event") -> None:
    """Validate `message` against the bundled schema for `kind`.

    Raises SchemaValidationError on failure. Returns None on success.

    `kind` is one of: 'event', 'policy', 'decision-request',
    'decision-response', 'discovery', 'actor'.
    """
    schema_name = f"{kind}.json"
    if schema_name not in _SCHEMA_NAMES:
        raise ValueError(
            f"unknown message kind {kind!r}; "
            f"expected one of {[n.removesuffix('.json') for n in _SCHEMA_NAMES if n != 'common.json']}"
        )
    validator = _validator_for(schema_name)
    errors = sorted(validator.iter_errors(message), key=lambda e: e.path)
    if errors:
        first = errors[0]
        path = "/".join(str(p) for p in first.absolute_path) or "<root>"
        raise SchemaValidationError(
            f"{kind} schema validation failed at {path}: {first.message}"
            + (f"  (+{len(errors) - 1} more error(s))" if len(errors) > 1 else "")
        )
