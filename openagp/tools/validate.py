"""CLI: validate a JSON file against a bundled or external AGP schema.

Used by spec/.github/workflows/validate.yml to run schema CI on every fixture
without requiring jsonschema to be installed standalone.

    python -m openagp.tools.validate \\
      --kind event --instance fixtures/events/01-tool-call-allowed.json

    python -m openagp.tools.validate \\
      --schema schemas/event.json \\
      --instance fixtures/events/01-tool-call-allowed.json

Exit codes:
    0  passed
    1  validation failed
    2  bad CLI usage
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from openagp._schema import SchemaValidationError
from openagp._schema import validate as bundled_validate


def _validate_external(schema_path: Path, instance_path: Path) -> int:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    instance = json.loads(instance_path.read_text(encoding="utf-8"))

    common_path = schema_path.parent / "common.json"
    if common_path.exists():
        common = json.loads(common_path.read_text(encoding="utf-8"))
        common_resource = Resource.from_contents(common)
        registry = Registry().with_resources([
            ("common.json", common_resource),
            (common.get("$id", ""), common_resource),
        ])
    else:
        registry = Registry()

    validator = Draft202012Validator(schema, registry=registry)
    errors = sorted(validator.iter_errors(instance), key=lambda e: e.path)
    if not errors:
        print(f"OK  {instance_path}  (against {schema_path.name})")
        return 0

    for err in errors:
        path = "/".join(str(p) for p in err.absolute_path) or "<root>"
        print(f"FAIL  {instance_path} at {path}: {err.message}", file=sys.stderr)
    return 1


def _validate_bundled(kind: str, instance_path: Path) -> int:
    instance = json.loads(instance_path.read_text(encoding="utf-8"))
    try:
        bundled_validate(instance, kind=kind)
    except SchemaValidationError as exc:
        print(f"FAIL  {instance_path}: {exc}", file=sys.stderr)
        return 1
    print(f"OK  {instance_path}  (against bundled {kind} schema)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m openagp.tools.validate",
        description="Validate a JSON instance against an AGP schema.",
    )
    parser.add_argument("--instance", required=True, type=Path,
                        help="Path to the JSON file to validate.")
    parser.add_argument("--schema", type=Path,
                        help="Path to a JSON Schema file. If omitted, --kind is required.")
    parser.add_argument("--kind",
                        help="Bundled schema kind: event | policy | decision-request | decision-response | discovery.")
    args = parser.parse_args(argv)

    if not args.instance.exists():
        parser.error(f"instance not found: {args.instance}")

    if args.schema is not None:
        if not args.schema.exists():
            parser.error(f"schema not found: {args.schema}")
        return _validate_external(args.schema, args.instance)

    if args.kind is None:
        parser.error("either --schema or --kind is required")
    return _validate_bundled(args.kind, args.instance)


if __name__ == "__main__":
    sys.exit(main())
