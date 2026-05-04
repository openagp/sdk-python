#!/usr/bin/env bash
# Sync canonical schemas from openagp/spec into the SDK's bundled copy.
# Run from the sdk-python repo root with the spec repo checked out as a sibling:
#
#   /workspace/openagp/spec/      <- canonical source
#   /workspace/openagp/sdk-python/ <- this repo
#
# Usage:
#   scripts/sync-schemas.sh [path-to-spec-repo]
#
# The script copies schemas/ into openagp/_schemas/ and fails if anything
# changed (so you can use it in CI to detect drift between the two repos).

set -euo pipefail

SDK_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SPEC_DIR="${1:-${SDK_ROOT}/../spec}"

if [[ ! -d "${SPEC_DIR}/schemas" ]]; then
  echo "error: ${SPEC_DIR}/schemas not found" >&2
  echo "       pass the spec repo path as the first arg, or check it out at ../spec" >&2
  exit 2
fi

DEST="${SDK_ROOT}/openagp/_schemas"
mkdir -p "${DEST}"

CHANGED=0
for f in "${SPEC_DIR}/schemas"/*.json; do
  name="$(basename "$f")"
  if ! cmp -s "$f" "${DEST}/${name}"; then
    cp "$f" "${DEST}/${name}"
    echo "updated: ${name}"
    CHANGED=1
  fi
done

if [[ "${CHANGED}" -eq 0 ]]; then
  echo "schemas already in sync"
fi

# Honor --check / CI usage: exit non-zero if anything changed.
if [[ "${1:-}" == "--check" ]] || [[ "${CI:-}" == "true" ]]; then
  exit "${CHANGED}"
fi
