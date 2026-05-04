"""Cross-language policy interop assertions.

For every (policy, event) vector in spec/test-vectors/v0.1-policy-decisions.json,
both SDKs must produce identical Decisions. If Python's evaluator drifts from
the committed vectors, this test fails — catching DSL semantic regressions
before they ship to TypeScript or other implementations.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from openagp import evaluate

VECTORS_FILE = (
    Path(__file__).resolve().parents[2]
    / "spec"
    / "test-vectors"
    / "v0.1-policy-decisions.json"
)
POLICIES_DIR = (
    Path(__file__).resolve().parents[2] / "spec" / "fixtures" / "policies"
)


def _load_vectors() -> list[dict]:
    if not VECTORS_FILE.exists():
        return []
    return json.loads(VECTORS_FILE.read_text(encoding="utf-8"))["vectors"]


@pytest.mark.parametrize("vector", _load_vectors(), ids=lambda v: v["name"])
def test_policy_decision_matches_committed_vector(vector: dict) -> None:
    policy = json.loads((POLICIES_DIR / vector["policy_fixture"]).read_text())
    result = evaluate(policy, vector["event"])
    assert result.decision == vector["expected_decision"], (
        f"decision drift on {vector['name']!r}: "
        f"got {result.decision}, expected {vector['expected_decision']}"
    )
    assert result.rule_id == vector["expected_rule_id"], (
        f"rule_id drift on {vector['name']!r}: "
        f"got {result.rule_id}, expected {vector['expected_rule_id']}"
    )
    assert dict(result.annotate) == dict(vector["expected_annotate"]), (
        f"annotate drift on {vector['name']!r}"
    )
