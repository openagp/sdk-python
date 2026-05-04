"""AGP policy DSL evaluator (Flow B / L2).

Given a policy descriptor and an event (or proposed action), produce a
Decision: which rule fired, what the resulting decision is, and why.

This implementation follows spec §3.5. The DSL grammar is intentionally
small for v0.1 — see the matcher list in
`openagp/spec/fixtures/policies/README.md`. v0.2 will publish a formal
JSON Schema for the DSL with an extended grammar.

Evaluation semantics (locked for v0.1):

  - Rules are evaluated in order. First-match-wins.
  - Within a rule, ALL conditions in `when` must match (AND semantics).
  - If no rule matches, the policy's `fallback.decision` applies. If no
    fallback is declared, the default is `allowed`.
  - The evaluator is pure: same (policy, event) -> same decision, every time.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse


@dataclass(frozen=True)
class Decision:
    """The outcome of evaluating a policy against an event.

    `decision` is one of: 'allowed', 'blocked', 'logged_only'. `rule_id` is
    the identifier of the firing rule, or 'fallback' if no rule matched.
    `reason` is the matched rule's `then.reason`, or a synthesized string
    for fallback. `annotate` carries any `then.annotate` payload (e.g. SCF
    controls) — empty dict if none.
    """

    decision: str
    rule_id: str
    reason: str
    annotate: dict[str, Any]

    def to_event_policy_block(self, *, policy_hash: str) -> dict[str, Any]:
        """Render this Decision as the `policy` block of an L2 event."""
        block: dict[str, Any] = {
            "decision": self.decision,
            "rule_id": self.rule_id,
            "policy_hash": policy_hash,
        }
        if self.reason:
            block["rationale"] = self.reason
        return block


class PolicyEvaluationError(ValueError):
    """Raised when a policy descriptor is malformed or uses an unsupported matcher."""


# === Field-path resolution ===================================================


def _resolve_path(event: dict[str, Any], path: str) -> Any:
    """Walk a dotted path into the event. Missing keys yield None."""
    cur: Any = event
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


# === Matchers ================================================================


def _match_equals(actual: Any, expected: Any) -> bool:
    return actual == expected


def _match_not_equals(actual: Any, expected: Any) -> bool:
    return actual != expected


def _match_in(actual: Any, expected: list[Any]) -> bool:
    return actual in expected


def _match_not_in(actual: Any, expected: list[Any]) -> bool:
    return actual not in expected


def _match_starts_with(actual: Any, prefix: Any) -> bool:
    return isinstance(actual, str) and isinstance(prefix, str) and actual.startswith(prefix)


def _match_ends_with(actual: Any, suffix: Any) -> bool:
    return isinstance(actual, str) and isinstance(suffix, str) and actual.endswith(suffix)


def _match_contains_pattern(actual: Any, pattern: Any) -> bool:
    if not isinstance(actual, str) or not isinstance(pattern, str):
        return False
    try:
        return re.search(pattern, actual) is not None
    except re.error as exc:
        raise PolicyEvaluationError(
            f"contains_pattern: invalid regex {pattern!r}: {exc}"
        ) from exc


def _extract_host(value: str) -> str | None:
    """Extract a hostname from a URL or email-like string. Returns None if
    no host could be parsed."""
    if "@" in value and "/" not in value:
        # Looks like an email address.
        _, _, host = value.partition("@")
        return host.lower() or None
    parsed = urlparse(value)
    host = parsed.hostname
    if host:
        return host.lower()
    # Bare hostname without scheme?
    if "/" not in value and "." in value:
        return value.lower()
    return None


def _domain_matches(host: str, pattern: str) -> bool:
    """Match a hostname against an exact or wildcard pattern.

    `acme.com`   matches `acme.com` exactly (not subdomains).
    `*.acme.com` matches any subdomain of `acme.com` (one or more labels).
    """
    pattern = pattern.lower()
    host = host.lower()
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".acme.com"
        return host.endswith(suffix) and host != suffix.lstrip(".")
    return host == pattern


def _match_domain_in(actual: Any, patterns: list[Any]) -> bool:
    if not isinstance(actual, str):
        return False
    host = _extract_host(actual)
    if host is None:
        return False
    return any(
        isinstance(p, str) and _domain_matches(host, p) for p in patterns
    )


def _match_domain_not_in(actual: Any, patterns: list[Any]) -> bool:
    if not isinstance(actual, str):
        # Non-string fields cannot be tested for domain membership; the
        # safer default is "not in any of these domains" -> True for blocks.
        # We follow the spec's "all conditions AND" semantics: a missing or
        # non-URL field means the condition trivially does NOT match a
        # domain-based policy. For block-on-not-in semantics this means the
        # rule does not fire on missing data — surface via fallback instead.
        return False
    host = _extract_host(actual)
    if host is None:
        return False
    return not any(
        isinstance(p, str) and _domain_matches(host, p) for p in patterns
    )


_MATCHERS = {
    "equals": _match_equals,
    "eq": _match_equals,
    "not_equals": _match_not_equals,
    "ne": _match_not_equals,
    "in": _match_in,
    "not_in": _match_not_in,
    "starts_with": _match_starts_with,
    "ends_with": _match_ends_with,
    "contains_pattern": _match_contains_pattern,
    "domain_in": _match_domain_in,
    "domain_not_in": _match_domain_not_in,
}


# === Rule evaluation =========================================================


def _condition_matches(
    field_path: str,
    condition: Any,
    event: dict[str, Any],
) -> bool:
    """Evaluate a single `when` entry against the event.

    `condition` is either a literal (equality) or a one-key matcher object.
    """
    actual = _resolve_path(event, field_path)

    # Literal -> equality match.
    if not isinstance(condition, dict):
        return actual == condition

    if len(condition) != 1:
        raise PolicyEvaluationError(
            f"matcher object on {field_path!r} must have exactly one key, got {list(condition)}"
        )
    matcher_name, arg = next(iter(condition.items()))

    matcher = _MATCHERS.get(matcher_name)
    if matcher is None:
        raise PolicyEvaluationError(
            f"unsupported matcher {matcher_name!r} on {field_path!r}; "
            f"v0.1 supports {sorted(_MATCHERS)}"
        )
    return matcher(actual, arg)


def _rule_matches(rule: dict[str, Any], event: dict[str, Any]) -> bool:
    when = rule.get("when") or {}
    if not isinstance(when, dict):
        raise PolicyEvaluationError(f"rule {rule.get('id')!r}: when must be an object")
    return all(
        _condition_matches(path, cond, event) for path, cond in when.items()
    )


def _applies_to(policy: dict[str, Any], event: dict[str, Any]) -> bool:
    """Honor the policy's `applies_to` block. A missing block applies to all."""
    applies_to = policy.get("applies_to") or {}

    vendors = applies_to.get("vendors")
    if vendors:
        ev_vendor = _resolve_path(event, "actor.vendor")
        if not any(v == "*" or v == ev_vendor for v in vendors):
            return False

    agents = applies_to.get("agents")
    if agents:
        ev_agent = _resolve_path(event, "actor.agent_id")
        if not any(a == "*" or a == ev_agent for a in agents):
            return False

    actions = applies_to.get("actions")
    if actions:
        ev_action_type = _resolve_path(event, "action.type")
        if ev_action_type not in actions:
            return False

    return True


# === Public API ==============================================================


def evaluate(policy: dict[str, Any], event: dict[str, Any]) -> Decision:
    """Evaluate `policy` against `event` and return a Decision.

    Pure function: no I/O, no logging, no exceptions for normal control flow.
    Raises PolicyEvaluationError only for malformed policies.
    """
    if not isinstance(policy, dict) or not isinstance(event, dict):
        raise TypeError("evaluate(policy, event) requires both arguments to be dicts")

    if not _applies_to(policy, event):
        return _fallback_decision(policy, reason="policy does not apply to this event")

    rules = policy.get("rules") or []
    for rule in rules:
        if _rule_matches(rule, event):
            then = rule.get("then") or {}
            return Decision(
                decision=then.get("decision") or "allowed",
                rule_id=rule.get("id") or "<unnamed>",
                reason=then.get("reason") or "",
                annotate=dict(then.get("annotate") or {}),
            )

    return _fallback_decision(policy, reason="no rule matched")


def _fallback_decision(policy: dict[str, Any], *, reason: str) -> Decision:
    fallback = policy.get("fallback") or {}
    raw_decision = fallback.get("decision")

    # Normalize fallback decision codes (allow_with_log -> allowed) to the
    # event-side decision vocabulary while preserving intent.
    if raw_decision == "allow_with_log":
        decision = "logged_only"
    elif raw_decision == "block":
        decision = "blocked"
    elif raw_decision in ("allowed", "blocked", "logged_only"):
        decision = raw_decision
    else:
        decision = "allowed"

    return Decision(
        decision=decision,
        rule_id="fallback",
        reason=reason,
        annotate={},
    )
