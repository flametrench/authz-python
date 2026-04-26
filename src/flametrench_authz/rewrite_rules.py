# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Authorization rewrite rules — v0.2 reference implementation.

The v0.1 SDK exposed only direct-tuple matching. v0.2 adds a deliberate
subset of Zanzibar userset_rewrite, so applications can declare role
implication ("admin implies editor") and parent-child inheritance ("org
viewer implies project viewer for org-owned projects") without
denormalizing tuples into the store.

See ADR 0007 for the full design rationale. This file implements:

- The rule node types (`This`, `ComputedUserset`, `TupleToUserset`).
- The `Rules` type — a nested dict keyed on ``(object_type, relation)``.
- The evaluation algorithm with cycle detection and depth/fan-out limits.

The implementation is the canonical reference; ports to Node, PHP, and
Java follow this shape with language-idiomatic adaptations.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, Mapping, Sequence, Union

# ─── Rule node types ───────────────────────────────────────────────


@dataclass(frozen=True)
class This:
    """The explicit-tuple set: equivalent to v0.1 ``check()`` semantics.

    A rule that includes ``This()`` is satisfied by any direct tuple
    matching the (subject, relation, object) being checked. In v0.2,
    ``This()`` is always implicitly part of every rule's union — the
    direct-tuple fast path runs before rule expansion and short-circuits
    on a hit. Listing it explicitly is documentation, not behavior.
    """


@dataclass(frozen=True)
class ComputedUserset:
    """Role implication on the same object.

    ``ComputedUserset(relation="editor")`` on a rule for
    ``proj.viewer`` means: anyone holding ``editor`` on this same
    project also has ``viewer``. The check recurses with the same
    object but a different relation.
    """

    relation: str


@dataclass(frozen=True)
class TupleToUserset:
    """Parent-child inheritance via a relation traversal.

    ``TupleToUserset(tupleset_relation="parent_org",
    computed_userset_relation="viewer")`` on a rule for
    ``proj.viewer`` means: enumerate all tuples ``(*, parent_org,
    proj)`` — for each such tuple's *subject* (which will be an
    org-shaped object), recursively check whether the original
    subject has ``viewer`` on that org.

    The two-relation hop is what makes "org member can view all
    projects owned by their org" expressible without per-project
    denormalization.
    """

    tupleset_relation: str
    computed_userset_relation: str


RuleNode = Union[This, ComputedUserset, TupleToUserset]
"""A single primitive in a rule's union."""


# A rule's body is a union of one or more nodes. We model it as a list
# (order-irrelevant; short-circuits on first hit).
Rule = Sequence[RuleNode]

# Rules are keyed on (object_type, relation).
Rules = Mapping[str, Mapping[str, Rule]]


# ─── Evaluation limits ─────────────────────────────────────────────


# Spec floor depth and fan-out; configurable per-store via the
# InMemoryTupleStore constructor.
DEFAULT_MAX_DEPTH = 8
DEFAULT_MAX_FAN_OUT = 1024


# ─── Evaluation ────────────────────────────────────────────────────


@dataclass(frozen=True)
class _Frame:
    """One node on the cycle-detection stack."""

    relation: str
    object_type: str
    object_id: str


@dataclass
class EvaluationResult:
    """Outcome of a rule-aware ``check()`` call.

    ``matched_tuple_id`` is the id of the underlying direct tuple that
    ultimately satisfied the check, walking back through any rewrite
    chain. ``None`` means the check was denied.
    """

    allowed: bool
    matched_tuple_id: str | None


# Type aliases for the lookup callbacks we need from the host store.
DirectLookup = Callable[[str, str, str, str, str], str | None]
"""(subject_type, subject_id, relation, object_type, object_id) → tup_id or None."""

ListByObject = Callable[[str, str, str | None], Iterable[tuple[str, str, str]]]
"""(object_type, object_id, relation) → iterable of (subject_type, subject_id, tup_id)."""


def evaluate(
    *,
    rules: Rules | None,
    subject_type: str,
    subject_id: str,
    relation: str,
    object_type: str,
    object_id: str,
    direct_lookup: DirectLookup,
    list_by_object: ListByObject,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_fan_out: int = DEFAULT_MAX_FAN_OUT,
) -> EvaluationResult:
    """Evaluate ``check()`` with optional rewrite-rule expansion.

    The algorithm is layered exactly as described in ADR 0007:

    1. Direct lookup. If a tuple matches, return it. v0.1-fast path.
    2. Rule expansion. If a rule exists for ``(object_type, relation)``,
       expand its primitives. Each primitive recurses with bounded
       depth and tracks a frame stack for cycle detection.
    3. Short-circuit on first match. Union semantics: any sub-evaluation
       returning ``allowed`` ends the evaluation.

    Cycle detection: per-evaluation, the stack of ``(relation,
    object_type, object_id)`` frames is checked before each recursive
    call. A repeat frame returns ``denied`` for that branch (the cycle
    adds no new information) without raising.

    Bounds: ``max_depth`` is the recursion ceiling (raises
    ``EvaluationLimitExceededError`` if exceeded). ``max_fan_out`` is
    the per-``TupleToUserset`` enumeration ceiling (raises the same).
    """
    # Imported lazily to avoid a top-of-module cycle.
    from .errors import EvaluationLimitExceededError

    def go(
        relation: str,
        object_type: str,
        object_id: str,
        stack: tuple[_Frame, ...],
        depth: int,
    ) -> EvaluationResult:
        # 1. Direct lookup.
        direct = direct_lookup(
            subject_type, subject_id, relation, object_type, object_id
        )
        if direct is not None:
            return EvaluationResult(allowed=True, matched_tuple_id=direct)

        # 2. Rule expansion.
        if rules is None:
            return EvaluationResult(allowed=False, matched_tuple_id=None)
        rule = rules.get(object_type, {}).get(relation)
        if rule is None:
            return EvaluationResult(allowed=False, matched_tuple_id=None)

        # Cycle detection — already visited? abort this branch.
        frame = _Frame(
            relation=relation, object_type=object_type, object_id=object_id
        )
        if frame in stack:
            return EvaluationResult(allowed=False, matched_tuple_id=None)

        # Depth bound.
        if depth >= max_depth:
            raise EvaluationLimitExceededError(
                f"Rule evaluation exceeded depth limit ({max_depth}) "
                f"at {object_type}.{relation} for {object_type}_{object_id}"
            )

        new_stack = (*stack, frame)

        for node in rule:
            if isinstance(node, This):
                # Already covered by step 1 above.
                continue
            if isinstance(node, ComputedUserset):
                result = go(
                    node.relation, object_type, object_id, new_stack, depth + 1
                )
                if result.allowed:
                    return result
                continue
            if isinstance(node, TupleToUserset):
                # Enumerate (*, tupleset_relation, this object).
                related = list(
                    list_by_object(object_type, object_id, node.tupleset_relation)
                )
                if len(related) > max_fan_out:
                    raise EvaluationLimitExceededError(
                        f"tuple_to_userset fan-out exceeded ({len(related)} > {max_fan_out}) "
                        f"at {object_type}.{relation} via {node.tupleset_relation}"
                    )
                for related_subject_type, related_subject_id, _tup_id in related:
                    # The tuple's subject becomes the object for the next hop.
                    result = go(
                        node.computed_userset_relation,
                        related_subject_type,
                        related_subject_id,
                        new_stack,
                        depth + 1,
                    )
                    if result.allowed:
                        return result
                continue
            raise TypeError(f"Unknown rule node: {node!r}")

        return EvaluationResult(allowed=False, matched_tuple_id=None)

    return go(relation, object_type, object_id, stack=(), depth=0)
