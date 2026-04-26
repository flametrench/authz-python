# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Reference in-memory TupleStore implementation.

O(1) check() via a secondary natural-key index; deterministic for tests.
A Postgres-backed store with proper indexes is planned for production.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

from flametrench_ids import generate

from .errors import (
    DuplicateTupleError,
    EmptyRelationSetError,
    InvalidFormatError,
    TupleNotFoundError,
)
from .patterns import RELATION_NAME_PATTERN, TYPE_PREFIX_PATTERN
from .rewrite_rules import (
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_FAN_OUT,
    Rules,
    evaluate,
)
from .types import CheckResult, Page, Tuple


def _default_clock() -> datetime:
    return datetime.now(timezone.utc)


class InMemoryTupleStore:
    """O(1) check() via secondary natural-key index; deterministic for tests.

    v0.2 adds optional rewrite-rule support. When ``rules`` is None
    (the default), behavior is byte-identical to v0.1 — a direct
    natural-key lookup is the only check path. When ``rules`` is
    provided, ``check()`` evaluates rules on direct-lookup miss per
    ADR 0007.
    """

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] | None = None,
        rules: Rules | None = None,
        max_depth: int = DEFAULT_MAX_DEPTH,
        max_fan_out: int = DEFAULT_MAX_FAN_OUT,
    ) -> None:
        self._tuples: dict[str, Tuple] = {}
        self._key_index: dict[str, str] = {}  # natural-key → tup id
        self._clock = clock or _default_clock
        self._rules = rules
        self._max_depth = max_depth
        self._max_fan_out = max_fan_out

    @staticmethod
    def _natural_key(
        subject_type: str,
        subject_id: str,
        relation: str,
        object_type: str,
        object_id: str,
    ) -> str:
        return f"{subject_type}|{subject_id}|{relation}|{object_type}|{object_id}"

    @staticmethod
    def _validate(relation: str, object_type: str) -> None:
        if not RELATION_NAME_PATTERN.match(relation):
            raise InvalidFormatError(
                f"relation '{relation}' must match {RELATION_NAME_PATTERN.pattern}",
                field="relation",
            )
        if not TYPE_PREFIX_PATTERN.match(object_type):
            raise InvalidFormatError(
                f"object_type '{object_type}' must match {TYPE_PREFIX_PATTERN.pattern}",
                field="object_type",
            )

    # ─── Mutations ───

    def create_tuple(
        self,
        subject_type: str,
        subject_id: str,
        relation: str,
        object_type: str,
        object_id: str,
        *,
        created_by: str | None = None,
    ) -> Tuple:
        self._validate(relation, object_type)
        key = self._natural_key(subject_type, subject_id, relation, object_type, object_id)
        existing = self._key_index.get(key)
        if existing is not None:
            raise DuplicateTupleError(
                "Tuple with identical natural key already exists",
                existing_tuple_id=existing,
            )
        tup = Tuple(
            id=generate("tup"),
            subject_type=subject_type,
            subject_id=subject_id,
            relation=relation,
            object_type=object_type,
            object_id=object_id,
            created_at=self._clock(),
            created_by=created_by,
        )
        self._tuples[tup.id] = tup
        self._key_index[key] = tup.id
        return tup

    def delete_tuple(self, tuple_id: str) -> None:
        tup = self._tuples.get(tuple_id)
        if tup is None:
            raise TupleNotFoundError(f"Tuple {tuple_id} not found")
        del self._tuples[tuple_id]
        self._key_index.pop(
            self._natural_key(
                tup.subject_type,
                tup.subject_id,
                tup.relation,
                tup.object_type,
                tup.object_id,
            ),
            None,
        )

    def cascade_revoke_subject(self, subject_type: str, subject_id: str) -> int:
        to_delete = [
            (tid, tup)
            for tid, tup in self._tuples.items()
            if tup.subject_type == subject_type and tup.subject_id == subject_id
        ]
        for tid, tup in to_delete:
            del self._tuples[tid]
            self._key_index.pop(
                self._natural_key(
                    tup.subject_type,
                    tup.subject_id,
                    tup.relation,
                    tup.object_type,
                    tup.object_id,
                ),
                None,
            )
        return len(to_delete)

    # ─── check() primitives ───

    def check(
        self,
        subject_type: str,
        subject_id: str,
        relation: str,
        object_type: str,
        object_id: str,
    ) -> CheckResult:
        # v0.1 fast path: direct natural-key lookup. Returns immediately
        # on a direct hit regardless of whether rules are registered.
        key = self._natural_key(subject_type, subject_id, relation, object_type, object_id)
        tup_id = self._key_index.get(key)
        if tup_id is not None:
            return CheckResult(allowed=True, matched_tuple_id=tup_id)

        # v0.2 path: rule expansion only when a direct lookup misses
        # AND rules are registered. With rules=None, this branch is
        # skipped and behavior is byte-identical to v0.1.
        if self._rules is None:
            return CheckResult(allowed=False, matched_tuple_id=None)

        result = evaluate(
            rules=self._rules,
            subject_type=subject_type,
            subject_id=subject_id,
            relation=relation,
            object_type=object_type,
            object_id=object_id,
            direct_lookup=self._direct_lookup,
            list_by_object=self._list_subjects_by_object,
            max_depth=self._max_depth,
            max_fan_out=self._max_fan_out,
        )
        return CheckResult(
            allowed=result.allowed, matched_tuple_id=result.matched_tuple_id
        )

    def _direct_lookup(
        self,
        subject_type: str,
        subject_id: str,
        relation: str,
        object_type: str,
        object_id: str,
    ) -> str | None:
        """Direct natural-key lookup callback for the rule evaluator."""
        return self._key_index.get(
            self._natural_key(
                subject_type, subject_id, relation, object_type, object_id
            )
        )

    def _list_subjects_by_object(
        self, object_type: str, object_id: str, relation: str | None
    ):
        """Enumerate (subject_type, subject_id, tup_id) tuples on an object.

        Used by ``TupleToUserset`` evaluation to follow a relation hop.
        """
        for t in self._tuples.values():
            if t.object_type != object_type or t.object_id != object_id:
                continue
            if relation is not None and t.relation != relation:
                continue
            yield (t.subject_type, t.subject_id, t.id)

    def check_any(
        self,
        subject_type: str,
        subject_id: str,
        relations: list[str],
        object_type: str,
        object_id: str,
    ) -> CheckResult:
        if len(relations) == 0:
            raise EmptyRelationSetError()
        for relation in relations:
            # Reuse rule-aware check() so check_any benefits from
            # rewrite rules when they're registered.
            result = self.check(
                subject_type, subject_id, relation, object_type, object_id
            )
            if result.allowed:
                return result
        return CheckResult(allowed=False, matched_tuple_id=None)

    # ─── Read accessors ───

    def get_tuple(self, tuple_id: str) -> Tuple:
        tup = self._tuples.get(tuple_id)
        if tup is None:
            raise TupleNotFoundError(f"Tuple {tuple_id} not found")
        return tup

    def list_tuples_by_subject(
        self,
        subject_type: str,
        subject_id: str,
        *,
        cursor: str | None = None,
        limit: int = 50,
    ) -> Page[Tuple]:
        matching = sorted(
            (
                t
                for t in self._tuples.values()
                if t.subject_type == subject_type and t.subject_id == subject_id
            ),
            key=lambda t: t.id,
        )
        return self._paginate(matching, cursor, limit)

    def list_tuples_by_object(
        self,
        object_type: str,
        object_id: str,
        *,
        relation: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> Page[Tuple]:
        matching = sorted(
            (
                t
                for t in self._tuples.values()
                if t.object_type == object_type
                and t.object_id == object_id
                and (relation is None or t.relation == relation)
            ),
            key=lambda t: t.id,
        )
        return self._paginate(matching, cursor, limit)

    @staticmethod
    def _paginate(
        all_items: list[Tuple], cursor: str | None, limit: int
    ) -> Page[Tuple]:
        if cursor is not None:
            start = 0
            for i, item in enumerate(all_items):
                if item.id > cursor:
                    start = i
                    break
                start = i + 1
        else:
            start = 0
        slice_ = all_items[start : start + limit]
        next_cursor = (
            slice_[-1].id
            if (start + limit) < len(all_items) and len(slice_) > 0
            else None
        )
        return Page(data=slice_, next_cursor=next_cursor)
