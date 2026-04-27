# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""PostgresTupleStore — Postgres-backed implementation of TupleStore.

Mirrors :class:`InMemoryTupleStore` byte-for-byte at the SDK boundary;
the difference is durability and concurrency. Schema lives in
``spec/reference/postgres.sql`` (the ``tup`` table).

Design notes:
    - All ID columns store native UUID. Wire-format prefixed IDs are
      computed at the SDK boundary via :mod:`flametrench_ids` encode/decode.
    - The natural-key UNIQUE constraint
      ``(subject_type, subject_id, relation, object_type, object_id)``
      drives duplicate detection.
    - ``check()`` / ``check_any()`` are exact-match only here in v0.2.
      Rewrite-rule support (ADR 0007) requires the in-memory store
      with the ``rules`` constructor option; bridging the synchronous
      evaluator to async DB I/O is tracked for v0.3.

Connection handling: this store accepts any object that quacks like a
psycopg3 connection — i.e. yields a cursor via ``connection()`` /
``cursor()``. The tests use ``psycopg.connect(...)`` directly.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Sequence

from flametrench_ids import decode as _decode, encode as _encode, generate as _generate

from .errors import (
    DuplicateTupleError,
    EmptyRelationSetError,
    InvalidFormatError,
    TupleNotFoundError,
)
from .patterns import RELATION_NAME_PATTERN, TYPE_PREFIX_PATTERN
from .types import CheckResult, Page, Tuple

# Postgres SQLSTATE 23505 = unique_violation.
_UNIQUE_VIOLATION = "23505"


def _default_clock() -> datetime:
    return datetime.now(timezone.utc)


def _wire_to_uuid(wire_id: str) -> str:
    return _decode(wire_id).uuid


def _row_to_tuple(row: Sequence[Any]) -> Tuple:
    """Map a tup row to the public Tuple dataclass.

    Column order MUST match the SELECT lists used throughout this module:
    ``id, subject_type, subject_id, relation, object_type, object_id,
    created_at, created_by``.
    """
    return Tuple(
        id=_encode("tup", str(row[0])),
        subject_type=str(row[1]),
        subject_id=_encode("usr", str(row[2])),
        relation=str(row[3]),
        object_type=str(row[4]),
        object_id=str(row[5]),
        created_at=row[6] if isinstance(row[6], datetime) else datetime.fromisoformat(str(row[6])),
        created_by=_encode("usr", str(row[7])) if row[7] is not None else None,
    )


_TUP_COLS = (
    "id, subject_type, subject_id, relation, object_type, object_id, created_at, created_by"
)


class PostgresTupleStore:
    """Postgres-backed TupleStore. See module docstring."""

    def __init__(
        self,
        connection: Any,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._conn = connection
        self._clock = clock or _default_clock

    def _now(self) -> datetime:
        return self._clock()

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

    @staticmethod
    def _is_unique_violation(exc: Exception) -> bool:
        sqlstate = getattr(exc, "sqlstate", None)
        if sqlstate == _UNIQUE_VIOLATION:
            return True
        # psycopg3 surfaces SQLSTATE on the diag attribute too; fall through.
        diag = getattr(exc, "diag", None)
        if diag is not None and getattr(diag, "sqlstate", None) == _UNIQUE_VIOLATION:
            return True
        return False

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
        tup_uuid = _decode(_generate("tup")).uuid
        subject_uuid = _wire_to_uuid(subject_id)
        created_by_uuid = _wire_to_uuid(created_by) if created_by is not None else None
        now = self._now()
        try:
            with self._conn.cursor() as cur:
                cur.execute(
                    f"""
                    INSERT INTO tup (id, subject_type, subject_id, relation, object_type, object_id, created_at, created_by)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING {_TUP_COLS}
                    """,
                    (tup_uuid, subject_type, subject_uuid, relation, object_type, object_id, now, created_by_uuid),
                )
                row = cur.fetchone()
                self._conn.commit()
                assert row is not None
                return _row_to_tuple(row)
        except Exception as exc:
            self._conn.rollback()
            if self._is_unique_violation(exc):
                with self._conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT id FROM tup
                        WHERE subject_type = %s AND subject_id = %s AND relation = %s
                          AND object_type = %s AND object_id = %s
                        """,
                        (subject_type, subject_uuid, relation, object_type, object_id),
                    )
                    existing = cur.fetchone()
                if existing is not None:
                    raise DuplicateTupleError(
                        "Tuple with identical natural key already exists",
                        existing_tuple_id=_encode("tup", str(existing[0])),
                    ) from exc
            raise

    def delete_tuple(self, tuple_id: str) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                "DELETE FROM tup WHERE id = %s",
                (_wire_to_uuid(tuple_id),),
            )
            count = cur.rowcount
        self._conn.commit()
        if count == 0:
            raise TupleNotFoundError(f"Tuple {tuple_id} not found")

    def cascade_revoke_subject(self, subject_type: str, subject_id: str) -> int:
        with self._conn.cursor() as cur:
            cur.execute(
                "DELETE FROM tup WHERE subject_type = %s AND subject_id = %s",
                (subject_type, _wire_to_uuid(subject_id)),
            )
            count = cur.rowcount
        self._conn.commit()
        return count or 0

    # ─── check / check_any ───

    def check(
        self,
        subject_type: str,
        subject_id: str,
        relation: str,
        object_type: str,
        object_id: str,
    ) -> CheckResult:
        return self.check_any(
            subject_type, subject_id, [relation], object_type, object_id,
        )

    def check_any(
        self,
        subject_type: str,
        subject_id: str,
        relations: list[str],
        object_type: str,
        object_id: str,
    ) -> CheckResult:
        if not relations:
            raise EmptyRelationSetError()
        with self._conn.cursor() as cur:
            cur.execute(
                """
                SELECT id FROM tup
                WHERE subject_type = %s AND subject_id = %s
                  AND relation = ANY(%s) AND object_type = %s AND object_id = %s
                LIMIT 1
                """,
                (
                    subject_type,
                    _wire_to_uuid(subject_id),
                    list(relations),
                    object_type,
                    object_id,
                ),
            )
            row = cur.fetchone()
        if row is None:
            return CheckResult(allowed=False, matched_tuple_id=None)
        return CheckResult(
            allowed=True,
            matched_tuple_id=_encode("tup", str(row[0])),
        )

    # ─── Read accessors ───

    def get_tuple(self, tuple_id: str) -> Tuple:
        with self._conn.cursor() as cur:
            cur.execute(
                f"SELECT {_TUP_COLS} FROM tup WHERE id = %s",
                (_wire_to_uuid(tuple_id),),
            )
            row = cur.fetchone()
        if row is None:
            raise TupleNotFoundError(f"Tuple {tuple_id} not found")
        return _row_to_tuple(row)

    def list_tuples_by_subject(
        self,
        subject_type: str,
        subject_id: str,
        *,
        cursor: str | None = None,
        limit: int = 50,
    ) -> Page[Tuple]:
        limit = min(limit, 200)
        params: list[Any] = [subject_type, _wire_to_uuid(subject_id)]
        sql = (
            f"SELECT {_TUP_COLS} FROM tup "
            "WHERE subject_type = %s AND subject_id = %s"
        )
        if cursor is not None:
            sql += " AND id > %s"
            params.append(_wire_to_uuid(cursor))
        sql += " ORDER BY id LIMIT %s"
        params.append(limit + 1)
        with self._conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
        return _paginate(rows, limit)

    def list_tuples_by_object(
        self,
        object_type: str,
        object_id: str,
        *,
        relation: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> Page[Tuple]:
        limit = min(limit, 200)
        params: list[Any] = [object_type, object_id]
        sql = (
            f"SELECT {_TUP_COLS} FROM tup "
            "WHERE object_type = %s AND object_id = %s"
        )
        if relation is not None:
            sql += " AND relation = %s"
            params.append(relation)
        if cursor is not None:
            sql += " AND id > %s"
            params.append(_wire_to_uuid(cursor))
        sql += " ORDER BY id LIMIT %s"
        params.append(limit + 1)
        with self._conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
        return _paginate(rows, limit)


def _paginate(rows: list[Sequence[Any]], limit: int) -> Page[Tuple]:
    page = rows[:limit]
    tuples = [_row_to_tuple(r) for r in page]
    next_cursor = tuples[-1].id if len(rows) > limit and tuples else None
    return Page(data=tuples, next_cursor=next_cursor)
