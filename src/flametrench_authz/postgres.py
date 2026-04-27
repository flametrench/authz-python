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

import base64
import hashlib
import hmac
import secrets
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterator, Sequence

from flametrench_ids import decode as _decode, encode as _encode, generate as _generate

from .errors import (
    DuplicateTupleError,
    EmptyRelationSetError,
    InvalidFormatError,
    InvalidShareTokenError,
    ShareConsumedError,
    ShareExpiredError,
    ShareNotFoundError,
    ShareRevokedError,
    TupleNotFoundError,
)
from .patterns import RELATION_NAME_PATTERN, TYPE_PREFIX_PATTERN
from .shares import (
    SHARE_MAX_TTL_SECONDS,
    CreateShareResult,
    Share,
    VerifiedShare,
)
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


# ─── PostgresShareStore (ADR 0012) ───


_SHR_COLS = (
    "id, token_hash, object_type, object_id, relation, created_by, "
    "expires_at, single_use, consumed_at, revoked_at, created_at"
)


def _hash_token_bytes(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


def _generate_share_token() -> str:
    raw = secrets.token_bytes(32)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _row_to_share(row: Sequence[Any]) -> Share:
    """Map a shr row to the public Share dataclass.

    Column order MUST match the SELECT lists used throughout this
    section: ``id, token_hash, object_type, object_id, relation,
    created_by, expires_at, single_use, consumed_at, revoked_at,
    created_at``.
    """
    return Share(
        id=_encode("shr", str(row[0])),
        # token_hash (row[1]) is internal; never copied to the public record.
        object_type=str(row[2]),
        object_id=str(row[3]),
        relation=str(row[4]),
        created_by=_encode("usr", str(row[5])),
        expires_at=row[6] if isinstance(row[6], datetime)
            else datetime.fromisoformat(str(row[6])),
        single_use=bool(row[7]),
        consumed_at=(
            row[8] if isinstance(row[8], datetime)
            else (datetime.fromisoformat(str(row[8])) if row[8] is not None else None)
        ),
        revoked_at=(
            row[9] if isinstance(row[9], datetime)
            else (datetime.fromisoformat(str(row[9])) if row[9] is not None else None)
        ),
        created_at=row[10] if isinstance(row[10], datetime)
            else datetime.fromisoformat(str(row[10])),
    )


class PostgresShareStore:
    """Postgres-backed ShareStore. See :class:`flametrench_authz.shares.ShareStore`.

    Verification is one round-trip on the lookup index (``shr_token_hash_idx``).
    Single-use consumption uses ``UPDATE ... WHERE consumed_at IS NULL
    RETURNING ...`` so concurrent verifies of a single-use token race-
    correctly to exactly one success.
    """

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

    @contextmanager
    def _tx(self) -> Iterator[Any]:
        try:
            yield self._conn
            self._conn.commit()
        except Exception:
            try:
                self._conn.rollback()
            except Exception:
                pass
            raise

    def create_share(
        self,
        object_type: str,
        object_id: str,
        relation: str,
        created_by: str,
        expires_in_seconds: int,
        *,
        single_use: bool = False,
    ) -> CreateShareResult:
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
        if expires_in_seconds <= 0:
            raise InvalidFormatError(
                f"expires_in_seconds must be positive, got {expires_in_seconds}",
                field="expires_in_seconds",
            )
        if expires_in_seconds > SHARE_MAX_TTL_SECONDS:
            raise InvalidFormatError(
                f"expires_in_seconds exceeds the spec ceiling of "
                f"{SHARE_MAX_TTL_SECONDS} (365 days)",
                field="expires_in_seconds",
            )
        share_uuid = _decode(_generate("shr")).uuid
        token = _generate_share_token()
        token_hash = _hash_token_bytes(token)
        now = self._now()
        expires_at = now + timedelta(seconds=expires_in_seconds)
        with self._conn.cursor() as cur:
            cur.execute(
                f"""
                INSERT INTO shr (id, token_hash, object_type, object_id, relation,
                                 created_by, expires_at, single_use, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING {_SHR_COLS}
                """,
                (
                    share_uuid, token_hash, object_type, object_id, relation,
                    _wire_to_uuid(created_by), expires_at, single_use, now,
                ),
            )
            row = cur.fetchone()
        self._conn.commit()
        assert row is not None
        return CreateShareResult(share=_row_to_share(row), token=token)

    def get_share(self, share_id: str) -> Share:
        with self._conn.cursor() as cur:
            cur.execute(
                f"SELECT {_SHR_COLS} FROM shr WHERE id = %s",
                (_wire_to_uuid(share_id),),
            )
            row = cur.fetchone()
        if row is None:
            raise ShareNotFoundError(f"Share {share_id} not found")
        return _row_to_share(row)

    def verify_share_token(self, token: str) -> VerifiedShare:
        input_hash = _hash_token_bytes(token)
        with self._tx() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT {_SHR_COLS} FROM shr
                    WHERE token_hash = %s
                    ORDER BY created_at DESC LIMIT 1
                    FOR UPDATE
                    """,
                    (input_hash,),
                )
                row = cur.fetchone()
            if row is None:
                raise InvalidShareTokenError()
            stored_hash = bytes(row[1]) if isinstance(row[1], (bytes, memoryview)) else row[1]
            if not isinstance(stored_hash, bytes):
                stored_hash = bytes(stored_hash)
            # Defense-in-depth: constant-time compare on the BYTEA column.
            if not hmac.compare_digest(input_hash, stored_hash):
                raise InvalidShareTokenError()
            # Spec error precedence: revoked > consumed > expired.
            if row[9] is not None:
                raise ShareRevokedError()
            if bool(row[7]) and row[8] is not None:
                raise ShareConsumedError()
            now = self._now()
            expires_at = row[6] if isinstance(row[6], datetime) else datetime.fromisoformat(str(row[6]))
            if now >= expires_at:
                raise ShareExpiredError()
            if bool(row[7]):
                # Atomic consume — concurrent verifies race here. The
                # ``WHERE consumed_at IS NULL`` clause is what makes the
                # second loser.
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE shr SET consumed_at = %s
                        WHERE id = %s AND consumed_at IS NULL
                        RETURNING id
                        """,
                        (now, row[0]),
                    )
                    upd = cur.fetchone()
                if upd is None:
                    raise ShareConsumedError()
            return VerifiedShare(
                share_id=_encode("shr", str(row[0])),
                object_type=str(row[2]),
                object_id=str(row[3]),
                relation=str(row[4]),
            )

    def revoke_share(self, share_id: str) -> Share:
        share_uuid = _wire_to_uuid(share_id)
        with self._conn.cursor() as cur:
            cur.execute(
                f"""
                UPDATE shr SET revoked_at = COALESCE(revoked_at, %s)
                WHERE id = %s
                RETURNING {_SHR_COLS}
                """,
                (self._now(), share_uuid),
            )
            row = cur.fetchone()
        self._conn.commit()
        if row is None:
            raise ShareNotFoundError(f"Share {share_id} not found")
        return _row_to_share(row)

    def list_shares_for_object(
        self,
        object_type: str,
        object_id: str,
        *,
        cursor: str | None = None,
        limit: int = 50,
    ) -> Page[Share]:
        limit = min(limit, 200)
        params: list[Any] = [object_type, object_id]
        sql = f"SELECT {_SHR_COLS} FROM shr WHERE object_type = %s AND object_id = %s"
        if cursor is not None:
            sql += " AND id > %s"
            params.append(_wire_to_uuid(cursor))
        sql += " ORDER BY id LIMIT %s"
        params.append(limit + 1)
        with self._conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
        page = rows[:limit]
        shares = [_row_to_share(r) for r in page]
        next_cursor = shares[-1].id if len(rows) > limit and shares else None
        return Page(data=shares, next_cursor=next_cursor)
