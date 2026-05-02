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

from flametrench_ids import (
    decode as _decode,
    decode_any as _decode_any,
    encode as _encode,
    generate as _generate,
)
import re as _re

from .errors import (
    DuplicateTupleError,
    EmptyRelationSetError,
    InvalidFormatError,
    InvalidShareTokenError,
    PreconditionError,
    ShareConsumedError,
    ShareExpiredError,
    ShareNotFoundError,
    ShareRevokedError,
    TupleNotFoundError,
)
from .patterns import RELATION_NAME_PATTERN, TYPE_PREFIX_PATTERN
from .rewrite_rules import (
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_FAN_OUT,
    Rules,
    evaluate,
)
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


_OBJECT_ID_WIRE_RE = _re.compile(r"^[a-z]{2,6}_[0-9a-f]{32}$")


def _object_id_to_uuid(object_id: str) -> str:
    """Decode an ``object_id`` to a Postgres-bindable UUID string.

    ``object_type`` is application-defined (per spec/docs/authorization.md
    and ADR 0001), so ``object_id`` may legitimately arrive as:

    1. A wire-format ID with a non-registered prefix (e.g. ``proj_<hex>``,
       ``file_<hex>``) — extract the UUID via ``decode_any`` so app-defined
       prefixes are accepted in addition to registered types.
    2. A raw 32-character hex UUID — accept as-is; Postgres UUID parsing
       handles both 32-hex and hyphenated forms.
    3. A canonical hyphenated UUID — also accepted as-is.

    Closes spec#8.
    """
    if _OBJECT_ID_WIRE_RE.match(object_id):
        return _decode_any(object_id).uuid
    return object_id


def _subject_id_to_uuid(subject_id: str) -> str:
    """v0.3 (ADR 0017) — accept subject ids in any of three shapes:
    wire format with ``usr_`` (the v0.1/v0.2 default), wire format with
    any registered prefix (``org_<hex>`` for ``tuple_to_userset``
    parent hops), or bare canonical UUID (passthrough). Mirrors
    :func:`_object_id_to_uuid`.
    """
    if _OBJECT_ID_WIRE_RE.match(subject_id):
        return _decode_any(subject_id).uuid
    return subject_id


def _uuid_hyphens_to_bare(hyphenated: str) -> str:
    """UUID ``01234567-89ab-...`` → bare 32-hex ``0123456789ab...``."""
    return hyphenated.replace("-", "")


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
        rules: Rules | None = None,
        max_depth: int = DEFAULT_MAX_DEPTH,
        max_fan_out: int = DEFAULT_MAX_FAN_OUT,
    ) -> None:
        """v0.3 (ADR 0017) — optional ``rules`` parameter mirroring
        :class:`InMemoryTupleStore`. With ``rules`` ``None``, ``check()``
        is exact-match only (v0.2-identical). With rules, expansion runs
        via iterative async-against-Postgres SELECT — same algorithm
        ADR 0007 specifies for in-memory."""
        self._conn = connection
        self._clock = clock or _default_clock
        self._rules = rules
        self._max_depth = max_depth
        self._max_fan_out = max_fan_out

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
        subject_uuid = _subject_id_to_uuid(subject_id)
        object_uuid = _object_id_to_uuid(object_id)
        created_by_uuid = _wire_to_uuid(created_by) if created_by is not None else None
        now = self._now()
        # ADR 0013: connection.transaction() opens BEGIN when standalone
        # and SAVEPOINT when nested. ON CONFLICT DO NOTHING avoids raising
        # 23505 inside an outer transaction (the previous catch-and-SELECT
        # pattern would run the SELECT inside a Postgres-aborted txn).
        with self._conn.transaction():
            with self._conn.cursor() as cur:
                cur.execute(
                    f"""
                    INSERT INTO tup (id, subject_type, subject_id, relation, object_type, object_id, created_at, created_by)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (subject_type, subject_id, relation, object_type, object_id) DO NOTHING
                    RETURNING {_TUP_COLS}
                    """,
                    (tup_uuid, subject_type, subject_uuid, relation, object_type, object_uuid, now, created_by_uuid),
                )
                row = cur.fetchone()
                if row is not None:
                    return _row_to_tuple(row)
                cur.execute(
                    """
                    SELECT id FROM tup
                    WHERE subject_type = %s AND subject_id = %s AND relation = %s
                      AND object_type = %s AND object_id = %s
                    """,
                    (subject_type, subject_uuid, relation, object_type, object_uuid),
                )
                existing = cur.fetchone()
                if existing is None:
                    # Race: another connection inserted-then-deleted between
                    # our ON CONFLICT and the SELECT. Surface a generic error.
                    raise RuntimeError(
                        "Tuple natural-key conflict resolved after insert lost the row; retry."
                    )
                raise DuplicateTupleError(
                    "Tuple with identical natural key already exists",
                    existing_tuple_id=_encode("tup", str(existing[0])),
                )

    def delete_tuple(self, tuple_id: str) -> None:
        with self._conn.transaction():
            with self._conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM tup WHERE id = %s",
                    (_wire_to_uuid(tuple_id),),
                )
                count = cur.rowcount
        if count == 0:
            raise TupleNotFoundError(f"Tuple {tuple_id} not found")

    def cascade_revoke_subject(self, subject_type: str, subject_id: str) -> int:
        with self._conn.transaction():
            with self._conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM tup WHERE subject_type = %s AND subject_id = %s",
                    (subject_type, _subject_id_to_uuid(subject_id)),
                )
                count = cur.rowcount
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
        # v0.1 fast path: direct natural-key lookup.
        direct = self._direct_lookup(subject_type, subject_id, relation, object_type, object_id)
        if direct is not None:
            return CheckResult(allowed=True, matched_tuple_id=direct)
        # ADR 0017 path: rule expansion only on direct miss AND when
        # rules are registered. With rules=None, behavior is byte-
        # identical to v0.2.
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
            list_by_object=self._list_by_object,
            max_depth=self._max_depth,
            max_fan_out=self._max_fan_out,
        )
        return CheckResult(
            allowed=result.allowed,
            matched_tuple_id=result.matched_tuple_id,
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
        # Fast path: when no rules are registered, a single SELECT with
        # `relation = ANY(...)` short-circuits the whole set in one
        # round trip. Preserves v0.2 behavior.
        if self._rules is None:
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
                        _subject_id_to_uuid(subject_id),
                        list(relations),
                        object_type,
                        _object_id_to_uuid(object_id),
                    ),
                )
                row = cur.fetchone()
            if row is None:
                return CheckResult(allowed=False, matched_tuple_id=None)
            return CheckResult(
                allowed=True,
                matched_tuple_id=_encode("tup", str(row[0])),
            )
        # With rules, evaluate each relation in turn. Per ADR 0017 no
        # union-of-rules optimization in v0.3.
        for relation in relations:
            result = self.check(subject_type, subject_id, relation, object_type, object_id)
            if result.allowed:
                return result
        return CheckResult(allowed=False, matched_tuple_id=None)

    # ─── Rule-evaluator callbacks (ADR 0017) ───

    def _direct_lookup(
        self,
        subject_type: str,
        subject_id: str,
        relation: str,
        object_type: str,
        object_id: str,
    ) -> str | None:
        with self._conn.cursor() as cur:
            cur.execute(
                """
                SELECT id FROM tup
                WHERE subject_type = %s AND subject_id = %s
                  AND relation = %s AND object_type = %s AND object_id = %s
                LIMIT 1
                """,
                (
                    subject_type,
                    _subject_id_to_uuid(subject_id),
                    relation,
                    object_type,
                    _object_id_to_uuid(object_id),
                ),
            )
            row = cur.fetchone()
        return _encode("tup", str(row[0])) if row is not None else None

    def _list_by_object(
        self,
        object_type: str,
        object_id: str,
        relation: str | None,
    ) -> Iterator[tuple[str, str, str]]:
        """Enumerate tuples on (object, relation). Used by tuple_to_userset.

        Yields (subject_type, subject_id, tup_id) triples. ``subject_id``
        is wire-format prefixed with ``subject_type`` (e.g.
        ``org_<hex>``) so the evaluator can pass it through as the
        next-hop ``object_id`` for further lookups.
        """
        sql = (
            "SELECT id, subject_type, subject_id FROM tup "
            "WHERE object_type = %s AND object_id = %s"
        )
        params: list[Any] = [object_type, _object_id_to_uuid(object_id)]
        if relation is not None:
            sql += " AND relation = %s"
            params.append(relation)
        with self._conn.cursor() as cur:
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()
        for row in rows:
            sub_type = str(row[1])
            # pg returns UUID columns as canonical hyphenated; the wire
            # format is bare hex.
            sub_id_wire = f"{sub_type}_{_uuid_hyphens_to_bare(str(row[2]))}"
            yield (sub_type, sub_id_wire, _encode("tup", str(row[0])))

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
        params: list[Any] = [subject_type, _subject_id_to_uuid(subject_id)]
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
        params: list[Any] = [object_type, _object_id_to_uuid(object_id)]
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
        """Run the wrapped block inside an explicit transaction.

        Uses psycopg3's ``connection.transaction()`` context manager
        rather than ``commit()``/``rollback()`` directly. This is
        correct under BOTH ``autocommit=False`` (the default) AND
        ``autocommit=True``: under autocommit=True, the bare
        commit-on-success / rollback-on-error pattern would NOT hold
        a ``FOR UPDATE`` row lock across statements, breaking the
        verify_share_token race-correctness contract.
        ``transaction()`` issues an explicit ``BEGIN``/``COMMIT``
        regardless of the connection's autocommit setting.
        """
        with self._conn.transaction():
            yield self._conn

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
        created_by_uuid = _wire_to_uuid(created_by)
        # ADR 0012: created_by MUST resolve to an active user. The DDL
        # FK enforces existence; status is checked here at the SDK
        # layer. Suspended/revoked users with leaked credentials cannot
        # mint shares.
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT status FROM usr WHERE id = %s",
                (created_by_uuid,),
            )
            user_row = cur.fetchone()
        if user_row is None:
            raise PreconditionError(
                f"created_by {created_by} does not exist",
                reason="creator_not_found",
            )
        if user_row[0] != "active":
            raise PreconditionError(
                f"created_by {created_by} is {user_row[0]}; "
                "only active users can mint shares",
                reason="creator_not_active",
            )
        share_uuid = _decode(_generate("shr")).uuid
        token = _generate_share_token()
        token_hash = _hash_token_bytes(token)
        now = self._now()
        expires_at = now + timedelta(seconds=expires_in_seconds)
        with self._conn.transaction():
            with self._conn.cursor() as cur:
                cur.execute(
                    f"""
                    INSERT INTO shr (id, token_hash, object_type, object_id, relation,
                                     created_by, expires_at, single_use, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING {_SHR_COLS}
                    """,
                    (
                        share_uuid, token_hash, object_type,
                        _object_id_to_uuid(object_id), relation,
                        created_by_uuid, expires_at, single_use, now,
                    ),
                )
                row = cur.fetchone()
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
        with self._conn.transaction():
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
        params: list[Any] = [object_type, _object_id_to_uuid(object_id)]
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
