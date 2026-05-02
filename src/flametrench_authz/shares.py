# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Share tokens — v0.2 primitive for time-bounded, presentation-bearer
resource access. See spec/docs/shares.md and spec/decisions/0012-share-tokens.md.

A share grants the bearer of an opaque short-TTL token resource-scoped
access to a single ``(object_type, object_id)`` at a given relation. The
bearer is NOT promoted to an authenticated principal — they receive
only the verified relation on the verified object.

This module ships the public types, the :class:`ShareStore` Protocol,
and the reference :class:`InMemoryShareStore`. The Postgres-backed
implementation lives in :mod:`flametrench_authz.postgres`.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Generic, Protocol, TypeVar, runtime_checkable

from flametrench_ids import generate

from .errors import (
    InvalidFormatError,
    InvalidShareTokenError,
    ShareConsumedError,
    ShareExpiredError,
    ShareNotFoundError,
    ShareRevokedError,
)
from .patterns import RELATION_NAME_PATTERN, TYPE_PREFIX_PATTERN
from .types import Page

T = TypeVar("T")

#: Spec-mandated upper bound on share lifetime (seconds): 365 days.
SHARE_MAX_TTL_SECONDS = 365 * 24 * 60 * 60


@dataclass(frozen=True)
class Share:
    """The public share record.

    Token storage (SHA-256 → BYTEA) is internal; the plaintext bearer
    credential is returned ONCE on :meth:`ShareStore.create_share` and
    never persisted nor exposed via this dataclass.
    """

    id: str
    object_type: str
    object_id: str
    relation: str
    created_by: str
    expires_at: datetime
    single_use: bool
    consumed_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime


@dataclass(frozen=True)
class CreateShareResult:
    """Returned by :meth:`ShareStore.create_share`.

    The plaintext ``token`` is observable here ONLY; the SDK persists
    only its SHA-256 hash. Callers MUST surface the token to the share
    recipient at this point and never log it.
    """

    share: Share
    #: Opaque base64url-encoded bearer credential, ≥ 256 bits of entropy.
    token: str


@dataclass(frozen=True)
class VerifiedShare:
    """Returned by :meth:`ShareStore.verify_share_token` on success.

    This is enough information to render the resource at the given
    relation; it is NOT an authenticated principal and MUST NOT be
    promoted to a session.
    """

    share_id: str
    object_type: str
    object_id: str
    relation: str


@runtime_checkable
class ShareStore(Protocol):
    """Contract every share-token backend implements.

    Verification ordering is normative (per ADR 0012):

    1. Hash input via SHA-256.
    2. Look up by ``token_hash``; missing → :class:`InvalidShareTokenError`.
    3. Constant-time-compare; mismatch → :class:`InvalidShareTokenError`.
    4. ``revoked_at`` non-null → :class:`ShareRevokedError`.
    5. ``single_use`` and ``consumed_at`` non-null → :class:`ShareConsumedError`.
    6. ``expires_at <= now`` → :class:`ShareExpiredError`.
    7. If ``single_use``: transactionally set ``consumed_at = now``.
    """

    def create_share(
        self,
        object_type: str,
        object_id: str,
        relation: str,
        created_by: str,
        expires_in_seconds: int,
        *,
        single_use: bool = False,
    ) -> CreateShareResult: ...

    def get_share(self, share_id: str) -> Share: ...

    def verify_share_token(self, token: str) -> VerifiedShare:
        """Verify a presented share-token bearer.

        Security:
            The returned ``VerifiedShare.relation`` is the relation the
            share was minted with. The adopter MUST gate write paths on
            this — ``verify_share_token`` only proves the token is
            valid, not that the bearer is allowed to perform the
            action. A common footgun (security-audit-v0.3.md C2):
            minting ``'viewer'`` shares and using them on both read AND
            write endpoints without checking ``verified.relation`` on
            the writes — the SDK will not stop a viewer share from
            posting comments. Mint distinct relations per intent; gate
            each endpoint accordingly. See ``spec/docs/shares.md``
            §"Adopter MUST: enforce the relation field".
        """
        ...

    def revoke_share(self, share_id: str) -> Share:
        """Idempotent. Calling on an already-revoked share returns the
        existing record with the original ``revoked_at``; not an error.
        """
        ...

    def list_shares_for_object(
        self,
        object_type: str,
        object_id: str,
        *,
        cursor: str | None = None,
        limit: int = 50,
    ) -> Page[Share]: ...


# ─── In-memory reference implementation ───


def _default_clock() -> datetime:
    return datetime.now(timezone.utc)


def _hash_token(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


def _generate_token() -> str:
    raw = secrets.token_bytes(32)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _validate(relation: str, object_type: str, expires_in_seconds: int) -> None:
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


class InMemoryShareStore:
    """Reference in-memory ShareStore. O(1) verify via secondary token-hash
    index; deterministic for tests.

    Token storage matches the Postgres reference (SHA-256 → 32 raw
    bytes, constant-time compare on verify), so behavior is byte-
    identical across backends.
    """

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._shares: dict[str, Share] = {}
        self._token_hashes: dict[str, bytes] = {}  # share_id → bytes
        self._by_token_hash: dict[bytes, str] = {}  # bytes → share_id
        self._clock = clock or _default_clock

    def _now(self) -> datetime:
        return self._clock()

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
        _validate(relation, object_type, expires_in_seconds)
        now = self._now()
        expires_at = now + timedelta(seconds=expires_in_seconds)
        share_id = generate("shr")
        token = _generate_token()
        token_hash = _hash_token(token)
        share = Share(
            id=share_id,
            object_type=object_type,
            object_id=object_id,
            relation=relation,
            created_by=created_by,
            expires_at=expires_at,
            single_use=single_use,
            consumed_at=None,
            revoked_at=None,
            created_at=now,
        )
        self._shares[share_id] = share
        self._token_hashes[share_id] = token_hash
        self._by_token_hash[token_hash] = share_id
        return CreateShareResult(share=share, token=token)

    def get_share(self, share_id: str) -> Share:
        if share_id not in self._shares:
            raise ShareNotFoundError(f"Share {share_id} not found")
        return self._shares[share_id]

    def verify_share_token(self, token: str) -> VerifiedShare:
        input_hash = _hash_token(token)
        share_id = self._by_token_hash.get(input_hash)
        if share_id is None:
            raise InvalidShareTokenError()
        share = self._shares.get(share_id)
        stored_hash = self._token_hashes.get(share_id)
        if share is None or stored_hash is None:
            raise InvalidShareTokenError()
        # Defense-in-depth: constant-time compare even though the index
        # just hit, mirroring the Postgres path's posture.
        if not hmac.compare_digest(input_hash, stored_hash):
            raise InvalidShareTokenError()
        # Spec error precedence: revoked > consumed > expired.
        if share.revoked_at is not None:
            raise ShareRevokedError()
        if share.single_use and share.consumed_at is not None:
            raise ShareConsumedError()
        now = self._now()
        if now >= share.expires_at:
            raise ShareExpiredError()
        if share.single_use:
            # Atomic consume — set ``consumed_at`` on the public record.
            # Keep the by-token-hash entry so a second verify can find
            # the row and return :class:`ShareConsumedError` (not
            # :class:`InvalidShareTokenError`). The Postgres equivalent
            # is ``UPDATE … WHERE consumed_at IS NULL RETURNING …``.
            consumed = Share(
                id=share.id,
                object_type=share.object_type,
                object_id=share.object_id,
                relation=share.relation,
                created_by=share.created_by,
                expires_at=share.expires_at,
                single_use=share.single_use,
                consumed_at=now,
                revoked_at=share.revoked_at,
                created_at=share.created_at,
            )
            self._shares[share_id] = consumed
        return VerifiedShare(
            share_id=share_id,
            object_type=share.object_type,
            object_id=share.object_id,
            relation=share.relation,
        )

    def revoke_share(self, share_id: str) -> Share:
        if share_id not in self._shares:
            raise ShareNotFoundError(f"Share {share_id} not found")
        share = self._shares[share_id]
        if share.revoked_at is not None:
            # Idempotent: return the existing record with the original timestamp.
            return share
        revoked = Share(
            id=share.id,
            object_type=share.object_type,
            object_id=share.object_id,
            relation=share.relation,
            created_by=share.created_by,
            expires_at=share.expires_at,
            single_use=share.single_use,
            consumed_at=share.consumed_at,
            revoked_at=self._now(),
            created_at=share.created_at,
        )
        self._shares[share_id] = revoked
        # Don't drop the by-token-hash entry — verify must find the row to
        # return :class:`ShareRevokedError`, not :class:`InvalidShareTokenError`.
        return revoked

    def list_shares_for_object(
        self,
        object_type: str,
        object_id: str,
        *,
        cursor: str | None = None,
        limit: int = 50,
    ) -> Page[Share]:
        limit = min(limit, 200)
        all_matching = sorted(
            (
                s
                for s in self._shares.values()
                if s.object_type == object_type
                and s.object_id == object_id
                and (cursor is None or s.id > cursor)
            ),
            key=lambda s: s.id,
        )
        data = all_matching[:limit]
        next_cursor = (
            data[-1].id if len(all_matching) > limit and data else None
        )
        return Page(data=data, next_cursor=next_cursor)
