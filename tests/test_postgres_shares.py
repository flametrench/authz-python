# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for PostgresShareStore (ADR 0012).

Gated on AUTHZ_POSTGRES_URL — when the env var is unset the entire
module is skipped, mirroring the Node and PHP suites.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

import pytest
from flametrench_ids import decode, generate

from flametrench_authz import (
    InvalidFormatError,
    InvalidShareTokenError,
    PreconditionError,
    SHARE_MAX_TTL_SECONDS,
    ShareConsumedError,
    ShareExpiredError,
    ShareNotFoundError,
    ShareRevokedError,
)

POSTGRES_URL = os.environ.get("AUTHZ_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    POSTGRES_URL is None,
    reason="AUTHZ_POSTGRES_URL not set; PostgresShareStore tests skipped.",
)

if POSTGRES_URL is not None:
    import psycopg

    from flametrench_authz.postgres import PostgresShareStore

SCHEMA_SQL = Path(__file__).parent.joinpath("postgres-schema.sql").read_text()


@pytest.fixture
def conn() -> Iterator[Any]:
    assert POSTGRES_URL is not None
    c = psycopg.connect(POSTGRES_URL, autocommit=False)
    try:
        with c.cursor() as cur:
            cur.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;")
            cur.execute(SCHEMA_SQL)
        c.commit()
        yield c
    finally:
        c.close()


@pytest.fixture
def store(conn: Any) -> "PostgresShareStore":
    return PostgresShareStore(conn)


@pytest.fixture
def alice(conn: Any) -> str:
    u = generate("usr")
    with conn.cursor() as cur:
        cur.execute("INSERT INTO usr (id, status) VALUES (%s, 'active')", (decode(u).uuid,))
    conn.commit()
    return u


@pytest.fixture
def project42() -> str:
    return decode(generate("usr")).uuid


def test_create_share_yields_fresh_id(store, alice, project42):
    r = store.create_share("proj", project42, "viewer", alice, 600)
    assert r.share.id.startswith("shr_")
    assert r.token != r.share.id
    assert r.share.single_use is False
    assert r.share.consumed_at is None


def test_create_rejects_malformed_relation(store, alice, project42):
    with pytest.raises(InvalidFormatError):
        store.create_share("proj", project42, "Viewer!", alice, 600)


def test_create_rejects_ttl_above_ceiling(store, alice, project42):
    with pytest.raises(InvalidFormatError):
        store.create_share("proj", project42, "viewer", alice, SHARE_MAX_TTL_SECONDS + 1)


def test_verify_share_token_round_trips(store, alice, project42):
    r = store.create_share("proj", project42, "viewer", alice, 600)
    v = store.verify_share_token(r.token)
    assert v.share_id == r.share.id
    assert v.object_type == "proj"
    assert v.object_id == project42
    assert v.relation == "viewer"


def test_verify_junk_token_raises(store):
    with pytest.raises(InvalidShareTokenError):
        store.verify_share_token("not-a-real-token")


def test_verify_revoked_raises(store, alice, project42):
    r = store.create_share("proj", project42, "viewer", alice, 600)
    store.revoke_share(r.share.id)
    with pytest.raises(ShareRevokedError):
        store.verify_share_token(r.token)


def test_verify_expired_raises(conn, alice, project42):
    now = [datetime(2026, 4, 27, tzinfo=timezone.utc)]
    s = PostgresShareStore(conn, clock=lambda: now[0])
    r = s.create_share("proj", project42, "viewer", alice, 60)
    now[0] += timedelta(seconds=61)
    with pytest.raises(ShareExpiredError):
        s.verify_share_token(r.token)


def test_single_use_consumes(store, alice, project42):
    r = store.create_share("proj", project42, "viewer", alice, 600, single_use=True)
    store.verify_share_token(r.token)
    consumed = store.get_share(r.share.id)
    assert consumed.consumed_at is not None
    with pytest.raises(ShareConsumedError):
        store.verify_share_token(r.token)


def test_non_single_use_repeatable(store, alice, project42):
    r = store.create_share("proj", project42, "viewer", alice, 600)
    store.verify_share_token(r.token)
    second = store.verify_share_token(r.token)
    assert second.relation == "viewer"


def test_revoked_plus_expired_yields_revoked(conn, alice, project42):
    now = [datetime(2026, 4, 27, tzinfo=timezone.utc)]
    s = PostgresShareStore(conn, clock=lambda: now[0])
    r = s.create_share("proj", project42, "viewer", alice, 60)
    s.revoke_share(r.share.id)
    now[0] += timedelta(seconds=61)
    with pytest.raises(ShareRevokedError):
        s.verify_share_token(r.token)


def test_revoke_share_idempotent(store, alice, project42):
    r = store.create_share("proj", project42, "viewer", alice, 600)
    first = store.revoke_share(r.share.id)
    second = store.revoke_share(r.share.id)
    assert second.revoked_at == first.revoked_at


def test_revoke_unknown_raises(store):
    with pytest.raises(ShareNotFoundError):
        store.revoke_share(generate("shr"))


def test_get_unknown_raises(store):
    with pytest.raises(ShareNotFoundError):
        store.get_share(generate("shr"))


def test_list_shares_for_object_paginates(store, alice, project42):
    other = decode(generate("usr")).uuid
    for obj in [project42, project42, other, project42]:
        store.create_share("proj", obj, "viewer", alice, 600)
    page1 = store.list_shares_for_object("proj", project42, limit=2)
    assert len(page1.data) == 2
    assert page1.next_cursor is not None
    page2 = store.list_shares_for_object(
        "proj", project42, cursor=page1.next_cursor, limit=10,
    )
    ids = {s.id for s in page1.data} | {s.id for s in page2.data}
    assert len(ids) == 3


# ─── ADR 0012: created_by must be an active user ───


def test_create_rejects_suspended_user(store, conn, alice, project42):
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE usr SET status = 'suspended' WHERE id = %s",
            (decode(alice).uuid,),
        )
    conn.commit()
    with pytest.raises(PreconditionError):
        store.create_share("proj", project42, "viewer", alice, 600)


def test_create_rejects_revoked_user(store, conn, alice, project42):
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE usr SET status = 'revoked' WHERE id = %s",
            (decode(alice).uuid,),
        )
    conn.commit()
    with pytest.raises(PreconditionError):
        store.create_share("proj", project42, "viewer", alice, 600)


def test_create_rejects_unknown_user(store, project42):
    ghost = generate("usr")
    with pytest.raises(PreconditionError):
        store.create_share("proj", project42, "viewer", ghost, 600)


# ─── Spec error precedence: consumed > expired ───
# (revoked > consumed > expired — revoked covered above; consumed-vs-expired below)


def test_consumed_then_expired_yields_consumed(conn, alice, project42):
    """A single-use share that was consumed AND then expired raises
    ShareConsumedError — the consumed state takes precedence over expired."""
    now = [datetime(2026, 4, 27, tzinfo=timezone.utc)]
    s = PostgresShareStore(conn, clock=lambda: now[0])
    r = s.create_share("proj", project42, "viewer", alice, 60, single_use=True)
    s.verify_share_token(r.token)  # consumes
    now[0] += timedelta(seconds=61)  # now also expired
    with pytest.raises(ShareConsumedError):
        s.verify_share_token(r.token)


# ─── createdBy round-trip ───


def test_created_by_round_trips_through_postgres(store, alice, project42):
    """Confirm that the wire-format usr_<hex> we passed in is exactly
    what comes back from getShare — guards against an encode/decode
    mis-wire in the rowToShare mapper."""
    r = store.create_share("proj", project42, "viewer", alice, 600)
    fetched = store.get_share(r.share.id)
    assert fetched.created_by == alice
    assert fetched.created_by.startswith("usr_")


# ─── Listing returns shares in every state ───


def test_list_includes_revoked_and_consumed_shares(store, alice, project42):
    """spec/docs/shares.md: listSharesForObject returns shares regardless
    of consumed/revoked/expired state. Used by admin UIs to enumerate all
    shares ever minted on a resource."""
    active_r = store.create_share("proj", project42, "viewer", alice, 600)
    revoked_r = store.create_share("proj", project42, "viewer", alice, 600)
    consumed_r = store.create_share(
        "proj", project42, "viewer", alice, 600, single_use=True,
    )
    store.revoke_share(revoked_r.share.id)
    store.verify_share_token(consumed_r.token)
    page = store.list_shares_for_object("proj", project42)
    ids = {s.id for s in page.data}
    assert active_r.share.id in ids
    assert revoked_r.share.id in ids
    assert consumed_r.share.id in ids
    assert len(ids) == 3


# ─── autocommit=True regression test (Python-specific) ───


def test_verify_works_under_autocommit_true():
    """Python `_tx` must work correctly under autocommit=True. Bare
    commit-on-success / rollback-on-error against a connection with
    autocommit=True would NOT hold a FOR UPDATE row lock between the
    SELECT and the consume UPDATE; the fix uses psycopg's
    connection.transaction() context manager which issues an explicit
    BEGIN regardless of autocommit setting."""
    assert POSTGRES_URL is not None
    c = psycopg.connect(POSTGRES_URL, autocommit=True)
    try:
        # Reset schema. Under autocommit=True, DDL needs no commit() call.
        with c.cursor() as cur:
            cur.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;")
            cur.execute(SCHEMA_SQL)
        s = PostgresShareStore(c)
        u = generate("usr")
        with c.cursor() as cur:
            cur.execute(
                "INSERT INTO usr (id, status) VALUES (%s, 'active')",
                (decode(u).uuid,),
            )
        proj = decode(generate("usr")).uuid
        # Single-use happy path — exercises the multi-statement consume.
        r = s.create_share("proj", proj, "viewer", u, 600, single_use=True)
        v = s.verify_share_token(r.token)
        assert v.share_id == r.share.id
        # Second verify must see consumed_at and raise ShareConsumedError.
        with pytest.raises(ShareConsumedError):
            s.verify_share_token(r.token)
    finally:
        c.close()


# ─── Outer-transaction nesting (ADR 0013) ───

def test_create_share_cooperates_with_outer_transaction(store, conn, alice, project42):
    nested = PostgresShareStore(conn)
    with conn.transaction():
        r = nested.create_share("proj", project42, "viewer", alice, 600)
    assert store.get_share(r.share.id).id == r.share.id


def test_outer_rollback_undoes_inner_create_share(store, conn, alice, project42):
    nested = PostgresShareStore(conn)
    share_id = None
    try:
        with conn.transaction():
            r = nested.create_share("proj", project42, "viewer", alice, 600)
            share_id = r.share.id
            raise RuntimeError("force rollback")
    except RuntimeError:
        pass
    with pytest.raises(ShareNotFoundError):
        store.get_share(share_id)


def test_outer_can_commit_after_first_rolls_back_savepoint_revoked(
    store, conn, alice, project42,
):
    r = store.create_share("proj", project42, "viewer", alice, 600)
    store.revoke_share(r.share.id)
    with conn.transaction():
        nested = PostgresShareStore(conn)
        with pytest.raises(ShareRevokedError):
            nested.verify_share_token(r.token)
        # Outer txn still usable.
        r2 = nested.create_share("proj", project42, "viewer", alice, 600)
    assert store.get_share(r2.share.id).id == r2.share.id
