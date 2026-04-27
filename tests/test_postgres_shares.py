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
