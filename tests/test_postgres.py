# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for PostgresTupleStore.

Gated on AUTHZ_POSTGRES_URL — when the env var is unset the entire
module is skipped, mirroring the Node and PHP suites.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Iterator

import pytest
from flametrench_ids import decode, generate

from flametrench_authz import (
    DuplicateTupleError,
    EmptyRelationSetError,
    InvalidFormatError,
    TupleNotFoundError,
)

POSTGRES_URL = os.environ.get("AUTHZ_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    POSTGRES_URL is None,
    reason="AUTHZ_POSTGRES_URL not set; PostgresTupleStore tests skipped.",
)

if POSTGRES_URL is not None:
    import psycopg

    from flametrench_authz.postgres import PostgresTupleStore

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
def store(conn: Any) -> "PostgresTupleStore":
    return PostgresTupleStore(conn)


def _new_usr() -> str:
    return generate("usr")


def _new_object_id() -> str:
    return decode(generate("usr")).uuid


@pytest.fixture
def alice(conn: Any) -> str:
    u = _new_usr()
    with conn.cursor() as cur:
        cur.execute("INSERT INTO usr (id, status) VALUES (%s, 'active')", (decode(u).uuid,))
    conn.commit()
    return u


@pytest.fixture
def bob(conn: Any) -> str:
    u = _new_usr()
    with conn.cursor() as cur:
        cur.execute("INSERT INTO usr (id, status) VALUES (%s, 'active')", (decode(u).uuid,))
    conn.commit()
    return u


@pytest.fixture
def carol(conn: Any) -> str:
    u = _new_usr()
    with conn.cursor() as cur:
        cur.execute("INSERT INTO usr (id, status) VALUES (%s, 'active')", (decode(u).uuid,))
    conn.commit()
    return u


def test_create_tuple_yields_fresh_tup_id(store, alice):
    project = _new_object_id()
    t = store.create_tuple("usr", alice, "owner", "proj", project, created_by=alice)
    assert t.id.startswith("tup_")
    assert t.subject_id == alice
    assert t.created_by == alice
    assert t.object_id == project


def test_duplicate_natural_key_raises(store, alice):
    project = _new_object_id()
    first = store.create_tuple("usr", alice, "viewer", "proj", project)
    with pytest.raises(DuplicateTupleError) as ei:
        store.create_tuple("usr", alice, "viewer", "proj", project)
    assert ei.value.existing_tuple_id == first.id


def test_malformed_relation_rejected(store, alice):
    project = _new_object_id()
    with pytest.raises(InvalidFormatError):
        store.create_tuple("usr", alice, "Owner!", "proj", project)


def test_malformed_object_type_rejected(store, alice):
    project = _new_object_id()
    with pytest.raises(InvalidFormatError):
        store.create_tuple("usr", alice, "owner", "Project", project)


def test_check_returns_match(store, alice):
    project = _new_object_id()
    t = store.create_tuple("usr", alice, "editor", "proj", project)
    r = store.check("usr", alice, "editor", "proj", project)
    assert r.allowed
    assert r.matched_tuple_id == t.id


def test_check_returns_false_when_no_match(store, alice):
    project = _new_object_id()
    r = store.check("usr", alice, "owner", "proj", project)
    assert not r.allowed
    assert r.matched_tuple_id is None


def test_check_any_matches_any_supplied(store, alice):
    project = _new_object_id()
    store.create_tuple("usr", alice, "editor", "proj", project)
    r = store.check_any("usr", alice, ["viewer", "editor", "owner"], "proj", project)
    assert r.allowed


def test_check_any_rejects_empty_relations(store, alice):
    project = _new_object_id()
    with pytest.raises(EmptyRelationSetError):
        store.check_any("usr", alice, [], "proj", project)


def test_delete_tuple_then_check_false(store, alice):
    project = _new_object_id()
    t = store.create_tuple("usr", alice, "editor", "proj", project)
    store.delete_tuple(t.id)
    r = store.check("usr", alice, "editor", "proj", project)
    assert not r.allowed


def test_delete_unknown_tuple_raises(store):
    with pytest.raises(TupleNotFoundError):
        store.delete_tuple(generate("tup"))


def test_cascade_revoke_subject(store, alice, bob):
    p1 = _new_object_id()
    p2 = _new_object_id()
    store.create_tuple("usr", alice, "editor", "proj", p1)
    store.create_tuple("usr", alice, "viewer", "proj", p2)
    store.create_tuple("usr", bob, "viewer", "proj", p1)
    removed = store.cascade_revoke_subject("usr", alice)
    assert removed == 2
    assert store.list_tuples_by_subject("usr", alice).data == []
    assert len(store.list_tuples_by_subject("usr", bob).data) == 1


def test_get_tuple_round_trips(store, alice):
    project = _new_object_id()
    t = store.create_tuple("usr", alice, "owner", "proj", project, created_by=alice)
    f = store.get_tuple(t.id)
    assert f.id == t.id
    assert f.subject_id == alice
    assert f.relation == "owner"
    assert f.object_id == project
    assert f.created_by == alice


def test_get_tuple_unknown_raises(store):
    with pytest.raises(TupleNotFoundError):
        store.get_tuple(generate("tup"))


def test_list_tuples_by_object_filters(store, alice, bob, carol):
    p42 = _new_object_id()
    p99 = _new_object_id()
    store.create_tuple("usr", alice, "owner", "proj", p42)
    store.create_tuple("usr", bob, "viewer", "proj", p42)
    store.create_tuple("usr", carol, "viewer", "proj", p99)
    all_on_42 = store.list_tuples_by_object("proj", p42)
    assert len(all_on_42.data) == 2
    viewers_on_42 = store.list_tuples_by_object("proj", p42, relation="viewer")
    assert len(viewers_on_42.data) == 1
    assert viewers_on_42.data[0].subject_id == bob


def test_list_tuples_by_subject_paginates(store, alice):
    objects = [_new_object_id() for _ in range(5)]
    for o in objects:
        store.create_tuple("usr", alice, "viewer", "proj", o)
    page1 = store.list_tuples_by_subject("usr", alice, limit=2)
    assert len(page1.data) == 2
    assert page1.next_cursor is not None
    page2 = store.list_tuples_by_subject("usr", alice, cursor=page1.next_cursor, limit=10)
    all_ids = {t.id for t in page1.data} | {t.id for t in page2.data}
    assert len(all_ids) == 5


def test_wire_format_object_id_with_app_defined_prefix(store, alice):
    """spec#8 regression: object_type is application-defined per ADR 0001,
    so adopters legitimately pass wire-format prefixed IDs (e.g.
    ``proj_<32hex>``, ``file_<32hex>``) at this boundary. Previously this
    raised a Postgres UUID parse error.
    """
    wire_proj = "proj_" + _new_object_id().replace("-", "")
    t = store.create_tuple("usr", alice, "owner", "proj", wire_proj)
    assert t.id.startswith("tup_")
    # check() and list_tuples_by_object() must accept the same wire-format
    # value back through the read paths.
    result = store.check("usr", alice, "owner", "proj", wire_proj)
    assert result.allowed is True
    listed = store.list_tuples_by_object("proj", wire_proj)
    assert len(listed.data) == 1
