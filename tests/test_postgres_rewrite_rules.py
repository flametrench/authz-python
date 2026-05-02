# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""PostgresTupleStore rewrite-rule evaluation per ADR 0017.

Mirrors test_rewrite_rules.py (in-memory) so any drift between the two
implementations surfaces as a failing test. Gated on
AUTHZ_POSTGRES_URL — module is skipped when the env var is unset.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Iterator

import pytest
from flametrench_ids import decode, generate

from flametrench_authz.errors import EvaluationLimitExceededError
from flametrench_authz.rewrite_rules import (
    ComputedUserset,
    This,
    TupleToUserset,
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
def alice(conn: Any) -> str:
    a = generate("usr")
    with conn.cursor() as cur:
        cur.execute("INSERT INTO usr (id, status) VALUES (%s, 'active')", (decode(a).uuid,))
    conn.commit()
    return a


@pytest.fixture
def org_acme() -> str:
    return generate("org")[4:]  # bare hex


@pytest.fixture
def proj_42() -> str:
    return generate("org")[4:]  # bare hex


def test_empty_rules_no_derivation(conn: Any, alice: str, proj_42: str) -> None:
    store = PostgresTupleStore(conn)  # rules undefined
    store.create_tuple("usr", alice, "editor", "proj", proj_42)
    r = store.check("usr", alice, "viewer", "proj", proj_42)
    assert r.allowed is False


def test_empty_rules_dict_no_derivation(conn: Any, alice: str, proj_42: str) -> None:
    store = PostgresTupleStore(conn, rules={})
    store.create_tuple("usr", alice, "editor", "proj", proj_42)
    r = store.check("usr", alice, "viewer", "proj", proj_42)
    assert r.allowed is False


def test_computed_userset_editor_implies_viewer(
    conn: Any, alice: str, proj_42: str,
) -> None:
    rules = {
        "proj": {
            "viewer": [This(), ComputedUserset(relation="editor")],
        },
    }
    store = PostgresTupleStore(conn, rules=rules)
    editor = store.create_tuple("usr", alice, "editor", "proj", proj_42)
    r = store.check("usr", alice, "viewer", "proj", proj_42)
    assert r.allowed is True
    assert r.matched_tuple_id == editor.id


def test_computed_userset_admin_to_viewer_chain(
    conn: Any, alice: str, proj_42: str,
) -> None:
    rules = {
        "proj": {
            "viewer": [This(), ComputedUserset(relation="editor")],
            "editor": [This(), ComputedUserset(relation="admin")],
        },
    }
    store = PostgresTupleStore(conn, rules=rules)
    admin = store.create_tuple("usr", alice, "admin", "proj", proj_42)
    r = store.check("usr", alice, "viewer", "proj", proj_42)
    assert r.allowed is True
    assert r.matched_tuple_id == admin.id


def test_tuple_to_userset_org_admin_implies_proj_admin(
    conn: Any, alice: str, org_acme: str, proj_42: str,
) -> None:
    rules = {
        "proj": {
            "admin": [
                This(),
                TupleToUserset(
                    tupleset_relation="parent_org",
                    computed_userset_relation="admin",
                ),
            ],
        },
    }
    store = PostgresTupleStore(conn, rules=rules)
    org_admin = store.create_tuple("usr", alice, "admin", "org", org_acme)
    # Wire-format the org subject id so PostgresTupleStore decodes it.
    store.create_tuple(
        "org", f"org_{org_acme}", "parent_org", "proj", proj_42,
    )
    r = store.check("usr", alice, "admin", "proj", proj_42)
    assert r.allowed is True
    assert r.matched_tuple_id == org_admin.id


def test_tuple_to_userset_org_member_does_not_imply_proj_admin(
    conn: Any, alice: str, org_acme: str, proj_42: str,
) -> None:
    rules = {
        "proj": {
            "admin": [
                This(),
                TupleToUserset(
                    tupleset_relation="parent_org",
                    computed_userset_relation="admin",
                ),
            ],
        },
    }
    store = PostgresTupleStore(conn, rules=rules)
    store.create_tuple("usr", alice, "member", "org", org_acme)
    store.create_tuple("org", f"org_{org_acme}", "parent_org", "proj", proj_42)
    r = store.check("usr", alice, "admin", "proj", proj_42)
    assert r.allowed is False


def test_self_referential_cycle_terminates_silently(
    conn: Any, alice: str, proj_42: str,
) -> None:
    rules = {
        "proj": {
            "viewer": [This(), ComputedUserset(relation="viewer")],
        },
    }
    store = PostgresTupleStore(conn, rules=rules)
    r = store.check("usr", alice, "viewer", "proj", proj_42)
    assert r.allowed is False


def test_depth_limit_raises(conn: Any, alice: str, proj_42: str) -> None:
    rules = {
        "proj": {
            "viewer": [ComputedUserset(relation="editor")],
            "editor": [ComputedUserset(relation="admin")],
            "admin": [ComputedUserset(relation="owner")],
            "owner": [ComputedUserset(relation="super")],
        },
    }
    store = PostgresTupleStore(conn, rules=rules, max_depth=2)
    with pytest.raises(EvaluationLimitExceededError):
        store.check("usr", alice, "viewer", "proj", proj_42)


def test_check_any_fast_path_no_rules(conn: Any, alice: str, proj_42: str) -> None:
    store = PostgresTupleStore(conn)
    store.create_tuple("usr", alice, "editor", "proj", proj_42)
    r = store.check_any("usr", alice, ["viewer", "editor"], "proj", proj_42)
    assert r.allowed is True


def test_check_any_with_rules_evaluates_each_in_turn(
    conn: Any, alice: str, proj_42: str,
) -> None:
    rules = {
        "proj": {
            "viewer": [This(), ComputedUserset(relation="editor")],
        },
    }
    store = PostgresTupleStore(conn, rules=rules)
    store.create_tuple("usr", alice, "editor", "proj", proj_42)
    r = store.check_any("usr", alice, ["admin", "viewer"], "proj", proj_42)
    assert r.allowed is True
