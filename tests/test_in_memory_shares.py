# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for InMemoryShareStore (ADR 0012)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from flametrench_ids import decode, generate

from flametrench_authz import (
    InMemoryShareStore,
    InvalidFormatError,
    InvalidShareTokenError,
    SHARE_MAX_TTL_SECONDS,
    ShareConsumedError,
    ShareExpiredError,
    ShareNotFoundError,
    ShareRevokedError,
)


@pytest.fixture
def store() -> InMemoryShareStore:
    return InMemoryShareStore()


@pytest.fixture
def alice() -> str:
    return generate("usr")


@pytest.fixture
def project42() -> str:
    return decode(generate("usr")).uuid


def test_create_share_yields_fresh_id_and_distinct_token(store, alice, project42):
    result = store.create_share(
        object_type="proj",
        object_id=project42,
        relation="viewer",
        created_by=alice,
        expires_in_seconds=600,
    )
    assert result.share.id.startswith("shr_")
    assert result.token != result.share.id
    assert len(result.token) > 20
    assert result.share.single_use is False
    assert result.share.consumed_at is None
    assert result.share.revoked_at is None


def test_get_share_round_trips(store, alice, project42):
    r = store.create_share("proj", project42, "viewer", alice, 600)
    fetched = store.get_share(r.share.id)
    assert fetched.id == r.share.id


def test_get_share_unknown_raises(store):
    with pytest.raises(ShareNotFoundError):
        store.get_share(generate("shr"))


def test_create_share_rejects_malformed_relation(store, alice, project42):
    with pytest.raises(InvalidFormatError):
        store.create_share("proj", project42, "Viewer!", alice, 600)


def test_create_share_rejects_malformed_object_type(store, alice, project42):
    with pytest.raises(InvalidFormatError):
        store.create_share("Project", project42, "viewer", alice, 600)


def test_create_share_rejects_negative_ttl(store, alice, project42):
    with pytest.raises(InvalidFormatError):
        store.create_share("proj", project42, "viewer", alice, -1)


def test_create_share_rejects_ttl_above_ceiling(store, alice, project42):
    with pytest.raises(InvalidFormatError):
        store.create_share("proj", project42, "viewer", alice, SHARE_MAX_TTL_SECONDS + 1)


def test_verify_share_token_returns_share_and_relation(store, alice, project42):
    r = store.create_share("proj", project42, "viewer", alice, 600)
    v = store.verify_share_token(r.token)
    assert v.share_id == r.share.id
    assert v.object_type == "proj"
    assert v.object_id == project42
    assert v.relation == "viewer"


def test_verify_junk_token_raises(store):
    with pytest.raises(InvalidShareTokenError):
        store.verify_share_token("not-a-token")


def test_verify_revoked_share_raises_revoked(store, alice, project42):
    r = store.create_share("proj", project42, "viewer", alice, 600)
    store.revoke_share(r.share.id)
    with pytest.raises(ShareRevokedError):
        store.verify_share_token(r.token)


def test_verify_expired_share_raises_expired(alice, project42):
    now = [datetime(2026, 4, 27, tzinfo=timezone.utc)]
    s = InMemoryShareStore(clock=lambda: now[0])
    r = s.create_share("proj", project42, "viewer", alice, 60)
    now[0] += timedelta(seconds=61)
    with pytest.raises(ShareExpiredError):
        s.verify_share_token(r.token)


def test_single_use_consumes_on_first_verify(store, alice, project42):
    r = store.create_share("proj", project42, "viewer", alice, 600, single_use=True)
    store.verify_share_token(r.token)
    with pytest.raises(ShareConsumedError):
        store.verify_share_token(r.token)


def test_single_use_consumed_at_set_on_record(store, alice, project42):
    r = store.create_share("proj", project42, "viewer", alice, 600, single_use=True)
    assert r.share.consumed_at is None
    store.verify_share_token(r.token)
    after = store.get_share(r.share.id)
    assert after.consumed_at is not None


def test_non_single_use_can_verify_repeatedly(store, alice, project42):
    r = store.create_share("proj", project42, "viewer", alice, 600)
    store.verify_share_token(r.token)
    second = store.verify_share_token(r.token)
    assert second.relation == "viewer"


def test_revoked_plus_expired_yields_revoked(alice, project42):
    """Spec error precedence: revoked > consumed > expired."""
    now = [datetime(2026, 4, 27, tzinfo=timezone.utc)]
    s = InMemoryShareStore(clock=lambda: now[0])
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


def test_list_shares_for_object_paginates(store, alice, project42):
    other = decode(generate("usr")).uuid
    for obj in [project42, project42, other, project42]:
        store.create_share("proj", obj, "viewer", alice, 600)
    page1 = store.list_shares_for_object("proj", project42, limit=2)
    assert len(page1.data) == 2
    assert page1.next_cursor is not None
    page2 = store.list_shares_for_object("proj", project42, cursor=page1.next_cursor, limit=10)
    ids = {s.id for s in page1.data} | {s.id for s in page2.data}
    assert len(ids) == 3


def test_consumed_then_expired_yields_consumed(alice, project42):
    """Spec error precedence: consumed > expired."""
    now = [datetime(2026, 4, 27, tzinfo=timezone.utc)]
    s = InMemoryShareStore(clock=lambda: now[0])
    r = s.create_share("proj", project42, "viewer", alice, 60, single_use=True)
    s.verify_share_token(r.token)
    now[0] += timedelta(seconds=61)
    with pytest.raises(ShareConsumedError):
        s.verify_share_token(r.token)


def test_created_by_round_trips(store, alice, project42):
    r = store.create_share("proj", project42, "viewer", alice, 600)
    fetched = store.get_share(r.share.id)
    assert fetched.created_by == alice


def test_list_includes_revoked_and_consumed_shares(store, alice, project42):
    """listSharesForObject returns shares regardless of state."""
    active_r = store.create_share("proj", project42, "viewer", alice, 600)
    revoked_r = store.create_share("proj", project42, "viewer", alice, 600)
    consumed_r = store.create_share("proj", project42, "viewer", alice, 600, single_use=True)
    store.revoke_share(revoked_r.share.id)
    store.verify_share_token(consumed_r.token)
    page = store.list_shares_for_object("proj", project42)
    ids = {s.id for s in page.data}
    assert {active_r.share.id, revoked_r.share.id, consumed_r.share.id} <= ids
    assert len(ids) == 3
