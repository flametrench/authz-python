# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for InMemoryTupleStore.

Mirrors the Node + PHP unit suites so behavior is consistent across SDKs.
"""

from __future__ import annotations

import re

import pytest
from flametrench_ids import generate

from flametrench_authz import (
    DuplicateTupleError,
    EmptyRelationSetError,
    InMemoryTupleStore,
    InvalidFormatError,
    TupleNotFoundError,
)


@pytest.fixture
def store() -> InMemoryTupleStore:
    return InMemoryTupleStore()


@pytest.fixture
def alice() -> str:
    return generate("usr")


@pytest.fixture
def bob() -> str:
    return generate("usr")


@pytest.fixture
def carol() -> str:
    return generate("usr")


@pytest.fixture
def org_acme() -> str:
    return generate("org")


@pytest.fixture
def project_42() -> str:
    # Project is an application-custom object type, so we use a bare hex
    # string (not a Flametrench-prefixed ID) to match how apps model their
    # own domain objects in tuples.
    return generate("org")[4:]  # reuse UUID hex from a generated id


class TestCreateTuple:
    def test_creates_a_tuple_with_a_fresh_tup_id(
        self, store: InMemoryTupleStore, alice: str, org_acme: str
    ) -> None:
        t = store.create_tuple(
            subject_type="usr",
            subject_id=alice,
            relation="owner",
            object_type="org",
            object_id=org_acme,
            created_by=alice,
        )
        assert re.match(r"^tup_[0-9a-f]{32}$", t.id)
        assert t.subject_id == alice
        assert t.created_by == alice

    def test_rejects_duplicate_natural_key_with_existing_id_attached(
        self, store: InMemoryTupleStore, alice: str, project_42: str
    ) -> None:
        first = store.create_tuple(
            subject_type="usr",
            subject_id=alice,
            relation="viewer",
            object_type="proj",
            object_id=project_42,
        )
        with pytest.raises(DuplicateTupleError) as exc:
            store.create_tuple(
                subject_type="usr",
                subject_id=alice,
                relation="viewer",
                object_type="proj",
                object_id=project_42,
            )
        assert exc.value.existing_tuple_id == first.id

    def test_rejects_invalid_relation_names(
        self, store: InMemoryTupleStore, alice: str, org_acme: str
    ) -> None:
        with pytest.raises(InvalidFormatError):
            store.create_tuple(
                subject_type="usr",
                subject_id=alice,
                relation="Owner",  # uppercase not permitted
                object_type="org",
                object_id=org_acme,
            )

    def test_rejects_invalid_object_type_prefixes(
        self, store: InMemoryTupleStore, alice: str, project_42: str
    ) -> None:
        with pytest.raises(InvalidFormatError):
            store.create_tuple(
                subject_type="usr",
                subject_id=alice,
                relation="viewer",
                object_type="UPPER",
                object_id=project_42,
            )

    def test_accepts_custom_relations_matching_the_regex(
        self, store: InMemoryTupleStore, alice: str, org_acme: str
    ) -> None:
        t = store.create_tuple(
            subject_type="usr",
            subject_id=alice,
            relation="dispatcher",
            object_type="org",
            object_id=org_acme,
        )
        assert t.relation == "dispatcher"


class TestCheckExactMatch:
    def test_returns_allowed_true_for_exact_match(
        self, store: InMemoryTupleStore, alice: str, project_42: str
    ) -> None:
        store.create_tuple(
            subject_type="usr",
            subject_id=alice,
            relation="editor",
            object_type="proj",
            object_id=project_42,
        )
        result = store.check(
            subject_type="usr",
            subject_id=alice,
            relation="editor",
            object_type="proj",
            object_id=project_42,
        )
        assert result.allowed is True
        assert result.matched_tuple_id is not None
        assert result.matched_tuple_id.startswith("tup_")

    def test_returns_allowed_false_for_different_relation(
        self, store: InMemoryTupleStore, alice: str, project_42: str
    ) -> None:
        store.create_tuple(
            subject_type="usr",
            subject_id=alice,
            relation="editor",
            object_type="proj",
            object_id=project_42,
        )
        result = store.check(
            subject_type="usr",
            subject_id=alice,
            relation="viewer",
            object_type="proj",
            object_id=project_42,
        )
        assert result.allowed is False
        assert result.matched_tuple_id is None


class TestNoDerivation:
    """ADR 0001 load-bearing — admin doesn't imply editor, etc."""

    def test_admin_does_not_imply_editor(
        self, store: InMemoryTupleStore, alice: str, org_acme: str
    ) -> None:
        store.create_tuple(
            subject_type="usr",
            subject_id=alice,
            relation="admin",
            object_type="org",
            object_id=org_acme,
        )
        result = store.check(
            subject_type="usr",
            subject_id=alice,
            relation="editor",
            object_type="org",
            object_id=org_acme,
        )
        assert result.allowed is False

    def test_editor_does_not_imply_viewer(
        self, store: InMemoryTupleStore, alice: str, project_42: str
    ) -> None:
        store.create_tuple(
            subject_type="usr",
            subject_id=alice,
            relation="editor",
            object_type="proj",
            object_id=project_42,
        )
        result = store.check(
            subject_type="usr",
            subject_id=alice,
            relation="viewer",
            object_type="proj",
            object_id=project_42,
        )
        assert result.allowed is False

    def test_org_membership_does_not_imply_project_access(
        self,
        store: InMemoryTupleStore,
        alice: str,
        org_acme: str,
        project_42: str,
    ) -> None:
        store.create_tuple(
            subject_type="usr",
            subject_id=alice,
            relation="member",
            object_type="org",
            object_id=org_acme,
        )
        result = store.check(
            subject_type="usr",
            subject_id=alice,
            relation="viewer",
            object_type="proj",
            object_id=project_42,
        )
        assert result.allowed is False


class TestCheckAny:
    def test_returns_true_if_any_requested_relation_matches(
        self, store: InMemoryTupleStore, alice: str, project_42: str
    ) -> None:
        store.create_tuple(
            subject_type="usr",
            subject_id=alice,
            relation="editor",
            object_type="proj",
            object_id=project_42,
        )
        result = store.check_any(
            subject_type="usr",
            subject_id=alice,
            relations=["viewer", "editor", "owner"],
            object_type="proj",
            object_id=project_42,
        )
        assert result.allowed is True

    def test_returns_false_if_no_relation_matches(
        self, store: InMemoryTupleStore, alice: str, project_42: str
    ) -> None:
        store.create_tuple(
            subject_type="usr",
            subject_id=alice,
            relation="editor",
            object_type="proj",
            object_id=project_42,
        )
        result = store.check_any(
            subject_type="usr",
            subject_id=alice,
            relations=["viewer", "admin"],
            object_type="proj",
            object_id=project_42,
        )
        assert result.allowed is False

    def test_rejects_empty_relation_set(
        self, store: InMemoryTupleStore, alice: str, project_42: str
    ) -> None:
        with pytest.raises(EmptyRelationSetError):
            store.check_any(
                subject_type="usr",
                subject_id=alice,
                relations=[],
                object_type="proj",
                object_id=project_42,
            )


class TestDeleteTuple:
    def test_removes_the_tuple_and_natural_key_index(
        self, store: InMemoryTupleStore, alice: str, project_42: str
    ) -> None:
        t = store.create_tuple(
            subject_type="usr",
            subject_id=alice,
            relation="viewer",
            object_type="proj",
            object_id=project_42,
        )
        store.delete_tuple(t.id)
        result = store.check(
            subject_type="usr",
            subject_id=alice,
            relation="viewer",
            object_type="proj",
            object_id=project_42,
        )
        assert result.allowed is False
        # Natural-key slot is freed; can recreate.
        recreated = store.create_tuple(
            subject_type="usr",
            subject_id=alice,
            relation="viewer",
            object_type="proj",
            object_id=project_42,
        )
        assert recreated.id != t.id

    def test_throws_for_unknown_id(self, store: InMemoryTupleStore) -> None:
        with pytest.raises(TupleNotFoundError):
            store.delete_tuple("tup_deadbeef00000000000000000000ff")


class TestCascadeRevokeSubject:
    def test_deletes_every_tuple_held_by_subject(
        self,
        store: InMemoryTupleStore,
        alice: str,
        bob: str,
        org_acme: str,
        project_42: str,
    ) -> None:
        store.create_tuple(
            subject_type="usr",
            subject_id=alice,
            relation="owner",
            object_type="org",
            object_id=org_acme,
        )
        store.create_tuple(
            subject_type="usr",
            subject_id=alice,
            relation="editor",
            object_type="proj",
            object_id=project_42,
        )
        store.create_tuple(
            subject_type="usr",
            subject_id=bob,
            relation="member",
            object_type="org",
            object_id=org_acme,
        )

        n = store.cascade_revoke_subject("usr", alice)
        assert n == 2

        alice_page = store.list_tuples_by_subject("usr", alice)
        assert len(alice_page.data) == 0

        bob_page = store.list_tuples_by_subject("usr", bob)
        assert len(bob_page.data) == 1


class TestListing:
    def test_filter_by_relation_when_provided(
        self,
        store: InMemoryTupleStore,
        alice: str,
        bob: str,
        carol: str,
        project_42: str,
    ) -> None:
        for u in (alice, bob, carol):
            store.create_tuple(
                subject_type="usr",
                subject_id=u,
                relation="viewer",
                object_type="proj",
                object_id=project_42,
            )
        store.create_tuple(
            subject_type="usr",
            subject_id=alice,
            relation="editor",
            object_type="proj",
            object_id=project_42,
        )
        viewers = store.list_tuples_by_object("proj", project_42, relation="viewer")
        assert len(viewers.data) == 3
        all_ = store.list_tuples_by_object("proj", project_42)
        assert len(all_.data) == 4

    def test_pagination_via_tup_id_cursor(
        self,
        store: InMemoryTupleStore,
        alice: str,
        bob: str,
        carol: str,
        project_42: str,
    ) -> None:
        for u in (alice, bob, carol):
            store.create_tuple(
                subject_type="usr",
                subject_id=u,
                relation="viewer",
                object_type="proj",
                object_id=project_42,
            )
        page1 = store.list_tuples_by_object(
            "proj", project_42, relation="viewer", limit=2
        )
        assert len(page1.data) == 2
        assert page1.next_cursor is not None
        page2 = store.list_tuples_by_object(
            "proj",
            project_42,
            relation="viewer",
            limit=2,
            cursor=page1.next_cursor,
        )
        assert len(page2.data) == 1
        assert page2.next_cursor is None
