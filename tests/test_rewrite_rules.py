# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for v0.2 rewrite-rule evaluation.

Covers ADR 0007's load-bearing cases:
- empty rules ⇒ v0.1-equivalent behavior
- computed_userset (role implication chain)
- tuple_to_userset (parent-child inheritance)
- cycle detection (silent skip, not error)
- depth limit (raises EvaluationLimitExceededError)
- fan-out limit (same)
"""

from __future__ import annotations

import pytest
from flametrench_ids import generate

from flametrench_authz import (
    ComputedUserset,
    EvaluationLimitExceededError,
    InMemoryTupleStore,
    This,
    TupleToUserset,
)


@pytest.fixture
def alice() -> str:
    return generate("usr")


@pytest.fixture
def bob() -> str:
    return generate("usr")


@pytest.fixture
def org_acme() -> str:
    return generate("org")


@pytest.fixture
def proj_42() -> str:
    return generate("org")[4:]  # bare hex


class TestEmptyRulesEqualsV01:
    """The load-bearing v0.1 compatibility guarantee."""

    def test_no_rules_means_no_derivation(
        self, alice: str, proj_42: str
    ) -> None:
        store = InMemoryTupleStore()  # rules=None
        store.create_tuple(
            subject_type="usr",
            subject_id=alice,
            relation="editor",
            object_type="proj",
            object_id=proj_42,
        )
        # editor doesn't imply viewer when no rules registered
        result = store.check(
            subject_type="usr",
            subject_id=alice,
            relation="viewer",
            object_type="proj",
            object_id=proj_42,
        )
        assert result.allowed is False

    def test_empty_rules_dict_means_no_derivation(
        self, alice: str, proj_42: str
    ) -> None:
        store = InMemoryTupleStore(rules={})
        store.create_tuple(
            subject_type="usr",
            subject_id=alice,
            relation="editor",
            object_type="proj",
            object_id=proj_42,
        )
        result = store.check(
            subject_type="usr",
            subject_id=alice,
            relation="viewer",
            object_type="proj",
            object_id=proj_42,
        )
        assert result.allowed is False


class TestComputedUserset:
    """Role implication on the same object."""

    def test_editor_implies_viewer(self, alice: str, proj_42: str) -> None:
        rules = {
            "proj": {
                "viewer": [This(), ComputedUserset(relation="editor")],
            },
        }
        store = InMemoryTupleStore(rules=rules)
        editor_tup = store.create_tuple(
            subject_type="usr",
            subject_id=alice,
            relation="editor",
            object_type="proj",
            object_id=proj_42,
        )
        result = store.check(
            subject_type="usr",
            subject_id=alice,
            relation="viewer",
            object_type="proj",
            object_id=proj_42,
        )
        assert result.allowed is True
        # The matched tuple is the underlying editor tuple, not a synthetic.
        assert result.matched_tuple_id == editor_tup.id

    def test_admin_implies_editor_implies_viewer(
        self, alice: str, proj_42: str
    ) -> None:
        rules = {
            "proj": {
                "viewer": [This(), ComputedUserset(relation="editor")],
                "editor": [This(), ComputedUserset(relation="admin")],
            },
        }
        store = InMemoryTupleStore(rules=rules)
        admin_tup = store.create_tuple(
            subject_type="usr",
            subject_id=alice,
            relation="admin",
            object_type="proj",
            object_id=proj_42,
        )
        # check viewer — should resolve through admin → editor → viewer
        result = store.check(
            subject_type="usr",
            subject_id=alice,
            relation="viewer",
            object_type="proj",
            object_id=proj_42,
        )
        assert result.allowed is True
        assert result.matched_tuple_id == admin_tup.id

    def test_no_chain_to_admin_no_implication(
        self, alice: str, proj_42: str
    ) -> None:
        # Rules wire viewer ← editor but NOT editor ← admin.
        rules = {
            "proj": {
                "viewer": [This(), ComputedUserset(relation="editor")],
            },
        }
        store = InMemoryTupleStore(rules=rules)
        store.create_tuple(
            subject_type="usr",
            subject_id=alice,
            relation="admin",
            object_type="proj",
            object_id=proj_42,
        )
        # admin → viewer requires admin → editor → viewer; the
        # admin → editor edge isn't in the rule set.
        result = store.check(
            subject_type="usr",
            subject_id=alice,
            relation="viewer",
            object_type="proj",
            object_id=proj_42,
        )
        assert result.allowed is False


class TestTupleToUserset:
    """Parent-child inheritance via a relation hop."""

    def test_org_admin_implies_proj_admin_via_parent_org(
        self, alice: str, org_acme: str, proj_42: str
    ) -> None:
        # Rule: proj.admin satisfied by (proj#parent_org).admin
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
        store = InMemoryTupleStore(rules=rules)
        # Alice is admin of org_acme.
        org_admin = store.create_tuple(
            subject_type="usr",
            subject_id=alice,
            relation="admin",
            object_type="org",
            object_id=org_acme,
        )
        # proj_42 has parent_org pointing to org_acme.
        # The "subject" of the parent_org tuple is the org itself.
        store.create_tuple(
            subject_type="org",  # org as subject — works because
            subject_id=org_acme,  # subject_type accepts any v0.1 prefix
            relation="parent_org",
            object_type="proj",
            object_id=proj_42,
        )
        # Now alice should have admin on proj_42 via the rewrite.
        result = store.check(
            subject_type="usr",
            subject_id=alice,
            relation="admin",
            object_type="proj",
            object_id=proj_42,
        )
        assert result.allowed is True
        assert result.matched_tuple_id == org_admin.id

    def test_org_member_does_not_imply_proj_admin(
        self, alice: str, org_acme: str, proj_42: str
    ) -> None:
        # Rule: proj.admin satisfied by (proj#parent_org).admin
        # Alice is a MEMBER of org_acme, not an admin.
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
        store = InMemoryTupleStore(rules=rules)
        store.create_tuple(
            subject_type="usr",
            subject_id=alice,
            relation="member",
            object_type="org",
            object_id=org_acme,
        )
        store.create_tuple(
            subject_type="org",
            subject_id=org_acme,
            relation="parent_org",
            object_type="proj",
            object_id=proj_42,
        )
        result = store.check(
            subject_type="usr",
            subject_id=alice,
            relation="admin",
            object_type="proj",
            object_id=proj_42,
        )
        assert result.allowed is False


class TestCycleDetection:
    def test_self_referential_cycle_terminates_silently(
        self, alice: str, proj_42: str
    ) -> None:
        # Rule with a cycle: proj.viewer ← proj.viewer (self-reference).
        # The cycle adds no information; evaluation should silently
        # return denied without raising.
        rules = {
            "proj": {
                "viewer": [This(), ComputedUserset(relation="viewer")],
            },
        }
        store = InMemoryTupleStore(rules=rules)
        # No direct viewer tuple → cycle path → denied.
        result = store.check(
            subject_type="usr",
            subject_id=alice,
            relation="viewer",
            object_type="proj",
            object_id=proj_42,
        )
        assert result.allowed is False

    def test_two_node_cycle_terminates_silently(
        self, alice: str, proj_42: str
    ) -> None:
        # viewer ← editor ← viewer creates a 2-node cycle.
        rules = {
            "proj": {
                "viewer": [This(), ComputedUserset(relation="editor")],
                "editor": [This(), ComputedUserset(relation="viewer")],
            },
        }
        store = InMemoryTupleStore(rules=rules)
        result = store.check(
            subject_type="usr",
            subject_id=alice,
            relation="viewer",
            object_type="proj",
            object_id=proj_42,
        )
        assert result.allowed is False


class TestDepthLimit:
    def test_depth_limit_raises(self, alice: str, proj_42: str) -> None:
        # Build a chain longer than max_depth=2.
        rules = {
            "proj": {
                "r0": [This(), ComputedUserset(relation="r1")],
                "r1": [This(), ComputedUserset(relation="r2")],
                "r2": [This(), ComputedUserset(relation="r3")],
                "r3": [This(), ComputedUserset(relation="r4")],
            },
        }
        store = InMemoryTupleStore(rules=rules, max_depth=2)
        with pytest.raises(EvaluationLimitExceededError):
            store.check(
                subject_type="usr",
                subject_id=alice,
                relation="r0",
                object_type="proj",
                object_id=proj_42,
            )

    def test_within_depth_limit_succeeds(
        self, alice: str, proj_42: str
    ) -> None:
        rules = {
            "proj": {
                "viewer": [This(), ComputedUserset(relation="editor")],
                "editor": [This(), ComputedUserset(relation="admin")],
            },
        }
        store = InMemoryTupleStore(rules=rules, max_depth=4)
        store.create_tuple(
            subject_type="usr",
            subject_id=alice,
            relation="admin",
            object_type="proj",
            object_id=proj_42,
        )
        result = store.check(
            subject_type="usr",
            subject_id=alice,
            relation="viewer",
            object_type="proj",
            object_id=proj_42,
        )
        assert result.allowed is True


class TestFanOutLimit:
    def test_fan_out_limit_raises(self, alice: str) -> None:
        # 5 parent_org tuples at fan-out limit 3 should raise.
        proj = generate("org")[4:]
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
        store = InMemoryTupleStore(rules=rules, max_fan_out=3)
        for _ in range(5):
            org_id = generate("org")
            store.create_tuple(
                subject_type="org",
                subject_id=org_id,
                relation="parent_org",
                object_type="proj",
                object_id=proj,
            )
        with pytest.raises(EvaluationLimitExceededError):
            store.check(
                subject_type="usr",
                subject_id=alice,
                relation="admin",
                object_type="proj",
                object_id=proj,
            )


class TestDirectFastPath:
    """When a direct tuple matches, rule expansion never runs."""

    def test_direct_match_short_circuits_rules(
        self, alice: str, proj_42: str
    ) -> None:
        # A pathological rule set that would otherwise loop infinitely
        # without cycle detection. The direct fast path should bypass
        # rules entirely.
        rules = {
            "proj": {
                "viewer": [This(), ComputedUserset(relation="viewer")],
            },
        }
        store = InMemoryTupleStore(rules=rules, max_depth=2)
        direct = store.create_tuple(
            subject_type="usr",
            subject_id=alice,
            relation="viewer",
            object_type="proj",
            object_id=proj_42,
        )
        result = store.check(
            subject_type="usr",
            subject_id=alice,
            relation="viewer",
            object_type="proj",
            object_id=proj_42,
        )
        assert result.allowed is True
        assert result.matched_tuple_id == direct.id
