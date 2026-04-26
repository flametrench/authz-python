# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Flametrench v0.1 conformance suite — Python harness for authorization.

Exercises check, check_any, and create_tuple (uniqueness + format) against
the fixture corpus vendored from
github.com/flametrench/spec/conformance/fixtures/authorization/. The
fixtures under tests/conformance/fixtures/ are a snapshot; the drift-check
CI job verifies they match the upstream spec repo.

Python's snake_case convention happens to match the wire format exactly,
so unlike the Node and PHP harnesses, no key translation is needed here.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from flametrench_authz import (
    ComputedUserset,
    DuplicateTupleError,
    EmptyRelationSetError,
    InMemoryTupleStore,
    InvalidFormatError,
    Rule,
    Rules,
    This,
    TupleToUserset,
)


def _parse_rule_node(node: dict[str, Any]):
    """Parse one JSON rule-node into the SDK's dataclass."""
    t = node["type"]
    if t == "this":
        return This()
    if t == "computed_userset":
        return ComputedUserset(relation=node["relation"])
    if t == "tuple_to_userset":
        return TupleToUserset(
            tupleset_relation=node["tupleset_relation"],
            computed_userset_relation=node["computed_userset_relation"],
        )
    raise ValueError(f"Unknown rule node type: {t}")


def _parse_rules(raw: dict[str, Any] | None) -> Rules | None:
    """Parse the JSON rules field into the SDK's nested Rules type."""
    if not raw:
        return None
    out: dict[str, dict[str, Rule]] = {}
    for object_type, relations in raw.items():
        out[object_type] = {}
        for relation, nodes in relations.items():
            out[object_type][relation] = [_parse_rule_node(n) for n in nodes]
    return out

_FIXTURES_DIR = Path(__file__).parent / "conformance" / "fixtures"


def _load_fixture(relative_path: str) -> dict[str, Any]:
    raw = (_FIXTURES_DIR / relative_path).read_text(encoding="utf-8")
    return json.loads(raw)


def _error_class_for_spec_name(name: str) -> type[Exception]:
    if name == "DuplicateTupleError":
        return DuplicateTupleError
    if name == "InvalidFormatError":
        return InvalidFormatError
    if name == "EmptyRelationSetError":
        return EmptyRelationSetError
    raise RuntimeError(f"Unknown spec error name: {name}")


def _seed(store: InMemoryTupleStore, given: list[dict[str, Any]]) -> None:
    for t in given:
        store.create_tuple(
            subject_type=t["subject_type"],
            subject_id=t["subject_id"],
            relation=t["relation"],
            object_type=t["object_type"],
            object_id=t["object_id"],
        )


def _params(relative_path: str) -> list[Any]:
    fixture = _load_fixture(relative_path)
    return [pytest.param(t, id=t["id"]) for t in fixture["tests"]]


# ─── authorization.check (exact match) ───


@pytest.mark.parametrize("test_case", _params("authorization/check.json"))
def test_check_conformance(test_case: dict[str, Any]) -> None:
    store = InMemoryTupleStore(rules=_parse_rules(test_case.get("rules")))
    _seed(store, test_case["input"]["given_tuples"])
    c = test_case["input"]["check"]
    result = store.check(
        subject_type=c["subject_type"],
        subject_id=c["subject_id"],
        relation=c["relation"],
        object_type=c["object_type"],
        object_id=c["object_id"],
    )
    expected = test_case["expected"]["result"]
    assert result.allowed is expected["allowed"]


# ─── authorization.check with v0.2 rewrite rules ───


def _check_with_rewrites(test_case: dict[str, Any]) -> None:
    store = InMemoryTupleStore(rules=_parse_rules(test_case.get("rules")))
    _seed(store, test_case["input"]["given_tuples"])
    c = test_case["input"]["check"]
    result = store.check(
        subject_type=c["subject_type"],
        subject_id=c["subject_id"],
        relation=c["relation"],
        object_type=c["object_type"],
        object_id=c["object_id"],
    )
    expected = test_case["expected"]["result"]
    assert result.allowed is expected["allowed"]


@pytest.mark.parametrize(
    "test_case",
    _params("authorization/rewrite-rules/computed-userset.json"),
)
def test_rewrite_computed_userset_conformance(test_case: dict[str, Any]) -> None:
    _check_with_rewrites(test_case)


@pytest.mark.parametrize(
    "test_case",
    _params("authorization/rewrite-rules/tuple-to-userset.json"),
)
def test_rewrite_tuple_to_userset_conformance(test_case: dict[str, Any]) -> None:
    _check_with_rewrites(test_case)


@pytest.mark.parametrize(
    "test_case",
    _params("authorization/rewrite-rules/empty-rules-equals-v01.json"),
)
def test_rewrite_empty_rules_equals_v01_conformance(
    test_case: dict[str, Any],
) -> None:
    _check_with_rewrites(test_case)


# ─── authorization.check_any (set form) ───


@pytest.mark.parametrize("test_case", _params("authorization/check-any.json"))
def test_check_any_conformance(test_case: dict[str, Any]) -> None:
    store = InMemoryTupleStore()
    _seed(store, test_case["input"]["given_tuples"])
    c = test_case["input"]["check"]
    if "error" in test_case["expected"]:
        ctor = _error_class_for_spec_name(test_case["expected"]["error"])
        with pytest.raises(ctor):
            store.check_any(
                subject_type=c["subject_type"],
                subject_id=c["subject_id"],
                relations=c["relations"],
                object_type=c["object_type"],
                object_id=c["object_id"],
            )
    else:
        result = store.check_any(
            subject_type=c["subject_type"],
            subject_id=c["subject_id"],
            relations=c["relations"],
            object_type=c["object_type"],
            object_id=c["object_id"],
        )
        expected = test_case["expected"]["result"]
        assert result.allowed is expected["allowed"]


# ─── authorization.create_tuple (uniqueness) ───


@pytest.mark.parametrize("test_case", _params("authorization/uniqueness.json"))
def test_create_tuple_uniqueness_conformance(test_case: dict[str, Any]) -> None:
    store = InMemoryTupleStore()
    _seed(store, test_case["input"]["given_tuples"])
    c = test_case["input"]["create"]
    if "error" in test_case["expected"]:
        ctor = _error_class_for_spec_name(test_case["expected"]["error"])
        with pytest.raises(ctor):
            store.create_tuple(
                subject_type=c["subject_type"],
                subject_id=c["subject_id"],
                relation=c["relation"],
                object_type=c["object_type"],
                object_id=c["object_id"],
            )
    else:
        created = store.create_tuple(
            subject_type=c["subject_type"],
            subject_id=c["subject_id"],
            relation=c["relation"],
            object_type=c["object_type"],
            object_id=c["object_id"],
        )
        assert created.id.startswith("tup_")


# ─── authorization.create_tuple (format) ───


@pytest.mark.parametrize("test_case", _params("authorization/format.json"))
def test_create_tuple_format_conformance(test_case: dict[str, Any]) -> None:
    store = InMemoryTupleStore()
    _seed(store, test_case["input"]["given_tuples"])
    c = test_case["input"]["create"]
    if "error" in test_case["expected"]:
        ctor = _error_class_for_spec_name(test_case["expected"]["error"])
        with pytest.raises(ctor):
            store.create_tuple(
                subject_type=c["subject_type"],
                subject_id=c["subject_id"],
                relation=c["relation"],
                object_type=c["object_type"],
                object_id=c["object_id"],
            )
    else:
        created = store.create_tuple(
            subject_type=c["subject_type"],
            subject_id=c["subject_id"],
            relation=c["relation"],
            object_type=c["object_type"],
            object_id=c["object_id"],
        )
        assert created.id.startswith("tup_")
