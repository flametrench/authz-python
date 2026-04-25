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
    DuplicateTupleError,
    EmptyRelationSetError,
    InMemoryTupleStore,
    InvalidFormatError,
)

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
    store = InMemoryTupleStore()
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
