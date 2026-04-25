# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""TupleStore — the contract every authorization backend implements.

Exact-match semantics: ``check()`` returns true iff a tuple with the
exact 5-tuple key exists. No derivation, no inheritance, no group
expansion in v0.1. Any implementation that returns true for a missing
tuple — even via a reasonable inference — is NOT conformant.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .types import CheckResult, Page, Tuple


@runtime_checkable
class TupleStore(Protocol):
    # ─── Mutations ───

    def create_tuple(
        self,
        subject_type: str,
        subject_id: str,
        relation: str,
        object_type: str,
        object_id: str,
        *,
        created_by: str | None = None,
    ) -> Tuple: ...

    def delete_tuple(self, tuple_id: str) -> None: ...

    def cascade_revoke_subject(self, subject_type: str, subject_id: str) -> int:
        """Delete every tuple with the given subject. Returns count."""
        ...

    # ─── The check primitive ───

    def check(
        self,
        subject_type: str,
        subject_id: str,
        relation: str,
        object_type: str,
        object_id: str,
    ) -> CheckResult: ...

    def check_any(
        self,
        subject_type: str,
        subject_id: str,
        relations: list[str],
        object_type: str,
        object_id: str,
    ) -> CheckResult: ...

    # ─── Read accessors ───

    def get_tuple(self, tuple_id: str) -> Tuple: ...

    def list_tuples_by_subject(
        self,
        subject_type: str,
        subject_id: str,
        *,
        cursor: str | None = None,
        limit: int = 50,
    ) -> Page[Tuple]: ...

    def list_tuples_by_object(
        self,
        object_type: str,
        object_id: str,
        *,
        relation: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> Page[Tuple]: ...
