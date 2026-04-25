# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Authorization entity types.

Frozen dataclasses (immutable, comparable) for cross-language parity
with the readonly classes used in the PHP and Node SDKs.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Generic, TypeVar

T = TypeVar("T")


@dataclass(frozen=True)
class Tuple:
    """A relational tuple — the sole authz primitive in v0.1.

    The natural key is ``(subject_type, subject_id, relation, object_type,
    object_id)``. ``id`` is the opaque tup_ identifier.
    """

    id: str
    subject_type: str
    subject_id: str
    relation: str
    object_type: str
    object_id: str
    created_at: datetime
    created_by: str | None = None


@dataclass(frozen=True)
class CheckResult:
    """Returned by check() and check_any().

    ``matched_tuple_id`` is None when ``allowed`` is False, or when the
    implementation chooses not to disclose which tuple satisfied.
    """

    allowed: bool
    matched_tuple_id: str | None = None


@dataclass(frozen=True)
class Page(Generic[T]):
    """A paginated slice of a list operation."""

    data: list[T]
    next_cursor: str | None
