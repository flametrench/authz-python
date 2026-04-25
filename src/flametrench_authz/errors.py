# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Error types raised by the authorization layer.

Every error carries a stable `code` matching the OpenAPI Error envelope.
"""

from __future__ import annotations


class AuthzError(Exception):
    """Base class for every authorization-layer error."""

    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code


class TupleNotFoundError(AuthzError):
    """A tuple with the requested id does not exist."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="not_found")


class DuplicateTupleError(AuthzError):
    """A tuple with the same natural key already exists.

    Callers MAY treat this as an idempotency success by fetching the
    existing tuple via ``existing_tuple_id``; this package raises an
    error to make the duplication explicit.
    """

    def __init__(self, message: str, existing_tuple_id: str) -> None:
        super().__init__(message, code="conflict.duplicate_tuple")
        self.existing_tuple_id = existing_tuple_id


class InvalidFormatError(AuthzError):
    """An input violates a spec-defined format rule."""

    def __init__(self, message: str, field: str) -> None:
        super().__init__(message, code=f"invalid_format.{field}")
        self.field = field


class EmptyRelationSetError(AuthzError):
    """The check-set form was called with an empty relations array."""

    def __init__(self) -> None:
        super().__init__(
            "check_any() relations array must be non-empty",
            code="invalid_format.relations",
        )
