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


class EvaluationLimitExceededError(AuthzError):
    """Rewrite-rule evaluation exceeded a bound (depth or fan-out).

    Raised by :func:`flametrench_authz.rewrite_rules.evaluate` when a
    chain of computed_userset / tuple_to_userset hops exceeds the
    configured ``max_depth`` or when a single ``TupleToUserset`` step
    enumerates more tuples than ``max_fan_out``.

    Bounds are configurable per-store; the spec floor is depth=8,
    fan-out=1024. Apps hitting this in practice should restructure
    their rule set or explicitly raise the limit.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, code="evaluation_limit_exceeded")


# ─── v0.2 share-token errors (ADR 0012) ───


class InvalidShareTokenError(AuthzError):
    """Generic violation of ``verify_share_token`` precondition.

    Raised when the token doesn't match any row, or when the hash
    comparison fails. Deliberately conflated to avoid a timing oracle
    distinguishing "no such hash" from "hash collision but mismatch".
    """

    def __init__(self, message: str = "Invalid share token") -> None:
        super().__init__(message, code="invalid_share_token")


class ShareExpiredError(AuthzError):
    """The share's ``expires_at`` has passed."""

    def __init__(self, message: str = "Share has expired") -> None:
        super().__init__(message, code="share_expired")


class ShareRevokedError(AuthzError):
    """The share has been explicitly revoked."""

    def __init__(self, message: str = "Share has been revoked") -> None:
        super().__init__(message, code="share_revoked")


class ShareConsumedError(AuthzError):
    """A single-use share has already been consumed."""

    def __init__(self, message: str = "Share has already been consumed") -> None:
        super().__init__(message, code="share_consumed")


class ShareNotFoundError(AuthzError):
    """A share with the requested id does not exist."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="not_found")
