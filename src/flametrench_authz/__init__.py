# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""flametrench-authz — relational tuples and exact-match check().

The spec-normative authorization layer for Flametrench v0.1. See the
upstream specification at
https://github.com/flametrench/spec/blob/main/docs/authorization.md.

Exact-match semantics: ``check()`` returns true iff a tuple with the
exact 5-tuple key exists. No derivation, no inheritance, no group
expansion in v0.1.
"""

from .errors import (
    AuthzError,
    DuplicateTupleError,
    EmptyRelationSetError,
    InvalidFormatError,
    TupleNotFoundError,
)
from .in_memory import InMemoryTupleStore
from .patterns import RELATION_NAME_PATTERN, TYPE_PREFIX_PATTERN
from .store import TupleStore
from .types import CheckResult, Page, Tuple

__all__ = [
    "AuthzError",
    "CheckResult",
    "DuplicateTupleError",
    "EmptyRelationSetError",
    "InMemoryTupleStore",
    "InvalidFormatError",
    "Page",
    "RELATION_NAME_PATTERN",
    "TYPE_PREFIX_PATTERN",
    "Tuple",
    "TupleNotFoundError",
    "TupleStore",
]

__version__ = "0.1.0"
