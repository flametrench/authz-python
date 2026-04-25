# Copyright 2026 NDC Digital, LLC
# SPDX-License-Identifier: Apache-2.0

"""Format-rule constants matching the Flametrench v0.1 specification."""

import re

# Relation name regex — `^[a-z_]{2,32}$`. Custom relations matching this
# pattern are accepted; uppercase, length, and special characters are not.
RELATION_NAME_PATTERN = re.compile(r"^[a-z_]{2,32}$")

# Object-type prefix regex — `^[a-z]{2,6}$`. Mirrors the type-prefix rule
# from docs/ids.md.
TYPE_PREFIX_PATTERN = re.compile(r"^[a-z]{2,6}$")
