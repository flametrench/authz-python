# flametrench-authz

[![CI](https://github.com/flametrench/authz-python/actions/workflows/ci.yml/badge.svg)](https://github.com/flametrench/authz-python/actions/workflows/ci.yml)

Python SDK for the [Flametrench](https://github.com/flametrench/spec) authorization specification: relational tuples and exact-match `check()`. Exact-match is the default — no implicit rewriting at the API boundary ([ADR 0001](https://github.com/flametrench/spec/blob/main/decisions/0001-authorization-model.md)). v0.2 adds opt-in rewrite rules ([ADR 0007](https://github.com/flametrench/spec/blob/main/decisions/0007-rewrite-rules.md)) — `computed_userset` (role implication) and `tuple_to_userset` (parent-child inheritance) — for adopters who want hierarchies. Group expansion remains deferred.

The same fixture corpus that gates `@flametrench/authz` (Node), `flametrench/authz` (PHP), and `dev.flametrench:authz` (Java) runs here. Cross-language interop is enforced by the test suite.

**Status:** v0.2.0rc4 (release candidate). Includes `ShareStore` ([ADR 0012](https://github.com/flametrench/spec/blob/main/decisions/0012-share-tokens.md)) and Postgres-backed adapters (`PostgresTupleStore`, `PostgresShareStore`).

```python
from flametrench_authz import InMemoryTupleStore
from flametrench_ids import generate

store = InMemoryTupleStore()
alice = generate("usr")
project_42 = generate("org")[4:]  # bare hex for app-owned objects

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
```

## Installation

```bash
pip install flametrench-authz
```

Requires Python 3.11+. Depends on `flametrench-ids` for tup_ id generation.

## Spec invariants enforced

- **Exact-match `check()`** — returns true iff a tuple with the exact 5-tuple natural key exists. No derivation; admin does NOT imply editor.
- **Uniqueness** — duplicate creation of the same `(subject_type, subject_id, relation, object_type, object_id)` raises `DuplicateTupleError`.
- **Format** — relations match `^[a-z_]{2,32}$`; object types match `^[a-z]{2,6}$`. Violations raise `InvalidFormatError`.
- **Empty-set rejection** — `check_any()` with an empty `relations` array raises `EmptyRelationSetError` rather than silently returning false.

## Conformance

```bash
pytest
```

Runs the same authorization fixture corpus — `check.json`, `check-any.json`, `uniqueness.json`, `format.json` — that gates the Node and PHP SDKs.

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

Copyright 2026 NDC Digital, LLC.
