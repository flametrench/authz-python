# flametrench-authz

Python SDK for the [Flametrench v0.1](https://github.com/flametrench/spec) authorization specification: relational tuples and exact-match `check()`. No rewrite rules in v0.1; that's a v0.2+ feature per [ADR 0001](https://github.com/flametrench/spec/blob/main/decisions/0001-authorization-model.md).

The same fixture corpus that gates `@flametrench/authz` (Node) and `flametrench/authz` (PHP) runs here. Cross-language interop is enforced by the test suite.

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
