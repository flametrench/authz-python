# Changelog

All notable changes to `flametrench-authz` are recorded here.
Spec-level changes live in [`spec/CHANGELOG.md`](https://github.com/flametrench/spec/blob/main/CHANGELOG.md).

## [v0.2.0rc2] — 2026-04-27

### Added
- `PostgresTupleStore` (new module `flametrench_authz.postgres`) — a Postgres-backed `TupleStore`. Mirrors `InMemoryTupleStore` byte-for-byte at the SDK boundary; the difference is durability and concurrency.
  - Schema: `spec/reference/postgres.sql` (the `tup` table). Apply before constructing the store.
  - Connection: accepts any psycopg3-compatible connection. `psycopg[binary]>=3.1` declared as the `postgres` extra — adopters using only the in-memory store don't pull it in.
  - Coverage: 15 integration tests, gated on `AUTHZ_POSTGRES_URL`.
- Rewrite-rule support (ADR 0007) is exact-match only in the Postgres store; bridging the synchronous evaluator to DB I/O is tracked for v0.3. Adopters with rule needs can pull the relevant tuple subset into memory and use `InMemoryTupleStore(rules=...)`.

## [v0.2.0rc1] — 2026-04-25

Initial v0.2 release-candidate. ADR 0007 rewrite rules in `InMemoryTupleStore`. See [`spec/CHANGELOG.md`](https://github.com/flametrench/spec/blob/main/CHANGELOG.md) for the spec-level summary.

For pre-rc history, see git tags.
