# Schema migrations & versioning

AgentForge has two kinds of schema, and they evolve by different rules.

## 1. Wire contracts (`contracts/v1/*`)

The four inter-agent message schemas are versioned by directory. Every message
carries `schema_version` (`"1.0.0"`), and both the producer (`to_wire`) and the
consumer (`contracts.models.validate_message`) validate against the same files.

**Policy:** additive changes (a new *optional* field, a new event `type` the
rollups already tolerate) stay in `v1` — an older consumer ignores them and a
validator still passes. A **breaking** change (removing/renaming a required
field, tightening a type) ships a new `contracts/v2/` directory and bumps the
message `const` version; the two versions run side by side during migration.

Nothing so far has needed `v2`: the round-2 additions (`cost_usd` now populated,
`decision_path`/`attack_source`, the `drift_check`/`regression_report`/`cost`/
`escalation` event types) are all additive. That is a deliberate outcome of the
optional-field discipline, not an accident.

## 2. History database (`observability/history.py`)

The cross-run trend store (SQLite locally, Postgres in prod) is a real database
that outlives a single process, so it needs in-place migration — adding a field
must upgrade existing rows, not silently no-op.

**Mechanism.** `HistoryStore` tracks a `schema_meta.version` and applies an
ordered `_MIGRATIONS` list (`(to_version, DDL)`) on every open, exactly once per
DB. A DB that predates version tracking is treated as the v1 baseline and
upgraded; a current DB is untouched. `ALTER TABLE ADD COLUMN` is valid in both
SQLite and Postgres, so one migration list covers both backends.

| Version | Change |
|---|---|
| v1 | baseline `campaign_snapshots` (totals + per-category pass rates) |
| v2 | `+ target_version` column — so trends can be sliced per deploy |

**Adding a field (the worked recipe):**
1. Append `(N, "ALTER TABLE campaign_snapshots ADD COLUMN <name> <type>")` to
   `_MIGRATIONS` and bump `SCHEMA_VERSION = N`.
2. Populate it in `record_snapshot` and return it in `snapshots()`.
3. That's it — existing DBs migrate on next open; `test_history.py`
   `::test_migration_upgrades_a_v1_database_in_place` proves an old DB gains the
   column and keeps its rows.

**Guarantee tested:** opening a v1 DB (base table, a row, no `schema_meta`, no
`target_version`) migrates it to the current version, preserves the old row, and
back-fills the new column as NULL — no data loss, no manual step.
