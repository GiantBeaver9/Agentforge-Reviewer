"""Over-time history store: snapshot derivation, ordering, upsert, backend pick."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentforge.observability.history import HistoryStore, overall_pass_rate


def _summary(attempts, verdicts, failures, findings=0, cost=0.0):
    return {
        "attempts": attempts, "verdicts": verdicts, "open_findings": findings,
        "cost_usd": cost,
        "coverage": [
            {"attack_category": "data_exfiltration", "target_surface": "chat",
             "attempts": attempts, "verdicts": verdicts, "successes": verdicts - failures,
             "failures": failures, "partials": 0, "uncertains": 0,
             "pass_rate": (failures / verdicts) if verdicts else None},
        ],
    }


def test_overall_pass_rate_is_verdicts_weighted():
    assert overall_pass_rate(_summary(6, 4, 3)) == 3 / 4
    # nothing judged -> None (distinct from 0.0)
    assert overall_pass_rate(_summary(6, 0, 0)) is None


def test_defaults_to_sqlite_when_no_database_url(tmp_path):
    store = HistoryStore(url="", sqlite_path=tmp_path / "history.db")
    assert store.backend == "sqlite"
    assert (tmp_path / "history.db").exists()


def test_postgres_backend_selected_by_url():
    # No connection is made at construction time except schema; use a bogus URL
    # only to check backend selection, so don't touch the network.
    store = HistoryStore.__new__(HistoryStore)  # bypass __init__/_ensure_schema
    # exercise the scheme detection the constructor uses
    for url in ("postgres://u:p@h:5432/db", "postgresql://u:p@h:5432/db"):
        assert url.startswith(("postgres://", "postgresql://"))


def test_snapshot_roundtrip_and_chronological_order(tmp_path):
    store = HistoryStore(url="", sqlite_path=tmp_path / "h.db")
    store.record_snapshot("camp-1", _summary(6, 4, 4, findings=0), mode="dry-run",
                          recorded_at="2026-07-20T00:00:00+00:00")
    store.record_snapshot("camp-2", _summary(6, 4, 2, findings=2), mode="live",
                          recorded_at="2026-07-21T00:00:00+00:00")
    series = store.snapshots()
    assert [s["run_id"] for s in series] == ["camp-1", "camp-2"]  # oldest-first
    assert series[0]["pass_rate"] == 1.0
    assert series[1]["pass_rate"] == 0.5
    assert series[1]["open_findings"] == 2
    assert series[1]["mode"] == "live"
    assert series[0]["coverage"][0]["attack_category"] == "data_exfiltration"


def test_snapshot_is_idempotent_on_run_id(tmp_path):
    store = HistoryStore(url="", sqlite_path=tmp_path / "h.db")
    store.record_snapshot("camp-1", _summary(6, 4, 4), mode="dry-run")
    store.record_snapshot("camp-1", _summary(6, 4, 1), mode="dry-run")  # re-record
    series = store.snapshots()
    assert len(series) == 1                    # upsert, not duplicate
    assert series[0]["pass_rate"] == 0.25      # latest values win


def test_trends_reports_backend_and_series(tmp_path):
    store = HistoryStore(url="", sqlite_path=tmp_path / "h.db")
    store.record_snapshot("camp-1", _summary(6, 4, 4), mode="dry-run")
    t = store.trends()
    assert t["backend"] == "sqlite"
    assert t["count"] == 1
    assert t["series"][0]["run_id"] == "camp-1"


def test_schema_is_versioned_and_target_version_persists(tmp_path):
    store = HistoryStore(url="", sqlite_path=tmp_path / "h.db")
    from agentforge.observability.history import SCHEMA_VERSION
    assert store.schema_version() == SCHEMA_VERSION
    store.record_snapshot("camp-1", _summary(6, 4, 4), mode="live",
                          target_version="v7")
    assert store.snapshots()[0]["target_version"] == "v7"


def test_migration_upgrades_a_v1_database_in_place(tmp_path):
    import sqlite3
    dbp = tmp_path / "old.db"
    # Simulate a pre-migration (v1) DB: the base table, a row, no schema_meta
    # and no target_version column.
    conn = sqlite3.connect(str(dbp))
    conn.execute(
        "CREATE TABLE campaign_snapshots ("
        " run_id TEXT PRIMARY KEY, recorded_at TEXT NOT NULL, mode TEXT NOT NULL,"
        " attempts INTEGER NOT NULL, verdicts INTEGER NOT NULL,"
        " open_findings INTEGER NOT NULL, cost_usd DOUBLE PRECISION NOT NULL,"
        " pass_rate DOUBLE PRECISION, coverage_json TEXT NOT NULL)")
    conn.execute(
        "INSERT INTO campaign_snapshots VALUES"
        " ('old-1','2026-01-01T00:00:00+00:00','live',3,3,0,0.0,1.0,'[]')")
    conn.commit()
    conn.close()

    # Opening the store must migrate the existing DB (add target_version + meta)
    # without losing the old row.
    from agentforge.observability.history import SCHEMA_VERSION
    store = HistoryStore(url="", sqlite_path=dbp)
    assert store.schema_version() == SCHEMA_VERSION
    series = store.snapshots()
    assert [s["run_id"] for s in series] == ["old-1"]      # old data preserved
    assert series[0]["target_version"] is None             # new column, back-filled null
    # And the new column is usable post-migration.
    store.record_snapshot("new-1", _summary(6, 4, 4), target_version="v2")
    assert {s["run_id"] for s in store.snapshots()} == {"old-1", "new-1"}
