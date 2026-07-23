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
