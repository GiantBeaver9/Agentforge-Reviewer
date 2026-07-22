"""Over-time campaign history — the trend layer above the per-run store.

``ObservabilityStore`` answers "what happened in *this* run" from an append-only
JSONL log; that log is per-campaign and (on an ephemeral PaaS filesystem) does
not survive a redeploy. This module keeps the *cross-run* series the dashboard's
trend view needs: one immutable **snapshot row per campaign** — its totals and
per-category pass rates at completion — in a real database so history persists.

Two backends behind one interface, selected by environment (same opt-in/fail-soft
spirit as the LLM adapters):

* **Postgres** when ``DATABASE_URL`` is set (e.g. Railway injects it). Durable
  across deploys — this is the deployed path.
* **SQLite** otherwise, at a local file. The default for local dev, tests, and
  any egress-restricted sandbox. Zero third-party dependency (stdlib ``sqlite3``).

The snapshot is derived deterministically from a ``store.summary()`` dict, so the
history layer adds no new source of truth — it just retains what the deterministic
rollup already computed.
"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def overall_pass_rate(summary: dict[str, Any]) -> float | None:
    """Verdicts-weighted defended-fraction across every coverage cell.

    ``failure`` means the target defended, so pass_rate = failures / verdicts
    over the whole run. ``None`` when nothing was judged (distinct from 0.0),
    matching ``CategoryCoverage.pass_rate``'s contract.
    """
    verdicts = 0
    failures = 0
    for c in summary.get("coverage", []):
        verdicts += int(c.get("verdicts", 0) or 0)
        failures += int(c.get("failures", 0) or 0)
    if verdicts == 0:
        return None
    return failures / verdicts


class HistoryStore:
    """Append-only snapshot store for cross-run trends.

    ``url`` (or ``DATABASE_URL``) picks Postgres; otherwise a SQLite file at
    ``sqlite_path`` (or ``AGENTFORGE_HISTORY_DB``, else ``runs/history.db``).
    """

    def __init__(self, url: str | None = None, sqlite_path: str | Path | None = None):
        url = url if url is not None else os.environ.get("DATABASE_URL", "")
        if url and url.startswith(("postgres://", "postgresql://")):
            self.backend = "postgres"
            # psycopg3 accepts either scheme; normalize the legacy one.
            self._url = "postgresql://" + url.split("://", 1)[1]
            self._ph = "%s"
        else:
            self.backend = "sqlite"
            path = (sqlite_path or os.environ.get("AGENTFORGE_HISTORY_DB")
                    or (Path("runs") / "history.db"))
            self._path = Path(path)
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._ph = "?"
        self._ensure_schema()

    # ---- connection --------------------------------------------------------
    def _connect(self):
        if self.backend == "postgres":
            import psycopg  # lazy: only the deployed Postgres path needs the driver
            return psycopg.connect(self._url)
        return sqlite3.connect(str(self._path))

    def _ensure_schema(self) -> None:
        # Column types chosen to be valid in both SQLite and Postgres; run_id is
        # the natural key (one snapshot per campaign) so no dialect-specific
        # autoincrement is needed. recorded_at is ISO-8601, which sorts
        # chronologically as text.
        ddl = (
            "CREATE TABLE IF NOT EXISTS campaign_snapshots ("
            " run_id TEXT PRIMARY KEY,"
            " recorded_at TEXT NOT NULL,"
            " mode TEXT NOT NULL,"
            " attempts INTEGER NOT NULL,"
            " verdicts INTEGER NOT NULL,"
            " open_findings INTEGER NOT NULL,"
            " cost_usd DOUBLE PRECISION NOT NULL,"
            " pass_rate DOUBLE PRECISION,"
            " coverage_json TEXT NOT NULL)"
        )
        conn = self._connect()
        try:
            conn.execute(ddl)
            conn.commit()
        finally:
            conn.close()

    # ---- write -------------------------------------------------------------
    def record_snapshot(self, run_id: str, summary: dict[str, Any],
                        mode: str = "unknown", recorded_at: str | None = None) -> dict[str, Any]:
        """Persist one campaign's completion snapshot, derived from ``summary``.

        Idempotent on ``run_id`` (a re-record overwrites), so replaying a run
        does not double-count. Returns the row that was written.
        """
        row = {
            "run_id": run_id,
            "recorded_at": recorded_at or _now(),
            "mode": mode,
            "attempts": int(summary.get("attempts", 0) or 0),
            "verdicts": int(summary.get("verdicts", 0) or 0),
            "open_findings": int(summary.get("open_findings", 0) or 0),
            "cost_usd": float(summary.get("cost_usd", 0.0) or 0.0),
            "pass_rate": overall_pass_rate(summary),
            "coverage_json": json.dumps(summary.get("coverage", [])),
        }
        cols = ("run_id", "recorded_at", "mode", "attempts", "verdicts",
                "open_findings", "cost_usd", "pass_rate", "coverage_json")
        placeholders = ", ".join(self._ph for _ in cols)
        values = [row[c] for c in cols]
        # Upsert on run_id — ON CONFLICT ... EXCLUDED is valid in modern SQLite
        # (>=3.24) and Postgres alike.
        sql = (f"INSERT INTO campaign_snapshots ({', '.join(cols)}) "
               f"VALUES ({placeholders}) ON CONFLICT (run_id) DO UPDATE SET "
               + ", ".join(f"{c}=EXCLUDED.{c}" for c in cols if c != "run_id"))
        conn = self._connect()
        try:
            conn.execute(sql, values)
            conn.commit()
        finally:
            conn.close()
        return row

    # ---- read --------------------------------------------------------------
    def snapshots(self, limit: int = 100) -> list[dict[str, Any]]:
        """Recorded snapshots, oldest first (chronological for a trend line),
        capped to the most recent ``limit``."""
        q = (f"SELECT run_id, recorded_at, mode, attempts, verdicts, open_findings,"
             f" cost_usd, pass_rate, coverage_json FROM campaign_snapshots"
             f" ORDER BY recorded_at DESC LIMIT {self._ph}")
        conn = self._connect()
        try:
            cur = conn.execute(q, [int(limit)])
            rows = cur.fetchall()
        finally:
            conn.close()
        out = []
        for r in reversed(rows):  # DESC+LIMIT then reverse -> oldest-first, capped
            out.append({
                "run_id": r[0], "recorded_at": r[1], "mode": r[2],
                "attempts": r[3], "verdicts": r[4], "open_findings": r[5],
                "cost_usd": r[6], "pass_rate": r[7],
                "coverage": json.loads(r[8]) if r[8] else [],
            })
        return out

    def trends(self, limit: int = 100) -> dict[str, Any]:
        """Dashboard-shaped trend payload: the ordered series plus the backend
        in use (so the UI can say whether history is durable or local)."""
        series = self.snapshots(limit)
        return {"backend": self.backend, "count": len(series), "series": series}
