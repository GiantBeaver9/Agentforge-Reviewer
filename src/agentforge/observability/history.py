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


# Schema evolution. The base table is v1; each migration is (to_version, DDL)
# applied in order, tracked in ``schema_meta`` so it runs exactly once per DB and
# an existing DB is upgraded in place rather than silently drifting. ALTER TABLE
# ADD COLUMN is valid in both SQLite and Postgres, so one list covers both
# backends. See docs/migrations/README.md.
SCHEMA_VERSION = 3
_BASE_VERSION = 1
# Each migration is (to_version, (ddl, ...)) — a tuple of statements applied in
# order, once, tracked in schema_meta. ADD COLUMN / CREATE INDEX / CREATE TABLE
# are valid in both SQLite and Postgres.
_MIGRATIONS: list[tuple[int, tuple[str, ...]]] = [
    # v1 -> v2: per-version pass/fail breakdown needs the target's deploy id.
    (2, ("ALTER TABLE campaign_snapshots ADD COLUMN target_version TEXT",)),
    # v2 -> v3: findings get real, INDEXED columns (severity, attack_category)
    # instead of being buried in a JSON blob, so a triage query is index-backed.
    (3, (
        "CREATE TABLE IF NOT EXISTS findings ("
        " finding_id TEXT PRIMARY KEY,"
        " run_id TEXT NOT NULL,"
        " severity TEXT NOT NULL,"
        " attack_category TEXT NOT NULL,"
        " target_surface TEXT,"
        " status TEXT,"
        " lifecycle TEXT,"
        " confidence DOUBLE PRECISION,"
        " correlation_id TEXT,"
        " recorded_at TEXT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)",
        "CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(attack_category)",
        "CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id)",
        "CREATE INDEX IF NOT EXISTS idx_snapshots_recorded ON campaign_snapshots(recorded_at)",
        "CREATE INDEX IF NOT EXISTS idx_snapshots_version ON campaign_snapshots(target_version)",
    )),
]


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
        # chronologically as text. This DDL is the v1 baseline; anything added
        # since ships as a tracked migration below so existing DBs upgrade.
        base_ddl = (
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
            conn.execute(base_ddl)
            conn.execute("CREATE TABLE IF NOT EXISTS schema_meta (version INTEGER NOT NULL)")
            cur = conn.execute("SELECT version FROM schema_meta")
            row = cur.fetchone()
            if row is None:
                # A DB that predates version tracking (or a fresh one) is treated
                # as the v1 baseline; migrations then bring it to current.
                current = _BASE_VERSION
                conn.execute(f"INSERT INTO schema_meta (version) VALUES ({self._ph})",
                             [current])
            else:
                current = int(row[0])
            for to_version, statements in _MIGRATIONS:
                if to_version > current:
                    for ddl in statements:
                        try:
                            conn.execute(ddl)
                        except Exception:  # noqa: BLE001 — column/table may exist
                            # Idempotent: a statement that already ran (a DB
                            # migrated out of band) is not an error.
                            pass
                    current = to_version
            conn.execute(f"UPDATE schema_meta SET version = {self._ph}", [current])
            conn.commit()
        finally:
            conn.close()

    def schema_version(self) -> int:
        conn = self._connect()
        try:
            cur = conn.execute("SELECT version FROM schema_meta")
            row = cur.fetchone()
            return int(row[0]) if row else 0
        finally:
            conn.close()

    # ---- write -------------------------------------------------------------
    def record_snapshot(self, run_id: str, summary: dict[str, Any],
                        mode: str = "unknown", recorded_at: str | None = None,
                        target_version: str | None = None) -> dict[str, Any]:
        """Persist one campaign's completion snapshot, derived from ``summary``.

        Idempotent on ``run_id`` (a re-record overwrites), so replaying a run
        does not double-count. ``target_version`` (the deploy id the run ran
        against) is stored so trends can be sliced per build. Returns the row.
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
            "target_version": target_version,
        }
        cols = ("run_id", "recorded_at", "mode", "attempts", "verdicts",
                "open_findings", "cost_usd", "pass_rate", "coverage_json",
                "target_version")
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

    def record_findings(self, run_id: str, reports: list[Any],
                        recorded_at: str | None = None) -> int:
        """Persist findings into the indexed ``findings`` table (upsert on id).

        ``reports`` are :class:`VulnerabilityReport`-like objects (anything with
        the finding fields) or their ``to_dict()`` output. Returns the count
        written. Severity and attack_category are real columns, so a triage query
        (``findings(severity="critical")``) is index-backed, not a JSON scan.
        """
        ts = recorded_at or _now()
        rows = []
        for r in reports:
            d = r.to_dict() if hasattr(r, "to_dict") else dict(r)
            rows.append((d["finding_id"], run_id, d["severity"], d["attack_category"],
                         d.get("target_surface"), d.get("status"), d.get("lifecycle"),
                         float(d.get("confidence", 0.0) or 0.0),
                         d.get("correlation_id"), ts))
        if not rows:
            return 0
        cols = ("finding_id", "run_id", "severity", "attack_category", "target_surface",
                "status", "lifecycle", "confidence", "correlation_id", "recorded_at")
        ph = ", ".join(self._ph for _ in cols)
        sql = (f"INSERT INTO findings ({', '.join(cols)}) VALUES ({ph}) "
               f"ON CONFLICT (finding_id) DO UPDATE SET "
               + ", ".join(f"{c}=EXCLUDED.{c}" for c in cols if c != "finding_id"))
        conn = self._connect()
        try:
            for row in rows:
                conn.execute(sql, list(row))
            conn.commit()
        finally:
            conn.close()
        return len(rows)

    def findings(self, severity: str | None = None,
                 attack_category: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
        """Query findings, optionally filtered by severity/category (index-backed)."""
        where, params = [], []
        if severity:
            where.append(f"severity = {self._ph}")
            params.append(severity)
        if attack_category:
            where.append(f"attack_category = {self._ph}")
            params.append(attack_category)
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        q = (f"SELECT finding_id, run_id, severity, attack_category, target_surface,"
             f" status, lifecycle, confidence, correlation_id, recorded_at FROM findings"
             f"{clause} ORDER BY recorded_at DESC LIMIT {self._ph}")
        conn = self._connect()
        try:
            cur = conn.execute(q, params + [int(limit)])
            rows = cur.fetchall()
        finally:
            conn.close()
        keys = ("finding_id", "run_id", "severity", "attack_category", "target_surface",
                "status", "lifecycle", "confidence", "correlation_id", "recorded_at")
        return [dict(zip(keys, r)) for r in rows]

    def set_lifecycle(self, finding_id: str, new_state: str) -> str:
        """Transition a persisted finding's lifecycle, validating the move.

        Uses the same open -> in_progress -> resolved (+ reopen) rules as the
        report model, so an illegal transition is rejected here too.
        """
        from ..agents.documentation import _LIFECYCLE_TRANSITIONS
        conn = self._connect()
        try:
            cur = conn.execute(
                f"SELECT lifecycle FROM findings WHERE finding_id = {self._ph}", [finding_id])
            row = cur.fetchone()
            if row is None:
                raise KeyError(f"no finding {finding_id}")
            current = row[0] or "open"
            if new_state != current and new_state not in _LIFECYCLE_TRANSITIONS.get(current, set()):
                raise ValueError(f"illegal lifecycle transition {current!r} -> {new_state!r}")
            conn.execute(
                f"UPDATE findings SET lifecycle = {self._ph} WHERE finding_id = {self._ph}",
                [new_state, finding_id])
            conn.commit()
        finally:
            conn.close()
        return new_state

    def indexes(self) -> list[str]:
        """Names of the indexes present (for verification/tests)."""
        conn = self._connect()
        try:
            if self.backend == "postgres":
                cur = conn.execute("SELECT indexname FROM pg_indexes WHERE tablename IN "
                                   "('findings','campaign_snapshots')")
            else:
                cur = conn.execute("SELECT name FROM sqlite_master WHERE type='index' "
                                   "AND name LIKE 'idx_%'")
            return sorted(r[0] for r in cur.fetchall())
        finally:
            conn.close()

    # ---- read --------------------------------------------------------------
    def snapshots(self, limit: int = 100) -> list[dict[str, Any]]:
        """Recorded snapshots, oldest first (chronological for a trend line),
        capped to the most recent ``limit``."""
        q = (f"SELECT run_id, recorded_at, mode, attempts, verdicts, open_findings,"
             f" cost_usd, pass_rate, coverage_json, target_version FROM campaign_snapshots"
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
                "target_version": r[9],
            })
        return out

    def trends(self, limit: int = 100) -> dict[str, Any]:
        """Dashboard-shaped trend payload: the ordered series plus the backend
        in use (so the UI can say whether history is durable or local)."""
        series = self.snapshots(limit)
        return {"backend": self.backend, "count": len(series), "series": series}
