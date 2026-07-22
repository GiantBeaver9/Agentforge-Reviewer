"""Observability store — the deterministic substrate under the agents.

Every inter-agent message (directive, attempt, verdict, error) is appended to a
single JSONL run log keyed by ``correlation_id``. The store is append-only so a
run is auditable and resumable; nothing is ever mutated in place. It answers the
questions ARCHITECTURE.md §Observability requires — coverage per category, pass/
fail rate, open findings, cost, and the ordered timeline — and it is *also* the
Orchestrator's input, so the same numbers drive both the human dashboard and the
next campaign decision.

The store is deterministic on purpose (ARCHITECTURE.md §"AI vs deterministic"):
coverage math and cost accounting must be reproducible and must not drift, so no
LLM is involved here.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

# Message ``type`` values as they appear on the wire (contracts/v1/*).
DIRECTIVE = "orchestrator_to_redteam"
ATTEMPT = "redteam_to_judge"
VERDICT = "judge_to_documentation"
ERROR = "error"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class CategoryCoverage:
    """Per (attack_category, target_surface) rollup."""
    attack_category: str
    target_surface: str
    attempts: int = 0
    verdicts: int = 0
    successes: int = 0
    failures: int = 0
    partials: int = 0
    uncertains: int = 0

    @property
    def pass_rate(self) -> float | None:
        """Fraction of *judged* attempts the target defended (failure = defended).

        ``None`` when nothing has been judged yet — distinct from 0.0 (judged and
        all broke), which a bare ``0`` would hide.
        """
        if self.verdicts == 0:
            return None
        return self.failures / self.verdicts


class ObservabilityStore:
    """Append-only event log with deterministic query rollups.

    Not thread-safe by design: a single campaign appends serially. Concurrent
    campaigns should use distinct log paths (one per ``campaign_id``) and be
    merged at read time via :meth:`load_many`.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # ---- write -------------------------------------------------------------
    def record(self, message: dict[str, Any]) -> None:
        """Append one wire message. A local receive timestamp is added under
        ``_observed_at`` without mutating the original message's fields."""
        event = dict(message)
        event.setdefault("_observed_at", _now())
        with self.path.open("a") as fh:
            fh.write(json.dumps(event) + "\n")

    def record_all(self, messages: Iterable[dict[str, Any]]) -> None:
        for m in messages:
            self.record(m)

    # ---- read --------------------------------------------------------------
    def events(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        out: list[dict[str, Any]] = []
        for line in self.path.read_text().splitlines():
            line = line.strip()
            if line:
                out.append(json.loads(line))
        return out

    @staticmethod
    def load_many(paths: Iterable[str | Path]) -> list[dict[str, Any]]:
        merged: list[dict[str, Any]] = []
        for p in paths:
            store = ObservabilityStore(p)
            merged.extend(store.events())
        merged.sort(key=lambda e: e.get("_observed_at", ""))
        return merged

    def _by_type(self, type_: str) -> list[dict[str, Any]]:
        return [e for e in self.events() if e.get("type") == type_]

    # ---- rollups (Orchestrator input + dashboard) --------------------------
    def coverage(self) -> dict[tuple[str, str], CategoryCoverage]:
        """Coverage per (category, surface), joining verdicts to their attempts.

        Attempts are indexed by ``attempt_id`` so a verdict (which references
        only the attempt) is attributed to the right category/surface cell.
        """
        attempts = {a["attempt_id"]: a for a in self._by_type(ATTEMPT)}
        cells: dict[tuple[str, str], CategoryCoverage] = {}

        def cell(cat: str, surf: str) -> CategoryCoverage:
            key = (cat, surf)
            if key not in cells:
                cells[key] = CategoryCoverage(cat, surf)
            return cells[key]

        for a in attempts.values():
            cell(a["attack_category"], a["target_surface"]).attempts += 1

        for v in self._by_type(VERDICT):
            a = attempts.get(v.get("attempt_id"))
            if a is None:
                continue  # verdict for an attempt this log did not capture
            c = cell(a["attack_category"], a["target_surface"])
            c.verdicts += 1
            outcome = v.get("verdict")
            if outcome == "success":
                c.successes += 1
            elif outcome == "failure":
                c.failures += 1
            elif outcome == "partial":
                c.partials += 1
            else:
                c.uncertains += 1
        return cells

    def open_findings(self) -> list[dict[str, Any]]:
        """Confirmed exploits: verdicts with ``success`` (target broke), newest
        first, ordered by severity then confidence."""
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        wins = [v for v in self._by_type(VERDICT) if v.get("verdict") == "success"]
        wins.sort(key=lambda v: (order.get(v.get("severity", "info"), 9),
                                 -float(v.get("confidence", 0.0))))
        return wins

    def cost_usd(self) -> float:
        """Total observed target/LLM cost across all attempts and verdicts."""
        total = 0.0
        for a in self._by_type(ATTEMPT):
            total += float((a.get("target_metadata") or {}).get("cost_usd") or 0.0)
        for e in self.events():
            total += float(e.get("cost_usd") or 0.0)
        return round(total, 6)

    def attempt_count(self) -> int:
        return len(self._by_type(ATTEMPT))

    def timeline(self) -> list[dict[str, Any]]:
        """Ordered (producer, type, correlation_id, ts) of what each agent did."""
        rows = []
        for e in self.events():
            rows.append({
                "observed_at": e.get("_observed_at"),
                "producer": e.get("producer"),
                "type": e.get("type"),
                "correlation_id": e.get("correlation_id"),
            })
        rows.sort(key=lambda r: r.get("observed_at") or "")
        return rows

    def summary(self) -> dict[str, Any]:
        """One dict the dashboard/CLI can render and the Orchestrator can score."""
        cov = self.coverage()
        return {
            "attempts": self.attempt_count(),
            "verdicts": sum(c.verdicts for c in cov.values()),
            "open_findings": len(self.open_findings()),
            "cost_usd": self.cost_usd(),
            "coverage": [
                {
                    "attack_category": c.attack_category,
                    "target_surface": c.target_surface,
                    "attempts": c.attempts,
                    "verdicts": c.verdicts,
                    "successes": c.successes,
                    "failures": c.failures,
                    "partials": c.partials,
                    "uncertains": c.uncertains,
                    "pass_rate": c.pass_rate,
                }
                for c in sorted(cov.values(),
                                key=lambda x: (x.attack_category, x.target_surface))
            ],
        }
