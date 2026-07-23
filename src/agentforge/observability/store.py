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
            att = attempts.get(v.get("attempt_id"))
            if att is None:
                continue  # verdict for an attempt this log did not capture
            c = cell(att["attack_category"], att["target_surface"])
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

    def coverage_by_version(self) -> dict[str, dict[str, Any]]:
        """Pass/fail rollup keyed by the target's deploy id (``target_version``).

        Answers the case-study ask "break results down by system version": each
        attempt records the version it ran against; joining verdicts to attempts
        gives per-build defended-rate, so a regression across a deploy is visible
        as a pass_rate drop for the new version. ``unknown`` collects attempts
        whose target did not report a version (e.g. the offline mock).
        """
        attempts = {a["attempt_id"]: a for a in self._by_type(ATTEMPT)}

        def _blank() -> dict[str, Any]:
            return {"attempts": 0, "verdicts": 0, "successes": 0,
                    "failures": 0, "partials": 0, "uncertains": 0}

        out: dict[str, dict[str, Any]] = {}

        def _ver(a: dict[str, Any]) -> str:
            return (a.get("target_metadata") or {}).get("target_version") or "unknown"

        for a in attempts.values():
            out.setdefault(_ver(a), _blank())["attempts"] += 1
        for v in self._by_type(VERDICT):
            a = attempts.get(v.get("attempt_id"))
            if a is None:
                continue
            row = out.setdefault(_ver(a), _blank())
            row["verdicts"] += 1
            outcome = v.get("verdict")
            key = {"success": "successes", "failure": "failures",
                   "partial": "partials"}.get(outcome, "uncertains")
            row[key] += 1
        for row in out.values():
            row["pass_rate"] = (row["failures"] / row["verdicts"]
                                if row["verdicts"] else None)
        return out

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

    def cost_breakdown(self) -> dict[str, Any]:
        """Cost split by component, plus the per-attempt rate (the cost slope).

        Answers "cost per agent/component", not one lumped number: the target/Red
        Team per-attempt spend comes from each attempt's ``cost_usd``; the Judge's
        LLM spend from the ``cost`` events it emits (``component=judge_llm``). The
        per-attempt rate is the marginal cost of one more attempt — the slope a
        capacity plan multiplies out.
        """
        by_component: dict[str, float] = {}
        # Target + Red Team generation cost is folded into each attempt estimate.
        target = sum(float((a.get("target_metadata") or {}).get("cost_usd") or 0.0)
                     for a in self._by_type(ATTEMPT))
        if target:
            by_component["target_and_redteam"] = round(target, 6)
        # Standalone cost events (e.g. the LLM Judge) carry their own component.
        for e in self.events():
            c = e.get("cost_usd")
            if c and e.get("type") == "cost":
                comp = e.get("component", "other")
                by_component[comp] = round(by_component.get(comp, 0.0) + float(c), 6)
        total = round(sum(by_component.values()), 6)
        attempts = self.attempt_count()
        return {
            "total_usd": total,
            "by_component": by_component,
            "attempts": attempts,
            "per_attempt_usd": round(total / attempts, 6) if attempts else 0.0,
        }

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

    def agent_responses(self, clip: int = 400) -> dict[str, Any]:
        """Raw Red Team attempts and Judge verdicts, each tagged with its
        provenance (deterministic vs LLM), for the dashboard's agent-response
        view. Turn/rationale text is clipped so the payload stays light.

        ``attack_source``/``decision_path`` default to ``deterministic`` for
        older logs written before those fields existed.
        """
        from ..redact import redact_phi  # local import to avoid a package cycle

        def _clip(s: str) -> str:
            s = redact_phi(s or "")  # defense-in-depth: scrub PHI even from raw logs
            return s if len(s) <= clip else s[:clip] + "…"

        attempts = []
        for a in self._by_type(ATTEMPT):
            turns = a.get("turns", [])
            attacker = next((t.get("content", "") for t in turns
                             if t.get("role") == "attacker"), "")
            targets = [t.get("content", "") for t in turns if t.get("role") == "target"]
            attempts.append({
                "attempt_id": a.get("attempt_id"),
                "attack_category": a.get("attack_category"),
                "target_surface": a.get("target_surface"),
                "attack_technique": a.get("attack_technique"),
                "attack_source": a.get("attack_source", "deterministic"),
                "attacker": _clip(attacker),
                "target": _clip(targets[-1] if targets else ""),
            })

        verdicts = []
        for v in self._by_type(VERDICT):
            verdicts.append({
                "verdict_id": v.get("verdict_id"),
                "attempt_id": v.get("attempt_id"),
                "verdict": v.get("verdict"),
                "severity": v.get("severity"),
                "confidence": v.get("confidence"),
                "judge_model": v.get("judge_model"),
                "decision_path": v.get("decision_path", "deterministic"),
                "rationale": _clip(v.get("rationale", "")),
            })
        return {"attempts": attempts, "verdicts": verdicts}

    def summary(self) -> dict[str, Any]:
        """One dict the dashboard/CLI can render and the Orchestrator can score."""
        cov = self.coverage()
        return {
            "attempts": self.attempt_count(),
            "verdicts": sum(c.verdicts for c in cov.values()),
            "open_findings": len(self.open_findings()),
            "cost_usd": self.cost_usd(),
            "cost_breakdown": self.cost_breakdown(),
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
            "by_version": self.coverage_by_version(),
        }
