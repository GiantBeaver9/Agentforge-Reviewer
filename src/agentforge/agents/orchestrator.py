"""Orchestrator Agent.

Responsibility: decide *what to attack next* and *when to stop*. It reads the
observability state — coverage per (category, surface), open high-severity
findings, budget spent — scores each cell, and emits an ``AttackCampaignDirective``
(validated against orchestrator_to_redteam.schema.json). It owns budget/halt and
triggers a regression run when the target's deploy id changes.

Trust level: HIGH, deterministic-first (ARCHITECTURE.md §"Orchestration
strategy"). Scoring and budget math are pure rules over metrics so every
decision is auditable and reproducible — no LLM, no drift.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from ..contracts.models import (AttackCampaignDirective, AttackCategory, Budget,
                                TargetSurface)
from ..observability.store import ObservabilityStore

# Severity -> weight used when scoring "there is an open finding here".
_SEVERITY_WEIGHT = {"critical": 5.0, "high": 3.0, "medium": 2.0, "low": 1.0, "info": 0.5}

# The (category, surface) cells worth probing, with the seed cases that feed
# them and their OWASP tags. Grounded in THREAT_MODEL.md: prompt-only refusals
# (no verifier backstop) are the highest-yield live targets.
CELLS: list[dict[str, Any]] = [
    {"attack_category": "data_exfiltration", "target_surface": "chat",
     "owasp_web": ["A01:2021-Broken-Access-Control"],
     "owasp_llm": ["LLM06:Sensitive-Information-Disclosure"], "base_priority": 5},
    {"attack_category": "identity_role_exploitation", "target_surface": "chat",
     "owasp_web": ["A01:2021-Broken-Access-Control"],
     "owasp_llm": ["LLM06:Sensitive-Information-Disclosure"], "base_priority": 5},
    {"attack_category": "prompt_injection", "target_surface": "chat",
     "owasp_web": [], "owasp_llm": ["LLM01:Prompt-Injection"], "base_priority": 4},
    {"attack_category": "tool_misuse", "target_surface": "agent",
     "owasp_web": ["A04:2021-Insecure-Design"],
     "owasp_llm": ["LLM07:Insecure-Plugin-Design"], "base_priority": 3},
    {"attack_category": "denial_of_service", "target_surface": "agent",
     "owasp_web": [], "owasp_llm": ["LLM04:Model-Denial-of-Service"], "base_priority": 2},
]


@dataclass
class HaltDecision:
    halt: bool
    reason: str | None = None  # budget_exceeded | no_findings_in_window | None


@dataclass
class CampaignState:
    """Mutable run accounting the Orchestrator owns."""
    spent_usd: float = 0.0
    attempts: int = 0
    max_usd: float = 2.0
    max_attempts: int = 50
    no_signal_window: int = 0            # consecutive campaigns with no new success
    halt_after_empty_windows: int = 3
    last_target_version: str | None = None
    dispatched_cells: list[tuple[str, str]] = field(default_factory=list)


class OrchestratorAgent:
    def __init__(self, store: ObservabilityStore, state: CampaignState | None = None):
        self.store = store
        self.state = state or CampaignState()

    # ---- planning ----------------------------------------------------------
    def score_cells(self) -> list[tuple[float, dict[str, Any]]]:
        """Score every cell: severity_weight(open) + coverage_gap.

        coverage_gap is high when a cell has been probed little; open findings
        raise a cell so the Red Team keeps pressure where the target is weak.
        """
        cov = self.store.coverage()
        scored: list[tuple[float, dict[str, Any]]] = []
        for cell in CELLS:
            key = (cell["attack_category"], cell["target_surface"])
            c = cov.get(key)
            attempts = c.attempts if c else 0
            successes = c.successes if c else 0
            # Fewer attempts => bigger gap (saturating). Un-probed cell = full gap.
            coverage_gap = 1.0 / (1.0 + attempts)
            open_weight = _SEVERITY_WEIGHT.get(
                "critical" if successes else "info", 0.5) if successes else 0.0
            score = cell["base_priority"] * coverage_gap + open_weight
            scored.append((score, cell))
        scored.sort(key=lambda t: t[0], reverse=True)
        return scored

    def next_directive(self, max_attempts: int | None = None,
                       max_usd: float | None = None,
                       max_turns: int = 6) -> dict[str, Any]:
        """Emit the highest-scoring cell as an AttackCampaignDirective (wire).

        Produced through the typed :class:`AttackCampaignDirective` model, so the
        directive is schema-validated on the producer side (parity with the Red
        Team and Judge boundaries).
        """
        _, cell = self.score_cells()[0]
        campaign_id = f"camp-{uuid4().hex[:8]}"
        remaining_usd = max(0.0, self.state.max_usd - self.state.spent_usd)
        budget_usd = min(max_usd if max_usd is not None else remaining_usd, remaining_usd)
        directive = AttackCampaignDirective(
            directive_id=f"dir-{uuid4().hex[:8]}",
            campaign_id=campaign_id,
            correlation_id=campaign_id,
            attack_category=AttackCategory(cell["attack_category"]),
            target_surface=TargetSurface(cell["target_surface"]),
            owasp_web=cell["owasp_web"],
            owasp_llm=cell["owasp_llm"],
            rationale="open_high_severity" if self._has_open(cell) else "coverage_gap",
            priority=cell["base_priority"],
            max_turns=max_turns,
            budget=Budget(
                max_attempts=max_attempts or self.state.max_attempts,
                max_usd=round(budget_usd, 4) if budget_usd > 0 else self.state.max_usd,
            ),
        )
        return directive.to_wire()

    def _has_open(self, cell: dict[str, Any]) -> bool:
        cov = self.store.coverage().get((cell["attack_category"], cell["target_surface"]))
        return bool(cov and cov.successes)

    # ---- budget / halt -----------------------------------------------------
    def account(self, attempts: list[dict[str, Any]], new_successes: int) -> None:
        """Update run accounting after a campaign completes."""
        self.state.attempts += len(attempts)
        for a in attempts:
            self.state.spent_usd += float((a.get("target_metadata") or {}).get("cost_usd") or 0.0)
        self.state.no_signal_window = 0 if new_successes > 0 else self.state.no_signal_window + 1

    def halt_check(self) -> HaltDecision:
        if self.state.spent_usd >= self.state.max_usd:
            return HaltDecision(True, "budget_exceeded")
        if self.state.attempts >= self.state.max_attempts:
            return HaltDecision(True, "budget_exceeded")
        if self.state.no_signal_window >= self.state.halt_after_empty_windows:
            return HaltDecision(True, "no_findings_in_window")
        return HaltDecision(False)

    # ---- regression trigger ------------------------------------------------
    def target_changed(self, current_version: str | None) -> bool:
        """True when the deploy id changed since the last observed campaign.

        On a change the Orchestrator should run the regression harness before any
        new exploration (ARCHITECTURE.md §"Orchestration strategy").
        """
        changed = (current_version is not None
                   and self.state.last_target_version is not None
                   and current_version != self.state.last_target_version)
        if current_version is not None:
            self.state.last_target_version = current_version
        return changed


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
