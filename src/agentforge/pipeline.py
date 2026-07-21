"""Campaign pipeline — wires the four agents over the typed contract messages.

    Orchestrator --AttackCampaignDirective--> Red Team
    Red Team     --AttackAttempt----------->  Judge
    Judge        --Verdict (success)------->  Documentation
    Judge        --Verdict (all)----------->  Observability
    Orchestrator --budget/halt------------->  Observability

Every message shares a ``correlation_id`` and is appended to the observability
store, so a finding is traceable end-to-end (ARCHITECTURE.md §"How work flows").

The loop below *is* the graph's execution. If ``langgraph`` is installed,
:func:`build_langgraph` constructs an equivalent ``StateGraph`` whose nodes call
the same agents over the same typed edges; the plain-Python runner is the
offline/testable form and carries no heavy dependency.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .agents.documentation import DocumentationAgent, DataQualityError, VulnerabilityReport
from .agents.judge import JudgeAgent
from .agents.orchestrator import CampaignState, HaltDecision, OrchestratorAgent
from .agents.redteam import RedTeamAgent, SeedCase
from .observability.store import ObservabilityStore
from .target.client import TargetClient


@dataclass
class CampaignResult:
    directives: list[dict[str, Any]] = field(default_factory=list)
    attempts: list[dict[str, Any]] = field(default_factory=list)
    verdicts: list[dict[str, Any]] = field(default_factory=list)
    reports: list[VulnerabilityReport] = field(default_factory=list)
    halt: HaltDecision | None = None


def _seed_index(seeds: list[SeedCase]) -> dict[tuple[str, str], list[SeedCase]]:
    idx: dict[tuple[str, str], list[SeedCase]] = {}
    for s in seeds:
        idx.setdefault((s.attack_category, s.target_surface), []).append(s)
    return idx


def run_campaign(
    *,
    target: TargetClient,
    seeds: list[SeedCase],
    store: ObservabilityStore,
    judge: JudgeAgent | None = None,
    documentation: DocumentationAgent | None = None,
    orchestrator: OrchestratorAgent | None = None,
    pinned_pid: int = 1,
    max_rounds: int = 3,
    max_attempts_per_round: int = 6,
    redteam_llm=None,
) -> CampaignResult:
    """Run the full Orchestrator→RedTeam→Judge→Documentation loop to a halt.

    The Orchestrator picks the cell each round; the Red Team drives the target;
    the Judge decides; Documentation writes reports for confirmed exploits. The
    loop stops on the Orchestrator's halt decision (budget or no-signal window)
    or when ``max_rounds`` is reached.
    """
    judge = judge or JudgeAgent()
    documentation = documentation or DocumentationAgent()
    orchestrator = orchestrator or OrchestratorAgent(store, CampaignState(
        max_attempts=max_attempts_per_round * max_rounds))
    redteam = RedTeamAgent(target=target, pinned_pid=pinned_pid, llm=redteam_llm)
    by_cell = _seed_index(seeds)
    result = CampaignResult()

    for _ in range(max_rounds):
        directive = orchestrator.next_directive(max_attempts=max_attempts_per_round)
        store.record(directive)
        result.directives.append(directive)

        cell_seeds = by_cell.get(
            (directive["attack_category"], directive["target_surface"]), [])
        if not cell_seeds:
            # No seeds for the chosen cell — record the gap and let the
            # Orchestrator move on next round (coverage_gap stays high).
            orchestrator.account([], new_successes=0)
            if orchestrator.halt_check().halt:
                break
            continue

        attempts = redteam.run_directive(directive, cell_seeds)
        store.record_all(attempts)
        result.attempts.extend(attempts)

        new_successes = 0
        for attempt in attempts:
            verdict = judge.judge(attempt).to_wire()
            store.record(verdict)
            result.verdicts.append(verdict)
            if verdict["verdict"] == "success":
                new_successes += 1
                try:
                    report = documentation.document(verdict, attempt)
                    result.reports.append(report)
                except DataQualityError:
                    # A malformed success is dropped, not published — the
                    # data-quality gate is doing its job.
                    continue

        orchestrator.account(attempts, new_successes=new_successes)
        version = _observed_version(attempts)
        if orchestrator.target_changed(version):
            # Signal only — the regression harness is triggered by the caller.
            store.record({
                "schema_version": "1.0.0", "type": "error", "producer": "orchestrator",
                "message_id": "regen", "correlation_id": directive["campaign_id"],
                "created_at": directive["created_at"],
                "error_code": "regression_detected",
                "message": "target version changed; regression run required",
                "retryable": False,
            })

        decision = orchestrator.halt_check()
        if decision.halt:
            result.halt = decision
            break

    result.halt = result.halt or orchestrator.halt_check()
    return result


def _observed_version(attempts: list[dict[str, Any]]) -> str | None:
    for a in reversed(attempts):
        v = (a.get("target_metadata") or {}).get("target_version")
        if v:
            return str(v)
    return None


# --------------------------------------------------------------------------- #
#  Optional LangGraph construction (same agents, same typed edges)
# --------------------------------------------------------------------------- #
def build_langgraph(*, target, seeds, store, **kw):  # pragma: no cover - optional dep
    """Construct a LangGraph ``StateGraph`` mirroring :func:`run_campaign`.

    Importing langgraph is optional; the plain-Python runner above is the
    canonical, dependency-free execution. Raises ImportError if langgraph is
    absent so callers can fall back to ``run_campaign``.
    """
    from langgraph.graph import END, START, StateGraph  # noqa: F401

    judge = kw.get("judge") or JudgeAgent()
    documentation = kw.get("documentation") or DocumentationAgent()
    orchestrator = kw.get("orchestrator") or OrchestratorAgent(store, CampaignState())
    redteam = RedTeamAgent(target=target, pinned_pid=kw.get("pinned_pid", 1))
    by_cell = _seed_index(seeds)

    def orchestrate(state: dict) -> dict:
        directive = orchestrator.next_directive(max_attempts=kw.get("max_attempts_per_round", 6))
        store.record(directive)
        return {**state, "directive": directive}

    def red_team(state: dict) -> dict:
        d = state["directive"]
        cell_seeds = by_cell.get((d["attack_category"], d["target_surface"]), [])
        attempts = redteam.run_directive(d, cell_seeds)
        store.record_all(attempts)
        return {**state, "attempts": attempts}

    def adjudicate(state: dict) -> dict:
        verdicts = [judge.judge(a).to_wire() for a in state.get("attempts", [])]
        store.record_all(verdicts)
        return {**state, "verdicts": verdicts}

    def document(state: dict) -> dict:
        by_id = {a["attempt_id"]: a for a in state.get("attempts", [])}
        reports = []
        for v in state.get("verdicts", []):
            if v["verdict"] == "success":
                try:
                    reports.append(documentation.document(v, by_id[v["attempt_id"]]))
                except DataQualityError:
                    pass
        return {**state, "reports": reports}

    g = StateGraph(dict)
    g.add_node("orchestrate", orchestrate)
    g.add_node("red_team", red_team)
    g.add_node("adjudicate", adjudicate)
    g.add_node("document", document)
    g.add_edge(START, "orchestrate")
    g.add_edge("orchestrate", "red_team")
    g.add_edge("red_team", "adjudicate")
    g.add_edge("adjudicate", "document")
    g.add_edge("document", END)
    return g.compile()
