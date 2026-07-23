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

from . import costs
from .agents.documentation import (DocumentationAgent, DataQualityError,
                                   VulnerabilityReport, dedupe_reports)
from .agents.judge import JudgeAgent
from .agents.orchestrator import CampaignState, HaltDecision, OrchestratorAgent
from .agents.redteam import RedTeamAgent, SeedCase
from .observability.store import ObservabilityStore
from .regression import RegressionHarness, RegressionReport
from .target.client import TargetClient


@dataclass
class CampaignResult:
    directives: list[dict[str, Any]] = field(default_factory=list)
    attempts: list[dict[str, Any]] = field(default_factory=list)
    verdicts: list[dict[str, Any]] = field(default_factory=list)
    reports: list[VulnerabilityReport] = field(default_factory=list)
    halt: HaltDecision | None = None
    # Set when a target-version change fired an in-loop regression replay.
    regression: RegressionReport | None = None
    # Set when the campaign ran the Judge-drift gate against ground truth.
    drift: dict[str, Any] | None = None


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
    regression_cases: list[SeedCase] | None = None,
    ground_truth: list[dict[str, Any]] | None = None,
) -> CampaignResult:
    """Run the full Orchestrator→RedTeam→Judge→Documentation loop to a halt.

    The Orchestrator picks the cell each round; the Red Team drives the target;
    the Judge decides; Documentation writes reports for confirmed exploits. The
    loop stops on the Orchestrator's halt decision (budget or no-signal window)
    or when ``max_rounds`` is reached.

    Two gates the review flagged as "built but dead" now run in-loop:

    * ``ground_truth`` — if given, the Judge-drift gate (``check_ground_truth``)
      runs *before* any exploration and its result is recorded. A rubric that no
      longer agrees with the labeled attempts is surfaced, not silently trusted.
    * ``regression_cases`` — replayed by the :class:`RegressionHarness` the moment
      the target's deploy id changes mid-campaign (defaults to ``seeds``), so a
      new build is regression-checked before more budget is spent exploring it.
    """
    judge = judge or JudgeAgent()
    documentation = documentation or DocumentationAgent()
    orchestrator = orchestrator or OrchestratorAgent(store, CampaignState(
        max_attempts=max_attempts_per_round * max_rounds))
    redteam = RedTeamAgent(target=target, pinned_pid=pinned_pid, llm=redteam_llm)
    by_cell = _seed_index(seeds)
    result = CampaignResult()
    regression_cases = regression_cases if regression_cases is not None else seeds

    # Judge-drift gate: prove the rubric still agrees with ground truth before we
    # trust its verdicts this run (ARCHITECTURE.md §"Judge independence & drift").
    if ground_truth:
        result.drift = _run_drift_gate(judge, ground_truth, store)

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
            # The LLM Judge path costs money (the deterministic rubric is free);
            # record it so the dashboard cost total reflects real Judge spend.
            if verdict.get("decision_path") == "llm":
                _record_judge_cost(store, attempt, verdict)
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
            store.record({
                "schema_version": "1.0.0", "type": "error", "producer": "orchestrator",
                "message_id": "regen", "correlation_id": directive["campaign_id"],
                "created_at": directive["created_at"],
                "error_code": "regression_detected",
                "message": f"target version changed to {version}; running regression",
                "retryable": False,
            })
            # Actually run the harness now (previously only signaled): replay the
            # regression suite (cross-category) against the new build before any
            # further exploration spends budget on it.
            result.regression = _run_regression(
                target, judge, pinned_pid, regression_cases, seeds,
                store, directive["campaign_id"])

        decision = orchestrator.halt_check()
        if decision.halt:
            result.halt = decision
            break

    # Data-quality: collapse duplicate findings (same attack sequence on the same
    # cell) before the reports are persisted — enforce the dedupe the review
    # noted was implemented but never called in the running campaign.
    result.reports = dedupe_reports(result.reports)
    result.halt = result.halt or orchestrator.halt_check()
    return result


def _run_drift_gate(judge: JudgeAgent, ground_truth: list[dict[str, Any]],
                    store: ObservabilityStore) -> dict[str, Any]:
    """Run the Judge over the labeled ground truth and record the agreement.

    A drift-gate failure does not abort the run (the deterministic rubric is
    still usable) but it is recorded and flagged so a reviewer sees that the
    verdicts this run were produced by a rubric that no longer matches the
    labeled cases.
    """
    report = judge.check_ground_truth(ground_truth)
    store.record({
        "schema_version": "1.0.0", "type": "drift_check", "producer": "judge",
        "message_id": "drift", "correlation_id": "drift-gate",
        "created_at": _now(),
        "rubric_version": report["rubric_version"],
        "total": report["total"], "agreements": report["agreements"],
        "passed": report["passed"], "mismatches": report["mismatches"],
    })
    if not report["passed"]:
        store.record({
            "schema_version": "1.0.0", "type": "error", "producer": "judge",
            "message_id": "drift-fail", "correlation_id": "drift-gate",
            "created_at": _now(), "error_code": "invalid_message",
            "message": (f"Judge drift gate FAILED: {len(report['mismatches'])} of "
                        f"{report['total']} labeled cases mislabeled by rubric "
                        f"{report['rubric_version']}"),
            "retryable": False,
        })
    return report


def _run_regression(target: TargetClient, judge: JudgeAgent, pinned_pid: int,
                    regression_cases: list[SeedCase], corpus: list[SeedCase],
                    store: ObservabilityStore, correlation_id: str) -> RegressionReport:
    """Replay the regression suite against the (changed) target and record it."""
    harness = RegressionHarness(target=target, judge=judge, pinned_pid=pinned_pid)
    report = harness.replay_with_siblings(regression_cases, corpus, cross_category=True)
    summary = report.summary()
    store.record({
        "schema_version": "1.0.0", "type": "regression_report", "producer": "orchestrator",
        "message_id": "regrun", "correlation_id": correlation_id,
        "created_at": _now(),
        "total": summary["total"], "passed_count": summary["passed"],
        "regressed": summary["regressed"], "unreachable": summary["unreachable"],
        "regressed_cases": summary["regressed_cases"], "invariant_held": report.passed,
    })
    return report


def _record_judge_cost(store: ObservabilityStore, attempt: dict[str, Any],
                       verdict: dict[str, Any]) -> None:
    transcript = "\n".join(f"{t['role']}: {t['content']}" for t in attempt["turns"])
    store.record({
        "schema_version": "1.0.0", "type": "cost", "producer": "judge",
        "message_id": "jcost", "correlation_id": verdict.get("correlation_id", ""),
        "created_at": _now(),
        "cost_usd": costs.judge_llm_cost(transcript, verdict.get("rationale", "")),
        "component": "judge_llm", "attempt_id": attempt["attempt_id"],
    })


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


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
