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
from .redact import redact_attempt, redact_verdict
from .contracts.models import AgentError, ContractViolation, validate_message
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
    # Confirmed exploits promoted to deterministic regression cases this run.
    regression_cases_discovered: list[dict[str, Any]] = field(default_factory=list)
    # Count of adaptive (feedback-driven) attempts spawned off partial/successes.
    adaptive_attempts: int = 0


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
    enable_adaptive: bool = True,
    adaptive_variants: int = 10,
    adaptive_turns: bool = True,
) -> CampaignResult:
    """Run the full Orchestrator→RedTeam→Judge→Documentation loop to a halt.

    The Orchestrator picks the cell each round; the Red Team drives the target;
    the Judge decides; Documentation writes reports for confirmed exploits. The
    loop stops on the Orchestrator's halt decision (budget or no-signal window)
    or when ``max_rounds`` is reached.

    The loop is genuinely closed: when the Judge scores an attempt ``partial`` (a
    near miss) or ``success``, the Red Team autonomously refines it into up to
    ``adaptive_variants`` new variants off the *winning* attacker turn and runs
    them in the same round — no human picks what to try next (``enable_adaptive``).
    Confirmed exploits are promoted to deterministic regression cases in-run
    (``result.regression_cases_discovered``) and replayed by the harness, so a
    finding discovered this run — not just a static seed — guards the next build.

    Two gates the review flagged as "built but dead" also run in-loop:

    * ``ground_truth`` — if given, the Judge-drift gate (``check_ground_truth``)
      runs *before* any exploration and its result is recorded. A rubric that no
      longer agrees with the labeled attempts is surfaced, not silently trusted.
    * ``regression_cases`` — replayed by the :class:`RegressionHarness` the moment
      the target's deploy id changes mid-campaign (defaults to ``seeds`` plus the
      exploits confirmed so far this run), so a new build is regression-checked
      before more budget is spent exploring it.
    """
    judge = judge or JudgeAgent()
    documentation = documentation or DocumentationAgent()
    orchestrator = orchestrator or OrchestratorAgent(store, CampaignState(
        max_attempts=max_attempts_per_round * max_rounds))
    redteam = RedTeamAgent(target=target, pinned_pid=pinned_pid, llm=redteam_llm,
                           adaptive_turns=adaptive_turns)
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

        base_attempts = redteam.run_directive(directive, cell_seeds)
        if not base_attempts:
            # The Red Team returned nothing from a non-empty cell — the target was
            # unreachable this round (run_directive drops attempts on
            # TargetUnreachable). Emit the typed error instead of failing silently.
            _emit_error(store, error_code="target_unreachable", producer="redteam",
                        message="target unreachable: no attempts completed this round",
                        correlation_id=directive["campaign_id"], retryable=True)

        # Feedback loop: process each attempt, and when the Judge reports a
        # partial/success, queue an autonomous refinement fan-out off that
        # attempt. ``pending`` is a work queue so refinements are judged too;
        # depth is capped (refinements are not themselves refined) and the total
        # adaptive spend per round is bounded by ``adaptive_variants``.
        pending: list[dict[str, Any]] = list(base_attempts)
        round_attempts: list[dict[str, Any]] = []
        new_successes = 0
        adaptive_spawned = 0
        while pending:
            attempt = pending.pop(0)
            # Consumer-side validation: the Judge validates the AttackAttempt it
            # RECEIVES, independent of the Red Team having validated on produce. A
            # malformed/spoofed attempt is rejected at the boundary, not trusted.
            try:
                validate_message(attempt)
            except ContractViolation as exc:
                _emit_error(store, error_code="invalid_message", producer="judge",
                            message=f"rejected malformed attempt on receipt: {str(exc)[:180]}",
                            correlation_id=attempt.get("correlation_id", "unknown"))
                continue
            # Persist a PHI-redacted copy; adjudication below uses the raw
            # in-memory object, so redaction never changes a verdict.
            store.record(redact_attempt(attempt))
            result.attempts.append(attempt)
            round_attempts.append(attempt)

            verdict = validate_message(judge.judge(attempt).to_wire())
            store.record(redact_verdict(verdict))
            result.verdicts.append(verdict)
            if verdict.get("decision_path") == "llm":
                _record_judge_cost(store, attempt, verdict, judge)
            if getattr(judge, "last_llm_error", False):
                # LLM refinement was attempted but failed; the deterministic
                # rubric produced this verdict. Surface it as a typed error.
                _emit_error(store, error_code="judge_timeout", producer="judge",
                            message="LLM judge refinement failed; used deterministic rubric",
                            correlation_id=verdict.get("correlation_id", ""), retryable=True)
            if verdict.get("escalate_to_human"):
                _record_escalation(store, attempt, verdict)

            if verdict["verdict"] == "success":
                new_successes += 1
                try:
                    report = documentation.document(verdict, attempt)
                    result.reports.append(report)
                    # Promote the confirmed exploit into the regression suite
                    # (consume add_to_regression): a finding found THIS run now
                    # guards the next build, not just the static seeds.
                    if verdict.get("add_to_regression"):
                        result.regression_cases_discovered.append(
                            documentation.regression_case(report))
                except DataQualityError:
                    # A malformed success is dropped, not published.
                    pass

            # Adaptive escalation on a near-miss/win — the closed feedback loop.
            if (enable_adaptive
                    and verdict["verdict"] in ("partial", "success")
                    and attempt.get("attack_technique") != "adaptive"
                    and adaptive_spawned < adaptive_variants):
                syn_seed = _seed_from_attempt(attempt)
                followups = redteam.refine(
                    directive, attempt, verdict, syn_seed,
                    n=adaptive_variants - adaptive_spawned,
                    max_turns=directive.get("max_turns", 6))
                if followups:
                    adaptive_spawned += len(followups)
                    result.adaptive_attempts += len(followups)
                    pending.extend(followups)

        orchestrator.account(round_attempts, new_successes=new_successes)
        version = _observed_version(round_attempts)
        if orchestrator.target_changed(version):
            _emit_error(store, error_code="regression_detected", producer="orchestrator",
                        message=f"target version changed to {version}; running regression",
                        correlation_id=directive["campaign_id"],
                        details={"target_version": version})
            # Actually run the harness now (previously only signaled): replay the
            # regression suite (cross-category) against the new build before any
            # further exploration spends budget on it — INCLUDING the exploits
            # confirmed so far this run, not just the static seeds.
            discovered = [SeedCase.from_regression_case(c)
                          for c in result.regression_cases_discovered]
            result.regression = _run_regression(
                target, judge, pinned_pid, regression_cases + discovered, seeds,
                store, directive["campaign_id"])
            # Drive the vuln lifecycle from the replay: a finding that no longer
            # reproduces on the new build is resolved; one that regressed reopens.
            _apply_regression_lifecycle(result, store)

        decision = orchestrator.halt_check()
        if decision.halt:
            # Surface the halt as a typed, schema-validated error on the wire —
            # budget_exceeded / no_findings_in_window are real failure modes, not
            # just an internal dataclass.
            if decision.reason in ("budget_exceeded", "no_findings_in_window"):
                _emit_error(store, error_code=decision.reason, producer="orchestrator",
                            message=f"campaign halted: {decision.reason}",
                            correlation_id=directive["campaign_id"],
                            details={"attempts": orchestrator.state.attempts,
                                     "spent_usd": round(orchestrator.state.spent_usd, 6)})
            result.halt = decision
            break

    # Data-quality: collapse duplicate findings (same attack sequence on the same
    # cell) before the reports are persisted — enforce the dedupe the review
    # noted was implemented but never called in the running campaign.
    result.reports = dedupe_reports(result.reports)
    # Human-approval gate, enforced (not just labeled): non-critical DRAFT
    # findings auto-publish; every critical stays PENDING_HUMAN and is genuinely
    # un-published until a named human approves it (`publish` CLI / .publish()).
    for r in result.reports:
        if r.status == "draft":
            documentation.publish(r)
    result.halt = result.halt or orchestrator.halt_check()
    return result


def run_via_langgraph(
    *,
    target: TargetClient,
    seeds: list[SeedCase],
    store: ObservabilityStore,
    orchestrator: OrchestratorAgent,
    judge: JudgeAgent | None = None,
    documentation: DocumentationAgent | None = None,
    pinned_pid: int = 1,
    max_rounds: int = 3,
    max_attempts_per_round: int = 6,
) -> CampaignResult:
    """Execute the campaign through the actual LangGraph ``StateGraph`` runtime.

    This is the optional graph runtime: :func:`build_langgraph` wires the same
    four agents over the same typed edges, and we ``invoke`` it once per round,
    accounting/halting between rounds. Raises ``ImportError`` if ``langgraph`` is
    not installed, so the CLI falls back to the canonical plain-Python runner
    (which additionally carries the adaptive/promotion loop). The two share the
    same agents and store, so findings are identical for the same inputs.
    """
    judge = judge or JudgeAgent()
    documentation = documentation or DocumentationAgent()
    graph = build_langgraph(
        target=target, seeds=seeds, store=store, orchestrator=orchestrator,
        judge=judge, documentation=documentation, pinned_pid=pinned_pid,
        max_attempts_per_round=max_attempts_per_round)

    result = CampaignResult()
    for _ in range(max_rounds):
        state = graph.invoke({})
        if state.get("directive"):
            result.directives.append(state["directive"])
        attempts = state.get("attempts", [])
        verdicts = state.get("verdicts", [])
        result.attempts.extend(attempts)
        result.verdicts.extend(verdicts)
        result.reports.extend(state.get("reports", []))
        orchestrator.account(
            attempts, new_successes=sum(1 for v in verdicts if v["verdict"] == "success"))
        decision = orchestrator.halt_check()
        if decision.halt:
            result.halt = decision
            break
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
        _emit_error(store, error_code="invalid_message", producer="judge",
                    message=(f"Judge drift gate FAILED: {len(report['mismatches'])} of "
                             f"{report['total']} labeled cases mislabeled by rubric "
                             f"{report['rubric_version']}"),
                    correlation_id="drift-gate")
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


def _emit_error(store: ObservabilityStore, *, error_code: str, producer: str,
                message: str, correlation_id: str, retryable: bool = False,
                details: dict[str, Any] | None = None) -> dict[str, Any]:
    """Emit a typed, schema-validated AgentError on the wire and record it.

    Goes through :class:`AgentError.to_wire`, so every error the pipeline emits is
    validated against ``contracts/v1/errors.schema.json`` at runtime — not a raw
    dict that merely resembles the schema.
    """
    msg = AgentError(
        error_code=error_code, producer=producer, message=message,
        retryable=retryable, details=details, correlation_id=correlation_id,
    ).to_wire()
    store.record(msg)
    return msg


def _apply_regression_lifecycle(result: CampaignResult, store: ObservabilityStore) -> None:
    """Transition finding lifecycles from the regression replay outcome.

    Matches each replayed case back to its finding (case id == finding_id) and
    moves it: ``held`` (the exploit no longer reproduces) -> ``resolved``;
    ``regressed`` (it came back) -> ``open``. Records the transition as an event
    so the change is auditable.
    """
    if result.regression is None:
        return
    by_id = {r.finding_id: r for r in result.reports}
    for res in result.regression.results:
        rep = by_id.get(res.case_id)
        if rep is None:
            continue
        target_state = None
        if res.status == "held" and rep.lifecycle != "resolved":
            target_state = "resolved"
        elif res.status == "regressed" and rep.lifecycle == "resolved":
            target_state = "open"
        if target_state:
            try:
                rep.set_lifecycle(target_state)
            except ValueError:
                continue
            store.record({
                "schema_version": "1.0.0", "type": "lifecycle", "producer": "documentation",
                "message_id": "lc", "correlation_id": rep.correlation_id,
                "created_at": _now(), "finding_id": rep.finding_id,
                "lifecycle": target_state, "reason": f"regression:{res.status}",
            })


def _seed_from_attempt(attempt: dict[str, Any]) -> SeedCase:
    """Reconstruct a replayable SeedCase from an attempt wire message, so the Red
    Team can refine it without needing a handle on the original seed object."""
    attacker = [t["content"] for t in attempt.get("turns", [])
                if t.get("role") == "attacker"]
    return SeedCase(
        id=attempt.get("attempt_id", "adaptive"),
        attack_category=attempt["attack_category"],
        subcategory=attempt.get("subcategory", ""),
        target_surface=attempt["target_surface"],
        owasp_web=attempt.get("owasp_web", []),
        owasp_llm=attempt.get("owasp_llm", []),
        input_sequence=attacker or [""],
        expected_safe_behavior=attempt["expected_safe_behavior"],
    )


def _record_escalation(store: ObservabilityStore, attempt: dict[str, Any],
                       verdict: dict[str, Any]) -> None:
    """Consume the Judge's escalate_to_human flag as a visible event (a critical
    finding or an uncertain verdict a human should look at)."""
    store.record({
        "schema_version": "1.0.0", "type": "escalation", "producer": "judge",
        "message_id": "escal", "correlation_id": verdict.get("correlation_id", ""),
        "created_at": _now(), "attempt_id": attempt.get("attempt_id"),
        "verdict": verdict.get("verdict"), "severity": verdict.get("severity"),
        "reason": "critical_severity" if verdict.get("severity") == "critical"
                  else "uncertain_verdict",
    })


def _record_judge_cost(store: ObservabilityStore, attempt: dict[str, Any],
                       verdict: dict[str, Any], judge: JudgeAgent) -> None:
    # Prefer REAL spend: if the LLM Judge reported token usage, bill that; only
    # fall back to the transcript-length estimate when usage is absent.
    real = getattr(getattr(judge, "llm", None), "last_cost", None)
    if real is not None:
        cost_usd, basis = round(float(real), 8), "actual_usage"
    else:
        transcript = "\n".join(f"{t['role']}: {t['content']}" for t in attempt["turns"])
        cost_usd, basis = costs.judge_llm_cost(transcript, verdict.get("rationale", "")), "estimate"
    store.record({
        "schema_version": "1.0.0", "type": "cost", "producer": "judge",
        "message_id": "jcost", "correlation_id": verdict.get("correlation_id", ""),
        "created_at": _now(),
        "cost_usd": cost_usd, "basis": basis,
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
        store.record_all(redact_attempt(a) for a in attempts)
        return {**state, "attempts": attempts}

    def adjudicate(state: dict) -> dict:
        verdicts = [judge.judge(a).to_wire() for a in state.get("attempts", [])]
        store.record_all(redact_verdict(v) for v in verdicts)
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
