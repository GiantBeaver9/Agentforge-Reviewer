"""Regression harness — deterministic replay of confirmed exploits.

A confirmed exploit becomes a deterministic case (``regression=true``). On every
target version the harness replays the case and classifies the outcome **by the
invariant**, not by a string match on the old leak. Crucially it distinguishes
three states, because "not a success" is *not* the same as "fixed":

* ``held``       — the Judge ruled the target *affirmatively defended*
  (``verdict == "failure"``): the ``expected_safe_behavior`` invariant holds.
  This is the only state that counts as a pass.
* ``regressed``  — the exploit reproduced (``verdict == "success"``).
* ``inconclusive`` — the replay produced an ``uncertain``/``partial`` verdict:
  the build *drifted into an unclassifiable answer*. This does **not** count as
  a pass — it is exactly the "behavior merely changed, nothing was actually
  fixed" failure mode, so it is surfaced (and fails ``--strict``) instead of
  being waved through (ARCHITECTURE.md §"Regression harness").

It also re-runs sibling cases in the same category (and, with
``cross_category``, a bounded sample of every other category), so a fix that
regresses a neighbour is caught rather than silently traded away.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .agents.judge import JudgeAgent
from .agents.redteam import RedTeamAgent, SeedCase
from .target.client import TargetClient, TargetUnreachable

HELD = "held"
REGRESSED = "regressed"
INCONCLUSIVE = "inconclusive"
UNREACHABLE = "unreachable"


@dataclass
class RegressionResult:
    case_id: str
    attack_category: str
    status: str                  # held | regressed | inconclusive | unreachable
    verdict: str                 # judge verdict on replay
    detail: str

    @property
    def passed(self) -> bool:
        """Pass == the invariant *affirmatively* held. An inconclusive replay is
        not a pass — that is the whole point of the three-way classification."""
        return self.status == HELD

    @property
    def unreachable(self) -> bool:
        return self.status == UNREACHABLE


@dataclass
class RegressionReport:
    results: list[RegressionResult] = field(default_factory=list)

    @property
    def regressions(self) -> list[RegressionResult]:
        """Cases that used to be defended (they're in the suite because they were
        confirmed-then-fixed) but broke again on replay."""
        return [r for r in self.results if r.status == REGRESSED]

    @property
    def inconclusive(self) -> list[RegressionResult]:
        """Cases whose replay could not be classified as held or regressed — a
        drift into an unclassifiable answer, treated as NOT fixed."""
        return [r for r in self.results if r.status == INCONCLUSIVE]

    @property
    def passed(self) -> bool:
        """Clean only when every reachable case affirmatively held — no
        regression *and* no inconclusive drift."""
        reachable = [r for r in self.results if r.status != UNREACHABLE]
        return all(r.status == HELD for r in reachable)

    def summary(self) -> dict[str, Any]:
        return {
            "total": len(self.results),
            "passed": sum(1 for r in self.results if r.status == HELD),
            "held": sum(1 for r in self.results if r.status == HELD),
            "regressed": len(self.regressions),
            "inconclusive": len(self.inconclusive),
            "unreachable": sum(1 for r in self.results if r.status == UNREACHABLE),
            "clean": self.passed,
            "regressed_cases": [r.case_id for r in self.regressions],
            "inconclusive_cases": [r.case_id for r in self.inconclusive],
        }


class RegressionHarness:
    def __init__(self, target: TargetClient, judge: JudgeAgent | None = None,
                 pinned_pid: int = 1):
        self.redteam = RedTeamAgent(target=target, pinned_pid=pinned_pid)
        self.judge = judge or JudgeAgent()
        self.pinned_pid = pinned_pid

    def replay(self, cases: list[SeedCase], directive_id: str = "regression") -> RegressionReport:
        """Replay each case once (seed sequence only — no mutation search) and
        judge the outcome. Pass == the invariant held (target defended)."""
        report = RegressionReport()
        directive = {
            "directive_id": directive_id,
            "campaign_id": directive_id,
            "correlation_id": directive_id,
            "budget": {"max_attempts": len(cases) + 1, "max_usd": 1.0},
            "max_turns": 6,
        }
        for case in cases:
            try:
                attempt = self.redteam._run_one(
                    directive, case, case.input_sequence,
                    technique="regression", mutation_of=case.id, max_turns=6)
            except TargetUnreachable as exc:
                report.results.append(RegressionResult(
                    case.id, case.attack_category, status=UNREACHABLE,
                    verdict="uncertain", detail=str(exc)))
                continue
            if attempt is None:
                report.results.append(RegressionResult(
                    case.id, case.attack_category, status=UNREACHABLE,
                    verdict="uncertain", detail="target unreachable"))
                continue

            verdict = self.judge.judge(attempt)
            # Three-way, by the invariant: an affirmative defense HELDs; a
            # reproduced exploit REGRESSED; anything else (uncertain/partial) is
            # INCONCLUSIVE and must NOT be mistaken for a fix.
            if verdict.verdict == "failure":
                status = HELD
            elif verdict.verdict == "success":
                status = REGRESSED
            else:
                status = INCONCLUSIVE
            report.results.append(RegressionResult(
                case_id=case.id,
                attack_category=case.attack_category,
                status=status,
                verdict=verdict.verdict,
                detail=verdict.rationale,
            ))
        return report

    def replay_with_siblings(self, cases: list[SeedCase],
                             corpus: list[SeedCase],
                             cross_category: bool = False,
                             cross_category_per_cat: int = 2) -> RegressionReport:
        """Replay the regression ``cases`` plus neighbours from ``corpus``.

        Same-category siblings are always included: a fix that regresses a
        neighbour in the same category is caught. With ``cross_category=True`` a
        bounded sample of every *other* category is also replayed, so a fix that
        trades away a defense in a **different** category (e.g. hardening the
        exfiltration path but re-opening a prompt-injection one) is caught too —
        not just same-category siblings.
        """
        target_categories = {c.attack_category for c in cases}
        by_id = {c.id: c for c in cases}
        siblings = [c for c in corpus
                    if c.attack_category in target_categories and c.id not in by_id]

        extra: list[SeedCase] = []
        if cross_category:
            seen_ids = by_id.keys() | {s.id for s in siblings}
            per_cat: dict[str, int] = {}
            for c in corpus:
                if c.attack_category in target_categories or c.id in seen_ids:
                    continue
                if per_cat.get(c.attack_category, 0) >= cross_category_per_cat:
                    continue
                per_cat[c.attack_category] = per_cat.get(c.attack_category, 0) + 1
                extra.append(c)
        return self.replay(cases + siblings + extra)
