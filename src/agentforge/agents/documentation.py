"""Documentation Agent.

Responsibility: turn a *confirmed* exploit (a Judge ``Verdict`` with
``verdict=success``, plus the originating ``AttackAttempt``) into a structured,
reproducible vulnerability report and a deterministic regression case. It
enforces data-quality constraints before anything is persisted, and it puts a
**human approval gate** in front of any critical-severity report
(ARCHITECTURE.md §"Human approval gates").

Trust level: MEDIUM. It never decides success (that is the Judge) and never
patches the target (reports only). Report prose may be LLM-authored, but the
required fields and the regression case are deterministic so a report can never
ship missing its reproduction steps.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Report status lifecycle.
DRAFT = "draft"
PENDING_HUMAN = "pending_human_approval"
PUBLISHED = "published"

_REQUIRED_REPORT_FIELDS = (
    "finding_id", "title", "severity", "exploitability", "attack_category",
    "target_surface", "owasp_web", "owasp_llm", "reproduction",
    "expected_safe_behavior", "observed_behavior", "impact", "recommendation",
    "status",
    # A confirmed finding must carry its proof citation. The deterministic Judge
    # always emits >=1 evidence item on a success verdict (judge.py `_score`), so
    # requiring it costs the deterministic path nothing and closes the door on an
    # evidence-less report shipping from an LLM judge that skipped it.
    "evidence",
)

_EXPLOITABILITY_LEVELS = ("easy", "moderate", "hard")


def _derive_exploitability(attempt: dict[str, Any]) -> str:
    """Rate how hard the confirmed exploit is to reproduce, from attempt *shape*.

    Deterministic and evidence-free on purpose (ARCHITECTURE.md §"AI vs
    deterministic"): the rubric asks for severity **and** exploitability, and
    exploitability is a property of the reproduction, not a judgement call — so
    we read it off the attempt rather than ask a model.

    - ``easy``: one direct attacker turn that reproduces the leak — a single
      request replays it.
    - ``moderate``: a discovered variant (a mutation of a seed) or a two-turn
      exchange — some crafting or a setup turn is required.
    - ``hard``: a chain of three or more attacker turns — the exploit needs
      multi-step state to reproduce.
    """
    attacker_turns = [t for t in attempt.get("turns", []) if t.get("role") == "attacker"]
    n = len(attacker_turns)
    is_variant = bool(attempt.get("mutation_of")) or attempt.get("attack_technique") == "mutation"
    if n >= 3:
        return "hard"
    if n == 2 or is_variant:
        return "moderate"
    return "easy"


class DataQualityError(ValueError):
    """A report failed a data-quality invariant and must not be persisted."""


@dataclass
class VulnerabilityReport:
    finding_id: str
    title: str
    severity: str
    exploitability: str               # easy | moderate | hard (derived from shape)
    attack_category: str
    target_surface: str
    owasp_web: list[str]
    owasp_llm: list[str]
    reproduction: list[str]           # ordered attacker turns to replay
    expected_safe_behavior: str
    observed_behavior: str
    impact: str
    recommendation: str
    status: str
    verdict_id: str
    attempt_id: str
    confidence: float
    rubric_version: str
    correlation_id: str
    evidence: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            "exploitability": self.exploitability,
            "attack_category": self.attack_category,
            "target_surface": self.target_surface,
            "owasp_web": self.owasp_web,
            "owasp_llm": self.owasp_llm,
            "reproduction": self.reproduction,
            "expected_safe_behavior": self.expected_safe_behavior,
            "observed_behavior": self.observed_behavior,
            "impact": self.impact,
            "recommendation": self.recommendation,
            "status": self.status,
            "verdict_id": self.verdict_id,
            "attempt_id": self.attempt_id,
            "confidence": self.confidence,
            "rubric_version": self.rubric_version,
            "correlation_id": self.correlation_id,
            "evidence": self.evidence,
        }


_IMPACT = {
    "data_exfiltration": "PHI for a patient outside the pinned scope can be disclosed to the operator, breaching access control and patient confidentiality (HIPAA minimum-necessary).",
    "identity_role_exploitation": "A user can act outside their granted role/scope, defeating authorization on clinical data.",
    "prompt_injection": "Attacker-controlled text overrides the co-pilot's instructions, letting it be repurposed away from its clinical guardrails.",
    "tool_misuse": "The agent can be steered to invoke tools with attacker-chosen arguments, beyond the intended read-only clinical scope.",
    "state_corruption": "Session/synthesis state can be corrupted, causing the co-pilot to present wrong or cross-contaminated clinical data.",
    "denial_of_service": "A single user can exhaust the co-pilot's budget/latency headroom, denying service to clinicians.",
}

_RECOMMENDATION = {
    "data_exfiltration": "Enforce the pinned-patient scope server-side on every retrieval (not via prompt alone); reject any answer referencing a non-pinned pid before it reaches the user.",
    "identity_role_exploitation": "Move the authorization check behind a typed principal/scope at the data layer; never rely on the model to honor role boundaries.",
    "prompt_injection": "Add an output-side invariant verifier that fails closed when the answer deviates from the pinned-patient clinical task, independent of the prompt.",
    "tool_misuse": "Constrain tool arguments to a validated allowlist and gate tool calls on the same ACL as the chart; log and rate-limit per user.",
    "state_corruption": "Make session/synthesis writes transactional and validate invariants on read; freeze on inconsistency rather than serving degraded state.",
    "denial_of_service": "Add per-user turn/token rate limits in addition to the global budget breaker; shed load before the LLM call.",
}


class DocumentationAgent:
    """Confirmed exploit -> report + regression case, with data-quality gating."""

    def __init__(self, llm=None):
        self.llm = llm  # optional: object with .narrate(attempt, verdict) -> dict

    # ---- public API --------------------------------------------------------
    def document(self, verdict: dict[str, Any], attempt: dict[str, Any]) -> VulnerabilityReport:
        """Build a report from a success Verdict + its AttackAttempt.

        Raises ``DataQualityError`` if the inputs don't support a reproducible
        report (wrong verdict, mismatched ids, no attacker turns).
        """
        if verdict.get("verdict") != "success":
            raise DataQualityError(
                "documentation only runs on verdict=success; got "
                f"{verdict.get('verdict')!r}")
        if verdict.get("attempt_id") != attempt.get("attempt_id"):
            raise DataQualityError("verdict.attempt_id does not match attempt.attempt_id")

        attacker_turns = [t["content"] for t in attempt["turns"] if t["role"] == "attacker"]
        if not attacker_turns:
            raise DataQualityError("attempt has no attacker turns to reproduce")

        target_turns = [t["content"] for t in attempt["turns"] if t["role"] == "target"]
        observed = target_turns[-1] if target_turns else "(no target response captured)"

        category = attempt["attack_category"]
        severity = verdict["severity"]
        status = PENDING_HUMAN if severity == "critical" else DRAFT

        title = self._title(category, attempt["target_surface"], severity)
        narrative_impact = _IMPACT.get(category, "Confirmed deviation from the intended safe behavior.")
        recommendation = _RECOMMENDATION.get(category, "Add a server-side invariant check independent of the model prompt.")

        # Optional LLM narrative refinement (never removes required fields).
        if self.llm is not None:
            refined = self._narrate(attempt, verdict)
            if refined:
                title = refined.get("title", title)
                narrative_impact = refined.get("impact", narrative_impact)
                recommendation = refined.get("recommendation", recommendation)

        report = VulnerabilityReport(
            finding_id=f"AF-FIND-{attempt['attempt_id'].removeprefix('att-')}",
            title=title,
            severity=severity,
            exploitability=_derive_exploitability(attempt),
            attack_category=category,
            target_surface=attempt["target_surface"],
            owasp_web=attempt.get("owasp_web", []),
            owasp_llm=attempt.get("owasp_llm", []),
            reproduction=attacker_turns,
            expected_safe_behavior=attempt["expected_safe_behavior"],
            observed_behavior=observed,
            impact=narrative_impact,
            recommendation=recommendation,
            status=status,
            verdict_id=verdict["verdict_id"],
            attempt_id=attempt["attempt_id"],
            confidence=float(verdict.get("confidence", 0.0)),
            rubric_version=verdict.get("rubric_version", "unknown"),
            correlation_id=verdict.get("correlation_id", attempt.get("correlation_id", "")),
            evidence=verdict.get("evidence", []),
        )
        self._validate(report)
        return report

    def regression_case(self, report: VulnerabilityReport) -> dict[str, Any]:
        """Promote a confirmed exploit to a deterministic regression eval case.

        Pass condition is the *invariant* (``expected_safe_behavior``) holding on
        replay — not a string match on the leak — so a mere wording change in a
        future build does not silently 'pass' (ARCHITECTURE.md §"Regression
        harness").
        """
        return {
            "id": report.finding_id,
            "regression": True,
            "attack_category": report.attack_category,
            "subcategory": "confirmed_exploit",
            "exploitability": report.exploitability,
            "target_surface": report.target_surface,
            "owasp_web": report.owasp_web,
            "owasp_llm": report.owasp_llm,
            "input_sequence": [{"role": "attacker", "content": c} for c in report.reproduction],
            "expected_safe_behavior": report.expected_safe_behavior,
            "invariant": report.expected_safe_behavior,
            "source_finding": report.finding_id,
        }

    # ---- internals ---------------------------------------------------------
    def _title(self, category: str, surface: str, severity: str) -> str:
        pretty = category.replace("_", " ")
        return f"[{severity.upper()}] {pretty} on {surface} surface"

    def _narrate(self, attempt: dict[str, Any], verdict: dict[str, Any]) -> dict[str, Any] | None:
        try:
            return self.llm.narrate(attempt, verdict)
        except Exception:  # noqa: BLE001 — never let the LLM path drop the report
            return None

    def _validate(self, report: VulnerabilityReport) -> None:
        d = report.to_dict()
        for f in _REQUIRED_REPORT_FIELDS:
            v = d.get(f)
            if v is None or (isinstance(v, (str, list)) and len(v) == 0):
                raise DataQualityError(f"report missing required field: {f}")
        if not (0.0 <= report.confidence <= 1.0):
            raise DataQualityError("confidence out of range [0,1]")
        if report.exploitability not in _EXPLOITABILITY_LEVELS:
            raise DataQualityError(
                f"exploitability must be one of {_EXPLOITABILITY_LEVELS}; "
                f"got {report.exploitability!r}")


def dedupe_reports(reports: list[VulnerabilityReport]) -> list[VulnerabilityReport]:
    """Data-quality: drop duplicate findings that share the same attack sequence
    on the same (category, surface). Keeps the highest-confidence instance."""
    best: dict[tuple, VulnerabilityReport] = {}
    for r in reports:
        key = (r.attack_category, r.target_surface, tuple(r.reproduction))
        cur = best.get(key)
        if cur is None or r.confidence > cur.confidence:
            best[key] = r
    return list(best.values())
