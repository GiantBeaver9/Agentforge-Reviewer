"""Documentation agent: report generation, data-quality gates, human gate."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import pytest
from agentforge.agents.documentation import (DataQualityError, DocumentationAgent,
                                             PENDING_HUMAN, dedupe_reports,
                                             _derive_exploitability)
from agentforge.agents.judge import JudgeAgent
from agentforge.agents.redteam import RedTeamAgent, SeedCase
from agentforge.target.client import MockTargetClient


def _success_pair():
    d = json.loads((ROOT / "evals/cases/data_exfiltration.json").read_text())[0]
    directive = {"directive_id": "dir", "campaign_id": "c", "correlation_id": "c",
                 "attack_category": "data_exfiltration", "target_surface": "chat",
                 "rationale": "coverage_gap", "priority": 5, "max_turns": 4,
                 "budget": {"max_attempts": 6, "max_usd": 1.0}}
    attempts = RedTeamAgent(MockTargetClient("leaky")).run_directive(directive, [SeedCase.from_eval(d)])
    judge = JudgeAgent()
    for a in attempts:
        v = judge.judge(a).to_wire()
        if v["verdict"] == "success":
            return v, a
    raise AssertionError("expected a success verdict from leaky target")


def test_report_has_required_fields_and_human_gate():
    verdict, attempt = _success_pair()
    report = DocumentationAgent().document(verdict, attempt)
    d = report.to_dict()
    for f in ("finding_id", "title", "reproduction", "impact", "recommendation"):
        assert d[f], f
    # data_exfiltration success is critical -> must be gated for human approval.
    assert report.severity == "critical"
    assert report.status == PENDING_HUMAN


def test_regression_case_uses_invariant_not_string_match():
    verdict, attempt = _success_pair()
    report = DocumentationAgent().document(verdict, attempt)
    case = DocumentationAgent().regression_case(report)
    assert case["regression"] is True
    assert case["invariant"] == report.expected_safe_behavior
    assert case["input_sequence"]                # replayable


def test_report_requires_evidence():
    verdict, attempt = _success_pair()
    # the deterministic judge always attaches evidence to a success verdict
    report = DocumentationAgent().document(verdict, attempt)
    assert report.evidence, "success verdict should carry evidence"
    # ...and a report stripped of it must fail the data-quality gate
    report.evidence = []
    with pytest.raises(DataQualityError):
        DocumentationAgent()._validate(report)


def test_non_success_verdict_is_rejected():
    verdict, attempt = _success_pair()
    verdict = {**verdict, "verdict": "failure"}
    with pytest.raises(DataQualityError):
        DocumentationAgent().document(verdict, attempt)


def test_mismatched_ids_rejected():
    verdict, attempt = _success_pair()
    verdict = {**verdict, "attempt_id": "att-does-not-match"}
    with pytest.raises(DataQualityError):
        DocumentationAgent().document(verdict, attempt)


def test_report_has_exploitability_and_threads_to_regression_case():
    verdict, attempt = _success_pair()
    report = DocumentationAgent().document(verdict, attempt)
    assert report.exploitability in ("easy", "moderate", "hard")
    # required field: present in the serialized report...
    assert report.to_dict()["exploitability"] == report.exploitability
    # ...and threaded into the deterministic regression case.
    case = DocumentationAgent().regression_case(report)
    assert case["exploitability"] == report.exploitability


def test_exploitability_derivation_is_deterministic_from_shape():
    def attempt(technique, mutation_of, attacker_turns):
        turns = []
        for i in range(attacker_turns):
            turns.append({"index": 2 * i, "role": "attacker", "content": f"a{i}"})
            turns.append({"index": 2 * i + 1, "role": "target", "content": f"t{i}"})
        return {"attack_technique": technique, "mutation_of": mutation_of, "turns": turns}

    # single direct seed turn -> easy
    assert _derive_exploitability(attempt("seed", None, 1)) == "easy"
    # a discovered variant (mutation) even in one turn -> moderate
    assert _derive_exploitability(attempt("mutation", "att-seed", 1)) == "moderate"
    # a two-turn exchange -> moderate
    assert _derive_exploitability(attempt("seed", None, 2)) == "moderate"
    # a three-plus-turn chain -> hard
    assert _derive_exploitability(attempt("seed", None, 3)) == "hard"


def test_bad_exploitability_is_rejected():
    verdict, attempt = _success_pair()
    report = DocumentationAgent().document(verdict, attempt)
    report.exploitability = "trivial"  # not a valid level
    with pytest.raises(DataQualityError):
        DocumentationAgent()._validate(report)


def test_dedupe_keeps_highest_confidence():
    verdict, attempt = _success_pair()
    r1 = DocumentationAgent().document(verdict, attempt)
    r2 = DocumentationAgent().document({**verdict, "confidence": 0.99}, attempt)
    kept = dedupe_reports([r1, r2])
    assert len(kept) == 1
    assert kept[0].confidence == 0.99


def _mk_report(severity, status):
    from agentforge.agents.documentation import VulnerabilityReport
    return VulnerabilityReport(
        finding_id="AF-FIND-z", title="t", severity=severity, exploitability="easy",
        attack_category="data_exfiltration", target_surface="chat", owasp_web=[],
        owasp_llm=[], reproduction=["x"], expected_safe_behavior="e",
        observed_behavior="o", impact="i", recommendation="r", status=status,
        verdict_id="v", attempt_id="a", confidence=0.9, rubric_version="1.0.0",
        correlation_id="c")


def test_publish_gate_blocks_critical_without_approver():
    from agentforge.agents.documentation import (ApprovalRequired, DocumentationAgent,
                                                 PENDING_HUMAN, PUBLISHED)
    doc = DocumentationAgent()
    r = _mk_report("critical", PENDING_HUMAN)
    import pytest as _pytest
    with _pytest.raises(ApprovalRequired):
        doc.publish(r)                       # no approver -> refused
    assert r.status == PENDING_HUMAN         # not published
    doc.publish(r, approver="alice")
    assert r.status == PUBLISHED and r.approved_by == "alice"


def test_publish_auto_publishes_noncritical_draft():
    from agentforge.agents.documentation import DocumentationAgent, DRAFT, PUBLISHED
    doc = DocumentationAgent()
    r = _mk_report("high", DRAFT)
    doc.publish(r)                           # draft publishes with no approver
    assert r.status == PUBLISHED and r.approved_by is None
