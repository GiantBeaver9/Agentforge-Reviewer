"""Typed models must emit wire messages that pass the published contracts."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agentforge.contracts.models import (  # noqa: E402
    AgentError, AttackAttempt, AttackCategory, Severity, TargetMetadata,
    TargetSurface, Turn, Verdict,
)


def test_attack_attempt_roundtrips():
    a = AttackAttempt(
        directive_id="dir-1",
        attack_category=AttackCategory.prompt_injection,
        target_surface=TargetSurface.chat,
        attack_technique="role-play override",
        turns=[Turn(index=0, role="attacker", content="hi"),
               Turn(index=1, role="target", content="I can't do that.")],
        expected_safe_behavior="refuse",
        target_metadata=TargetMetadata(http_status=200, latency_ms=100.0),
    )
    wire = a.to_wire()          # raises if invalid
    assert wire["type"] == "redteam_to_judge"


def test_verdict_roundtrips():
    v = Verdict(attempt_id="att-1", verdict="success", confidence=0.9,
                severity=Severity.high, rationale="leaked", rubric_version="r1",
                judge_model="gemini-1.5-pro", add_to_regression=True)
    assert v.to_wire()["verdict"] == "success"


def test_error_roundtrips():
    e = AgentError(error_code="budget_exceeded", producer="orchestrator",
                   message="hit cap", retryable=False)
    assert e.to_wire()["error_code"] == "budget_exceeded"
