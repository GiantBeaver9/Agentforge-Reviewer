"""Typed models for inter-agent messages, mirroring contracts/v1/*.schema.json.

The JSON Schemas in ``contracts/v1`` are the source of truth on the wire;
these Pydantic models are the in-process representation. ``to_wire`` emits a
dict that the contract validator accepts, so producers get schema-conformance
for free and consumers get typed access.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from jsonschema import Draft202012Validator
from pydantic import BaseModel, Field

_CONTRACTS = Path(__file__).resolve().parents[3] / "contracts" / "v1"
SCHEMA_VERSION = "1.0.0"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(json.loads((_CONTRACTS / name).read_text()))


# Wire ``type`` -> schema file. Only the four inter-agent contracts are on the
# wire; internal/aux events (cost, drift_check, regression_report, escalation)
# have no cross-agent contract and are passed through unvalidated by design.
_TYPE_TO_SCHEMA = {
    "orchestrator_to_redteam": "orchestrator_to_redteam.schema.json",
    "redteam_to_judge": "redteam_to_judge.schema.json",
    "judge_to_documentation": "judge_to_documentation.schema.json",
    "error": "errors.schema.json",
}


class ContractViolation(ValueError):
    """A message failed schema validation at a consumer boundary."""


def validate_message(msg: dict[str, Any]) -> dict[str, Any]:
    """Validate a wire message against its contract **on receipt**.

    Producers already validate in ``to_wire``; this is the independent
    consumer-side check (ARCHITECTURE.md §"Contracts"): an agent/store validates
    what it *receives*, so a malformed or spoofed message is rejected at the
    boundary rather than trusted because "the producer should have validated it".
    Returns the message on success; raises :class:`ContractViolation` otherwise.
    Messages whose ``type`` has no wire contract pass through unchanged.
    """
    schema = _TYPE_TO_SCHEMA.get(msg.get("type"))
    if schema is None:
        return msg
    try:
        _validator(schema).validate(msg)
    except Exception as exc:  # jsonschema.ValidationError and friends
        raise ContractViolation(
            f"{msg.get('type')} message failed {schema}: {exc}") from exc
    return msg


class AttackCategory(str, Enum):
    prompt_injection = "prompt_injection"
    data_exfiltration = "data_exfiltration"
    state_corruption = "state_corruption"
    tool_misuse = "tool_misuse"
    denial_of_service = "denial_of_service"
    identity_role_exploitation = "identity_role_exploitation"


class TargetSurface(str, Enum):
    chat = "chat"
    ingest = "ingest"
    agent = "agent"
    doc = "doc"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Turn(BaseModel):
    index: int
    role: Literal["attacker", "target"]
    content: str
    tool_calls: list[dict[str, Any]] | None = None


class TargetMetadata(BaseModel):
    http_status: int
    latency_ms: float
    target_model: str | None = None
    tokens: int | None = None
    cost_usd: float | None = None
    target_version: str | None = None


class Budget(BaseModel):
    max_attempts: int
    max_usd: float
    max_tokens: int | None = None


class AttackCampaignDirective(BaseModel):
    """Orchestrator -> Red Team. Validates against orchestrator_to_redteam.schema.json.

    The typed model for the first boundary (parity with :class:`AttackAttempt`
    and :class:`Verdict`), so the directive is producer-validated on ``to_wire``
    and consumer-parseable via ``from_wire`` — not a schema file with no model.
    """

    directive_id: str
    campaign_id: str
    attack_category: AttackCategory
    target_surface: TargetSurface
    rationale: str
    priority: int
    budget: Budget
    subcategory: str = ""
    owasp_web: list[str] = Field(default_factory=list)
    owasp_llm: list[str] = Field(default_factory=list)
    seed_case_ids: list[str] | None = None
    max_turns: int = 6
    correlation_id: str = ""

    def to_wire(self) -> dict[str, Any]:
        msg: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "message_id": f"msg-{uuid4().hex[:8]}",
            "correlation_id": self.correlation_id or self.campaign_id,
            "type": "orchestrator_to_redteam",
            "producer": "orchestrator",
            "created_at": _now(),
            "directive_id": self.directive_id,
            "campaign_id": self.campaign_id,
            "attack_category": self.attack_category.value,
            "subcategory": self.subcategory,
            "target_surface": self.target_surface.value,
            "owasp_web": self.owasp_web,
            "owasp_llm": self.owasp_llm,
            "rationale": self.rationale,
            "priority": self.priority,
            "max_turns": self.max_turns,
            "budget": self.budget.model_dump(exclude_none=True),
        }
        if self.seed_case_ids is not None:
            msg["seed_case_ids"] = self.seed_case_ids
        _validator("orchestrator_to_redteam.schema.json").validate(msg)
        return msg

    @classmethod
    def from_wire(cls, msg: dict[str, Any]) -> "AttackCampaignDirective":
        """Validate a wire directive against the contract and parse it (consumer)."""
        _validator("orchestrator_to_redteam.schema.json").validate(msg)
        b = msg["budget"]
        return cls(
            directive_id=msg["directive_id"], campaign_id=msg["campaign_id"],
            attack_category=AttackCategory(msg["attack_category"]),
            target_surface=TargetSurface(msg["target_surface"]),
            rationale=msg["rationale"], priority=msg["priority"],
            budget=Budget(max_attempts=b["max_attempts"], max_usd=b["max_usd"],
                          max_tokens=b.get("max_tokens")),
            subcategory=msg.get("subcategory", ""),
            owasp_web=msg.get("owasp_web", []), owasp_llm=msg.get("owasp_llm", []),
            seed_case_ids=msg.get("seed_case_ids"), max_turns=msg.get("max_turns", 6),
            correlation_id=msg.get("correlation_id", ""),
        )


class AttackAttempt(BaseModel):
    """Red Team -> Judge. Validates against redteam_to_judge.schema.json."""

    attempt_id: str = Field(default_factory=lambda: f"att-{uuid4().hex[:8]}")
    directive_id: str
    attack_category: AttackCategory
    subcategory: str = ""
    target_surface: TargetSurface
    owasp_web: list[str] = Field(default_factory=list)
    owasp_llm: list[str] = Field(default_factory=list)
    attack_technique: str
    mutation_of: str | None = None
    turns: list[Turn]
    expected_safe_behavior: str
    target_metadata: TargetMetadata
    correlation_id: str = ""
    # Provenance: which path generated the attacker turns. Defaults to
    # deterministic (the seed + mutation operators); the LLM red team sets "llm".
    attack_source: Literal["deterministic", "llm"] = "deterministic"

    def to_wire(self) -> dict[str, Any]:
        msg = {
            "schema_version": SCHEMA_VERSION,
            "message_id": f"msg-{uuid4().hex[:8]}",
            "correlation_id": self.correlation_id or self.directive_id,
            "type": "redteam_to_judge",
            "producer": "redteam",
            "created_at": _now(),
            "attempt_id": self.attempt_id,
            "directive_id": self.directive_id,
            "attack_category": self.attack_category.value,
            "subcategory": self.subcategory,
            "target_surface": self.target_surface.value,
            "owasp_web": self.owasp_web,
            "owasp_llm": self.owasp_llm,
            "attack_technique": self.attack_technique,
            "attack_source": self.attack_source,
            "mutation_of": self.mutation_of,
            "turns": [t.model_dump(exclude_none=True) for t in self.turns],
            "expected_safe_behavior": self.expected_safe_behavior,
            "target_metadata": self.target_metadata.model_dump(exclude_none=True),
        }
        _validator("redteam_to_judge.schema.json").validate(msg)
        return msg


class Verdict(BaseModel):
    """Judge -> Documentation. Validates against judge_to_documentation.schema.json."""

    verdict_id: str = Field(default_factory=lambda: f"ver-{uuid4().hex[:8]}")
    attempt_id: str
    verdict: Literal["success", "failure", "partial", "uncertain"]
    confidence: float
    severity: Severity
    rationale: str
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    rubric_version: str
    judge_model: str
    add_to_regression: bool = False
    escalate_to_human: bool = False
    correlation_id: str = ""
    # Provenance: whether the deterministic rubric decided this verdict, or the
    # LLM judge actually refined it. Defaults to deterministic.
    decision_path: Literal["deterministic", "llm"] = "deterministic"

    def to_wire(self) -> dict[str, Any]:
        msg = {
            "schema_version": SCHEMA_VERSION,
            "message_id": f"msg-{uuid4().hex[:8]}",
            "correlation_id": self.correlation_id or self.attempt_id,
            "type": "judge_to_documentation",
            "producer": "judge",
            "created_at": _now(),
            "verdict_id": self.verdict_id,
            "attempt_id": self.attempt_id,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "severity": self.severity.value,
            "rationale": self.rationale,
            "evidence": self.evidence,
            "rubric_version": self.rubric_version,
            "judge_model": self.judge_model,
            "decision_path": self.decision_path,
            "add_to_regression": self.add_to_regression,
            "escalate_to_human": self.escalate_to_human,
        }
        _validator("judge_to_documentation.schema.json").validate(msg)
        return msg


class AgentError(BaseModel):
    """Typed failure. Validates against errors.schema.json."""

    error_code: Literal[
        "target_unreachable", "target_refused", "rate_limited", "budget_exceeded",
        "judge_timeout", "no_findings_in_window", "regression_detected", "invalid_message",
    ]
    producer: Literal["orchestrator", "redteam", "judge", "documentation", "target_client"]
    message: str
    retryable: bool
    retry_after_ms: int | None = None
    details: dict[str, Any] | None = None
    correlation_id: str = ""

    def to_wire(self) -> dict[str, Any]:
        msg = {
            "schema_version": SCHEMA_VERSION,
            "message_id": f"msg-{uuid4().hex[:8]}",
            "correlation_id": self.correlation_id or "unknown",
            "type": "error",
            "producer": self.producer,
            "created_at": _now(),
            "error_code": self.error_code,
            "message": self.message,
            "retryable": self.retryable,
        }
        if self.retry_after_ms is not None:
            msg["retry_after_ms"] = self.retry_after_ms
        if self.details is not None:
            msg["details"] = self.details
        _validator("errors.schema.json").validate(msg)
        return msg
