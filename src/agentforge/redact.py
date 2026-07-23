"""PHI redaction for persisted evidence and the dashboard.

A confirmed exploit's whole value is that the target disclosed data it shouldn't
have — but AgentForge must not then become the thing that stores that PHI in the
clear. This module scrubs clinical values (lab results, medications, vitals) from
any text before it is written to a report on disk or rendered in the dashboard.

Two rules make it safe:

* **Redact only for persistence/display, never before adjudication.** The Judge
  and the regression harness score the *raw* transcript in memory; redaction is
  applied to the copy that is stored or shown, so it can never change a verdict.
* **Keep the attack indicator, drop the payload.** A cross-patient marker like
  "patient 2" is an *attack* signal, not PHI, so it stays; the leaked *value*
  ("A1c was 8.1%", "metformin") is what gets replaced. That keeps findings
  triage-able without retaining the sensitive data.

Deterministic (regex + a fixed vocabulary) so redaction is reproducible and adds
no model cost.
"""
from __future__ import annotations

import re
from typing import Any

_PHI_TAG = "[PHI-REDACTED]"
_MED_TAG = "[MED-REDACTED]"

# Common medications the co-pilot might surface; a leaked med name is PHI.
_MEDS = (
    "metformin", "glipizide", "glimepiride", "insulin", "lisinopril",
    "atorvastatin", "metoprolol", "warfarin", "januvia", "ozempic",
    "amlodipine", "losartan", "hydrochlorothiazide", "gabapentin",
)

# A clinical measure followed (within a short span) by its value + unit.
_LAB_VALUE = re.compile(
    r"(?i)\b(a1c|hba1c|ldl|hdl|egfr|bp|blood pressure|glucose|creatinine|inr|weight)\b"
    r"([^.\n]{0,24}?)"
    r"\d{1,4}(?:\.\d+)?\s*(?:%|mg/dl|mmhg|kg|lbs)?(?:\s*/\s*\d{1,3})?"
)

# "patient <n> ... <number>[%]" — a cross-patient value disclosure; keep the
# "patient n" marker, drop the trailing numeric value.
_CROSS_PATIENT_VALUE = re.compile(
    r"(?i)(patient\s+(?:id\s+)?\d+[^.\n]{0,30}?)\b\d{1,4}(?:\.\d+)?\s*%?"
)

_MED_RE = re.compile(r"(?i)\b(" + "|".join(_MEDS) + r")\b")


def redact_phi(text: str | None) -> str:
    """Return ``text`` with clinical values/medications replaced by tags."""
    if not text:
        return text or ""
    t = _LAB_VALUE.sub(lambda m: f"{m.group(1)} {_PHI_TAG}", text)
    t = _CROSS_PATIENT_VALUE.sub(lambda m: f"{m.group(1)}{_PHI_TAG}", t)
    t = _MED_RE.sub(_MED_TAG, t)
    return t


def redact_evidence(evidence: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Redact the ``quote`` span of each evidence item (a copy; input untouched)."""
    out: list[dict[str, Any]] = []
    for e in (evidence or []):
        item = dict(e)
        if "quote" in item:
            item["quote"] = redact_phi(item.get("quote"))
        out.append(item)
    return out


def redact_turns(turns: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Redact target-turn content (a copy). Attacker turns are the attack, not PHI."""
    out: list[dict[str, Any]] = []
    for t in (turns or []):
        item = dict(t)
        if item.get("role") == "target":
            item["content"] = redact_phi(item.get("content"))
        out.append(item)
    return out


def redact_attempt(attempt: dict[str, Any]) -> dict[str, Any]:
    """A shallow copy of an AttackAttempt wire message with target turns redacted."""
    out = dict(attempt)
    out["turns"] = redact_turns(attempt.get("turns"))
    return out


def redact_verdict(verdict: dict[str, Any]) -> dict[str, Any]:
    """A copy of a Verdict with the rationale and evidence quotes redacted."""
    out = dict(verdict)
    if "rationale" in out:
        out["rationale"] = redact_phi(out.get("rationale"))
    if "evidence" in out:
        out["evidence"] = redact_evidence(out.get("evidence"))
    return out
