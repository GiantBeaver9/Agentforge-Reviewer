"""Deterministic cost model — the missing accounting under the budget breaker.

Every live attempt spends real money: the target co-pilot runs an LLM per turn,
and the Red Team / Judge may run their own models. That spend has to be visible
for two things the case study asks for: a dashboard cost metric that isn't a
permanently-zero field, and a budget breaker that actually **halts when cost
accumulates without signal**. This module is the single, deterministic source of
those numbers so both are driven by the same math (ARCHITECTURE.md §"Cost &
scale", docs/COST_ANALYSIS.md).

It is intentionally an *estimate*, not a meter: the target's true token bill is
not exposed over its HTTP surface, so we price each turn from the transcript at
published list prices. Estimation is deterministic (no LLM, no randomness) so the
same run always accounts the same cost — which is what makes it safe to gate a
budget on.
"""
from __future__ import annotations

from typing import Any, Iterable

# $ per 1M tokens (input, output). List prices, mid-2026, matching the model
# choices in docs/COST_ANALYSIS.md. "target" prices the co-pilot's own LLM at a
# mid tier; "redteam" is the cheap hosted open model (≈$0 run locally); "judge"
# is the mid-tier frontier Judge, billed only when the LLM Judge actually refines
# a verdict.
PRICE_PER_MTOK: dict[str, tuple[float, float]] = {
    "target": (0.30, 2.50),   # gemini-2.5-flash-class; the co-pilot per turn
    "redteam": (0.02, 0.03),  # llama-3.1-8b hosted; $0 marginal if truly local
    "judge": (0.30, 2.50),    # frontier Judge, LLM path only (deterministic=free)
}

# ~4 characters per token is the usual rough English ratio; deterministic so a
# replay accounts identically.
CHARS_PER_TOKEN = 4

# The target reads far more than the attacker's message each turn: its system
# prompt, the pinned patient's chart/synthesis, and retrieved facts. Fold that
# fixed context into every target turn's input so the per-attempt estimate is
# realistic rather than counting only the visible attacker text.
TARGET_CONTEXT_TOKENS = 800


def estimate_tokens(text: str | None) -> int:
    """Deterministic token estimate for a string (min 1 for any non-empty call)."""
    return max(1, len(text or "") // CHARS_PER_TOKEN)


def cost(role: str, in_tokens: int, out_tokens: int) -> float:
    """Cost in USD of one ``role`` call of the given token shape."""
    price_in, price_out = PRICE_PER_MTOK[role]
    return round(in_tokens / 1_000_000 * price_in
                 + out_tokens / 1_000_000 * price_out, 8)


def target_turn_cost(attacker_text: str, target_text: str) -> float:
    """Estimated target-side LLM spend for one attacker->target exchange."""
    in_tok = estimate_tokens(attacker_text) + TARGET_CONTEXT_TOKENS
    out_tok = estimate_tokens(target_text)
    return cost("target", in_tok, out_tok)


def attempt_cost(turns: Iterable[dict[str, Any]], *,
                 attack_source: str = "deterministic") -> float:
    """Estimate the full per-attempt spend from its transcript.

    Sums the target's per-turn LLM cost across the attempt, plus the Red Team's
    generation cost when an LLM produced the attacker turns (the deterministic
    mutation operators are free). The Judge's cost is accounted separately by the
    pipeline, since a deterministic verdict is free and only the escalated LLM
    path costs anything.
    """
    turns = list(turns)
    total = 0.0
    pending_attacker = ""
    for t in turns:
        if t.get("role") == "attacker":
            pending_attacker = t.get("content", "")
        elif t.get("role") == "target":
            total += target_turn_cost(pending_attacker, t.get("content", ""))
            pending_attacker = ""

    if attack_source == "llm":
        # One generation call produced this attacker turn (seed + ~4 variants are
        # amortized to a per-attempt share). Priced on the Red Team model.
        attacker_text = next((t.get("content", "") for t in turns
                              if t.get("role") == "attacker"), "")
        total += cost("redteam", estimate_tokens(attacker_text) + 200,
                      estimate_tokens(attacker_text))
    return round(total, 8)


def judge_llm_cost(transcript: str, rationale: str = "") -> float:
    """Cost of one LLM-Judge refinement call over a transcript."""
    return cost("judge", estimate_tokens(transcript) + 200,
                estimate_tokens(rationale) + 80)
