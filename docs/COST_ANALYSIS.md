# AgentForge — AI Cost Analysis

Projected AI spend at 100 / 1K / 10K / 100K attack attempts. The whole cost model
follows from one architectural decision (ARCHITECTURE.md §"Cost & scale"): the
**expensive, high-volume work — attack generation and mutation — runs on a
local/open model (≈ $0)**, and a **frontier model is spent only where judgement
quality matters (Judge, and Documentation on confirmed exploits)**. Everything
else (budget accounting, coverage math, regression replay, the deterministic
probes) is non-AI and free.

## Unit assumptions

Per-call token estimates are deliberately conservative (rounded up).

| Role | Model class | Price (in / out per 1M tok) | Tokens per call (in / out) | $ / call |
|---|---|---|---|---|
| Red Team generate + mutate | local (Llama-3.1-8B on owned GPU / Ollama) | ~$0 marginal | 400 / 300 | **$0.000** |
| Judge (per attempt) | frontier, small tier | $0.80 / $4.00 | 1,200 / 250 | **$0.00196** |
| Documentation (per **confirmed** finding) | frontier, mid tier | $3.00 / $15.00 | 2,500 / 900 | **$0.02100** |

Non-AI components (Orchestrator scoring, observability rollups, regression
replay, deterministic probes) are **$0** — pure Python over HTTP.

Two workload knobs drive the totals:
- **Judge coverage** — the *deterministic* rubric sees every attempt for free;
  the LLM Judge (optional) is escalated only on the **uncertain fraction `u`**,
  so real frontier Judge cost scales with `attempts × u`, not attempts (see
  §"Effective spend at scale"). The table below prices the conservative
  every-attempt case as an upper bound.
- **Finding rate `f`** — the fraction of attempts that are confirmed exploits and
  therefore trigger a Documentation call. A hardened target (like the current
  deploy, `f ≈ 0`) costs almost nothing downstream; a leaky build costs more but
  only because it is producing more reports. We model `f = 2%` as a working
  average and show the `f = 0%` / `f = 10%` band.

## Projection (Red Team local, `f = 2%`)

`total ≈ attempts × ($0 red_team + $0.00196 judge) + (attempts × f × $0.021 docs)`

| Attempts | Red Team | Judge | Documentation (f=2%) | **Total** | $ / attempt |
|---:|---:|---:|---:|---:|---:|
| 100 | $0.00 | $0.20 | $0.04 | **$0.24** | $0.0024 |
| 1,000 | $0.00 | $1.96 | $0.42 | **$2.38** | $0.0024 |
| 10,000 | $0.00 | $19.60 | $4.20 | **$23.80** | $0.0024 |
| 100,000 | $0.00 | $196.00 | $42.00 | **$238.00** | $0.0024 |

### Sensitivity to finding rate

| Attempts | f = 0% (hardened) | f = 2% | f = 10% (leaky build) |
|---:|---:|---:|---:|
| 100 | $0.20 | $0.24 | $0.41 |
| 1,000 | $1.96 | $2.38 | $4.06 |
| 10,000 | $19.60 | $23.80 | $40.60 |
| 100,000 | $196.00 | $238.00 | $406.00 |

## What if the Red Team were also a frontier model?

The single biggest lever is keeping the Red Team local. If it ran on a frontier
model instead (est. 700 tok in / 400 out mixed tier ≈ $0.006/call, and it makes
~5 calls per attempt for seed + 4 mutations):

| Attempts | Red Team (local) | Red Team (frontier) | Multiplier |
|---:|---:|---:|---:|
| 10,000 | $0.00 | ~$300 | — |
| 100,000 | $0.00 | ~$3,000 | **~13× the whole local bill** |

Local-model Red Team turns the dominant cost term to zero; this is the core
cost decision, not an optimization.

## Choosing the models (on criteria, not vendor)

Two roles, opposite requirements — pick on what the role needs, not on brand:

| Role | Needs | Good fits (any provider) | Avoid |
|---|---|---|---|
| **Judge** (independent, low volume) | strong instruction-following, reliable structured JSON, low hallucination; a **different family** than the Red Team | frontier tier — `claude-sonnet-5`, `gpt-4o`/`gpt-4o-mini`, `gemini-2.0-flash`; or a large open model (`qwen2.5-72b`, `llama-3.3-70b`) to stay fully open | the *same* model/family as the Red Team (correlated blind spots) |
| **Red Team** (high volume, offensive) | will **not refuse** offensive-security generation; cheap | open / weakly-guarded — `llama-3.1-8b`, `mistral`, uncensored variants (local, HF, or OpenRouter) | safety-tuned frontier models — they refuse, so the Red Team silently degrades to the deterministic operators |

**The one hard rule is independence — generator ≠ grader.** Using the same
family for both reintroduces the conflict of interest the platform exists to
remove. Don't pick the Judge by vendor loyalty — select it **empirically**: run
2–3 candidate Judges through `JudgeAgent.check_ground_truth()` against
`evals/ground_truth.json` and keep the highest-agreement model. That is a
neutral, reproducible selector, and it is the *right* way to choose a judge for a
platform whose thesis is "verify, don't trust the vendor."

## What each route costs

Token prices are the provider's list price; the *route* adds (or removes)
overhead on top:

| Route | Token price | Route overhead | Best for |
|---|---|---|---|
| **Direct** (Anthropic / OpenAI / Google) | provider list | none | a single committed model |
| **OpenRouter** | pass-through — **no per-token markup** | ~5% fee on credit top-ups; BYOK option; some `:free` rate-limited variants | routing to **multiple** families through one key + one balance |
| **HF Inference Providers** | pay-per-token, routed to a backend | dedicated Inference Endpoints (paid) for a specific uncensored model not on serverless | the **open/uncensored Red Team** catalog |
| **Local** (Ollama / vLLM) | ~$0 marginal | your own GPU / host | high-volume Red Team at zero token cost |

Because OpenRouter is pass-through, it's the pragmatic pick for this system: one
account routes the frontier **Judge** and the open **Red Team** simultaneously,
which is exactly the independent split the architecture wants. At the volumes
below, the ~5% top-up fee is rounding error (a $5 credit runs dozens of live
campaigns).

**Per-model reference prices** ($/1M tokens). *Confirm on the provider's page —
these move; only the Claude rows are pinned to the current catalog:*

| Model (typical role) | In $/MTok | Out $/MTok |
|---|---:|---:|
| `claude-sonnet-5` (Judge) | 3.00 (intro 2.00) | 15.00 (intro 10.00) |
| `claude-opus-4-8` (Judge, top) | 5.00 | 25.00 |
| `claude-haiku-4-5` (Judge, budget) | 1.00 | 5.00 |
| `gpt-4o-mini` (Judge) | _verify_ | _verify_ |
| `gemini-2.0-flash` (Judge) | _verify_ | _verify_ |
| `qwen2.5-72b-instruct` (open Judge) | _verify_ | _verify_ |
| `llama-3.1-8b-instruct` (Red Team) | _verify_ (cents) | _verify_ (cents) |

## Effective spend at scale — the deterministic gate

The headline table prices an LLM Judge on **every** attempt (an upper bound). The
shipped Judge doesn't work that way: the **free deterministic rubric decides the
clear cases, and only the uncertain fraction `u` is escalated to the LLM**
(`agents/judge.py` refines `uncertain`/`partial` only). So real frontier Judge
spend scales with `attempts × u`, not `attempts`:

`effective judge $ ≈ attempts × u × ($/judge-call)`

| Attempts | u = 40% | u = 20% | u = 10% |
|---:|---:|---:|---:|
| 10,000 | $7.84 | $3.92 | $1.96 |
| 100,000 | $78.40 | $39.20 | $19.60 |

(at the $0.00196/call small-frontier unit; for `claude-sonnet-5` multiply ≈3.8× —
100K @ `u=20%` ≈ **$150**.) The lever compounds: Documentation runs only on
confirmed exploits, and the probe + regression paths never call an LLM at all.
**The system is deliberately built so the frontier model is the smallest line
item, not the largest — that is what keeps it viable at 100K+ attempts.**

## Cost controls actually enforced in code

These are not aspirational — the Orchestrator enforces them (`agents/orchestrator.py`):

- **Per-run dollar cap** (`max_usd`) and **per-campaign attempt cap**
  (`max_attempts`) — the run halts with `budget_exceeded` when either is hit.
- **No-signal halt** (`no_findings_in_window`) — stop spending on a cell that
  yields nothing after N campaigns, instead of grinding attempts.
- **Deterministic-first** — the probe harness and regression replay answer the
  unauth / IDOR / fuzzing / replay questions with **zero** AI spend; the LLM is
  reserved for the LLM-semantic, multi-turn surface only.
- **Judge before Docs** — Documentation (the most expensive per-call role) runs
  *only* on `verdict=success`, so a hardened target incurs no report cost.

## Target-side cost (don't burn the co-pilot's budget)

A second, non-AgentForge cost: each live `agent.php`/`chat.php` attempt spends the
*target's* LLM budget (the co-pilot has a $50/day, $10/hr cap + circuit breaker).
Live campaigns therefore keep `--max-attempts` low and back off on the breaker;
bulk iteration happens offline against `MockTargetClient`. This is a safety
control as much as a cost one (THREAT_MODEL "Gotchas").
