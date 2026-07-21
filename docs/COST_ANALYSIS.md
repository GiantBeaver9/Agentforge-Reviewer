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
- **Judge coverage** — the Judge sees *every* attempt (it must, to decide). So
  Judge cost scales linearly with attempts.
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
