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

## Architecture changes by scale tier (not a flat per-attempt line)

The $0.0024/attempt figure above is a *unit price*, not an operating plan — it is
deliberately linear so the model is auditable, but the **architecture changes at
each tier**, and those changes (not the per-token price) are what keep the bill
sublinear. What you *build* differs at 100 vs 100K:

| Tier | What it is | Architecture at this tier | Dominant cost | Per-attempt trend |
|---|---|---|---|---|
| **100** | one capped live campaign / a demo | Everything inline, single process. Deterministic Judge only (`u=0`), no LLM Judge, Red Team local. Cost is the *target's* LLM spend, not AgentForge's. | target-side LLM | ~$0.002 (target), ≈$0 platform |
| **1K** | a nightly against staging | Add the **LLM Judge on the uncertain fraction only** (`u≈20%`), keep Red Team local. Batch attempts per cell; reuse one auth/CSRF session across the run. Persist runs to Postgres history. | Judge (20% of 1K) | flat, but 80% of attempts never touch a frontier model |
| **10K** | continuous against one target | **Cache + dedupe before spend:** hash each (attack_technique, seed, cell) and skip re-running an attempt whose transcript-shape was already judged; the Orchestrator's `no_findings_in_window` halt sheds dead cells so budget concentrates where the target is weak. Move the Red Team fully **local** (GPU) — hosted token cost stops mattering. Judge escalation batched. | Judge on the *residual* uncertain set | **falls** — dedupe + halt remove repeat spend |
| **100K+** | fleet: many targets / always-on | **Two-stage Judge** (cheap open model triages every uncertain case; frontier model only on the open-model's own "unsure"), so frontier calls scale with `attempts × u × u'` not `attempts × u`. Shard campaigns per target across workers (the store is per-`correlation_id`, so this parallelizes with no shared state). Reserve/commit pricing or BYOK to zero the platform fee. Alert on cost-per-finding, not raw spend. | frontier Judge on `u·u'` (a few %) | **lowest per-attempt** — the frontier model becomes a rounding error |

Concretely: *at 10K do X* = turn on transcript-shape dedupe and push the Red Team
onto local hardware; *at 100K do Y* = split the Judge into a cheap-triage →
frontier-confirm cascade and shard by target. Neither is a knob on the linear
model — they are different execution graphs, and each one bends the curve down.

The one thing that is **not** a tier change: independence. The generator ≠ grader
rule holds at every tier (a two-stage Judge still uses a different family than the
Red Team), because it is a correctness property, not a cost optimization.

## Development spend to date

Building AgentForge cost **≈ $0 in model spend**. The number is small enough to
state plainly and it is a design outcome, not luck:

- **LLM API spend during development: ~$0.** The entire platform is built on
  deterministic cores (Judge rubric, Orchestrator scoring, Red Team mutation
  operators, probes, regression replay), and the sandbox that built it has
  **external LLM/OpenRouter egress blocked** (docs/SECURITY_SCAN.md) — so no
  frontier tokens were ever spent to develop or test it. The 93-test suite runs
  fully offline against `MockTargetClient`.
- **Target-side spend during live validation: single-digit dollars.** Live
  end-to-end runs against the deployed co-pilot were capped (`--rounds 2
  --max-attempts 4`, ≤18 attempts each, a handful of runs). At the target's own
  per-attempt LLM cost that is on the order of **a few dollars total**, bounded
  by the target's `$10/hr / $50/day` breaker — we never approached it.
- **The only non-zero optional line** is if you *choose* to run the LLM Judge or
  LLM Red Team live; on the open/mid-tier models in the table that is cents per
  campaign. The shipped default spends nothing.

So the honest dev-spend figure is **≈ $0 in AI, a few dollars of target budget**
— which is the whole point of a deterministic-first design: you can build and
regression-guard the entire adversarial platform before spending a token, and
turn the models on only where judgement quality actually pays for itself.

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
| **OpenRouter** | pass-through — **no per-token markup**; equals the routed provider's list price | **5.5%** fee on pay-as-you-go credit top-ups; some `:free` rate-limited variants. **BYOK:** fee-free up to $25K/mo of list-price inference, then 5% | routing to **multiple** families through one key + one balance |
| **HF Inference Providers** | pay-per-token, routed to a backend | dedicated Inference Endpoints (paid) for a specific uncensored model not on serverless | the **open/uncensored Red Team** catalog |
| **Local** (LM Studio / Ollama / vLLM) | ~$0 marginal (electricity) | your own GPU / host | zero-token-cost, no-refusal, private Red Team — the recommended default when you have the hardware |

Because OpenRouter is pass-through, it's the pragmatic pick for this system: one
account routes the frontier **Judge** and the open **Red Team** simultaneously,
which is exactly the independent split the architecture wants. At the volumes
below the **5.5%** top-up fee is rounding error (a $5 credit runs dozens of live
campaigns); at high volume, **BYOK removes the platform fee** (fee-free to
$25K/mo of list-price inference), so the platform fee never becomes a scaling
term — you converge on the underlying providers' raw token cost.

**Per-model token prices** ($/1M tokens, list price via OpenRouter, mid-2026 —
these move, so verify at [`openrouter.ai/models`](https://openrouter.ai/models)).
The last column is the cost of **one Judge call** (~1,200 in / 250 out tokens):

| Model (role) | In $/MTok | Out $/MTok | $ / Judge call |
|---|---:|---:|---:|
| `llama-3.1-8b-instruct` (Red Team) | 0.02 | 0.03 | — |
| `qwen2.5-72b-instruct` (open Judge) | 0.04 | 0.10 | $0.00007 |
| `gemini-2.5-flash-lite` (Judge) | 0.10 | 0.40 | $0.00022 |
| `gpt-4o-mini` (Judge) | 0.15 | 0.60 | $0.00033 |
| `gemini-2.5-flash` (Judge) | 0.30 | 2.50 | $0.00099 |
| `claude-sonnet-5` (Judge, frontier) | 3.00 (intro 2.00) | 15.00 (intro 10.00) | $0.0074 |
| `claude-opus-4-8` (Judge, top) | 5.00 | 25.00 | $0.012 |

The **Red Team model is effectively free even hosted**: `llama-3.1-8b` at
$0.02/$0.03 is ~$0.00007 per attempt (4 variants), so 100K attempts ≈ **$7** on
OpenRouter — or **$0** run locally. `:free` rate-limited variants exist for
testing. Note the **~100× span across viable Judge models** ($0.00007 →
$0.0074/call) — that's the lever the next section quantifies.

## Effective spend at scale

**Plain terms first.** A single capped live campaign (the dashboard limits a live
run to ≤3 rounds × ≤6 attempts ≈ 18 attempts) costs **single-digit cents** — on
the order of **≲10¢ of Red Team and ≲2–3¢ of Judge** with a mid-tier model (up to
~13¢ Judge if *every* attempt escalates to a frontier model; ~$0 on an open one).
At that scale the *target's* own per-attempt LLM spend is the larger number. The
projection below is for the 100K+ regime a continuously-running deployment
reaches — where two levers keep it cheap.

**Lever 1 — the deterministic gate.** The headline table prices an LLM Judge on
**every** attempt (an upper bound). The shipped Judge only escalates the
**uncertain fraction `u`** to the LLM (`agents/judge.py` refines `uncertain`/
`partial` only), so frontier Judge spend scales with `attempts × u`, not
`attempts`.

**Lever 2 — the Judge model** (~100× per-call span, table above). Combined, at
**100K attempts with `u = 20%`** (i.e. 20K LLM Judge calls):

| Judge model | $ / call | 100K attempts @ u=20% |
|---|---:|---:|
| `qwen2.5-72b` (open) | $0.00007 | **~$1.50** |
| `gemini-2.5-flash-lite` | $0.00022 | ~$4.40 |
| `gpt-4o-mini` | $0.00033 | ~$6.60 |
| `claude-sonnet-5` (frontier) | $0.0074 | ~$147 |

So the Judge bill at 100K attempts runs **~$1.50 to ~$150** purely on model
choice; Red Team adds ≈$7 hosted / $0 local; Documentation fires only on
confirmed exploits; probes and regression never call an LLM. **The frontier model
is the smallest controllable line item, and the two levers keep it that way at
100K+.** Choose on the accuracy/cost trade-off from `check_ground_truth()`, not
list price alone — a $1.50 open judge that mislabels the ground truth costs more
than a $147 one that doesn't.

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
