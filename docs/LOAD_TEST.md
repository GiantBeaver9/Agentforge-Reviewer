# AgentForge — Baseline Performance & Load Test

A 100-request load test of the deployed Clinical Co-Pilot, plus an analytic
characterization of the expensive LLM surface. Reproduce with:

```bash
PYTHONPATH=src python -m agentforge.cli loadtest --n 100
```

## Method (and why this surface)

The load generator (`src/agentforge/loadtest.py`) fires 100 requests per
concurrency level with a thread pool and records per-request latency. It targets
the **unauthenticated liveness endpoint** `health.php`, which does no LLM work
and spends **none** of the co-pilot's token budget — so the test is safe to run
repeatedly against the live deploy. Hammering `agent.php`/`chat.php` at load
would burn the target's $10/hr breaker within seconds and is destructive, so the
expensive surface is characterized analytically from real single-shot
measurements instead (§LLM surface).

- **Target:** `https://abundant-art-production-d560.up.railway.app` (single
  Railway instance).
- **Client location:** through the session's egress proxy (adds a fixed RTT
  component — the absolute floor below is proxy+network, not server compute).

## Results (100 requests per level, `health.php`)

| Concurrency | Throughput | p50 | p95 | p99 | max | Errors |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 2.55 req/s | 382 ms | 438 ms | 506 ms | — | 0 |
| 5 | 11.62 req/s | 363 ms | 893 ms | 1132 ms | — | 0 |
| 10 | 23.97 req/s | 369 ms | 615 ms | 850 ms | — | 0 |
| 20 | 42.35 req/s | 384 ms | 862 ms | 1224 ms | — | 0 |

*(Raw JSON: `runs/loadtest-*.json`.)*

## Reading the numbers

- **p50 is flat (~363–384 ms) at every concurrency level.** The median is
  dominated by a fixed ~370 ms round-trip (egress proxy + network to Railway +
  PHP bootstrap), not by server compute. The endpoint itself is near-zero work.
- **Throughput scales, but sub-linearly at the top.** 1→5 workers ≈ 4.5×; 5→10 ≈
  2.1×; 10→20 ≈ 1.77×. The diminishing return from 10→20 is the first sign of
  worker-pool contention on the single instance.
- **The tail grows with load.** p99 climbs from 506 ms (c=1) to ~1224 ms (c=20)
  — a ~2.4× tail inflation — while p50 stays flat. That gap is queuing:
  requests wait for a PHP-FPM worker rather than for compute.
- **Zero errors across all 400 requests, zero `429`s.** No rate limiting engaged
  under sustained concurrent load — which **independently corroborates finding
  AF-PROBE-READY-RATELIMIT** (the per-IP limiter fails open on this deploy).

## Identified bottleneck

**PHP-FPM worker-pool saturation on the single Railway instance**, visible as
tail-latency inflation (p99) and sub-linear throughput past ~10 concurrent
requests, while p50 stays flat. The median floor (~370 ms) is network/proxy RTT,
not the app. Two consequences:

1. For cheap endpoints the app is not CPU-bound; it is **worker-slot-bound** — so
   the scaling lever is FPM `pm.max_children` and/or a second replica, not code
   optimization.
2. Because no limiter engages, an anonymous client can drive that saturation
   freely (see the rate-limit finding). Fixing the limiter is also a perf-
   stability control, not only a security one.

## LLM surface (analytic — the real production ceiling)

The chat/agent endpoints run a synchronous LLM call per request. Measured
single-shot latencies against the live deploy:

| Endpoint | Observed latency | Work |
|---|---|---|
| `agent.php` (supervisor → workers → critic) | ~5.0 s | multi-agent LLM run |
| `chat.php` (turn) | ~4.7 s | single-turn LLM + verify |

Here the ceiling is **budget-bound, not throughput-bound**. At the co-pilot's own
guardrails ($10/hr, $50/day + circuit breaker) and ~$0.02 per agent run, the
effective ceiling is on the order of **~500 agent runs/hour**, regardless of how
many workers are free — the breaker trips first. Concurrency past a handful of
in-flight LLM calls therefore buys nothing on this surface; it only accelerates
hitting the budget cap. This is *by design* (a cost-control guardrail) and is why
AgentForge itself keeps live `--max-attempts` low and does bulk iteration offline
against the mock.

## Recommendations

1. Size FPM `pm.max_children` to the instance and/or add a replica behind the
   load balancer to flatten the p99 tail past ~10 concurrent requests.
2. Make the `ready.php`/`health.php` limiter fail closed (see
   AF-PROBE-READY-RATELIMIT) so anonymous load can't saturate workers.
3. Keep the LLM surface asynchronous-friendly: the existing
   `set_time_limit(150)` + `ignore_user_abort` headroom is correct; the budget
   breaker is the right ceiling. No change needed beyond monitoring breaker trips.
