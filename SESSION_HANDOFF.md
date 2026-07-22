# AgentForge — Session Handoff (for the next, memory-wiped session)

Hi future me. You are "vector duck." Adam is the driver — sharp, knows what he
wants, gets sick of AI-for-AI's-sake. He likes fake insults and calls his
instructor a duck. Match his energy, don't be a sycophant, and **don't
over-polish** — he'd rather the submission look like honest human-scoped work
than suspiciously perfect. Act like an architect, not a code monkey.

## What this is

**AgentForge** — a multi-agent adversarial security platform that attacks the
OpenEMR **Clinical Co-Pilot** (`oe-module-clinical-copilot`) for Gauntlet AI
Week 3. Four agents (Orchestrator, Red Team, Judge, Documentation) over a
deterministic substrate (observability store, regression harness, probe
harness, load test). Design philosophy: **deterministic-first** — cheapest tool
that solves each sub-problem; LLM only for novel attack generation + NL
judgement. LLMs are **opt-in** and fail soft to the deterministic core.

## Where the code lives (TWO repos, keep them in parity)

1. **Monorepo:** `/home/user/openemr-base-clean/agentforge/` — branch
   **`claude/handoff-continuation-vx424d`** (repo `GiantBeaver9/openemr-base-clean`).
2. **Standalone:** `/workspace/agentforge-reviewer/` — branch **`main`**
   (repo `giantbeaver9/agentforge-reviewer`). Its root MIRRORS the `agentforge/`
   subdir. **Every change goes to BOTH repos**, then commit+push each.

## Current state — SUBMISSION-READY MVP ✅

- **70/70 tests green:** `cd agentforge && PYTHONPATH=src pytest tests/ -q`
- Verified **live** against the deployed target
  (`https://abundant-art-production-d560.up.railway.app`) — the co-pilot
  defended every seeded attack (honest negative), plus **3 real deterministic
  findings** on the unauthenticated surface.
- **Independent verification done today:** 10 adversarial sub-agent auditors +
  1 docs-vs-code drift audit. Result: **9 PASS, 3 PARTIAL (non-blocking), drift
  CLEAN after corrections.** Full checklist:
  `docs/VERIFICATION_CHECKLIST.pdf` (+ `.html` source).
- **Fixed today:** stale test count (39/63 → 70), Orchestrator formula wording
  (dropped a `regression_suspicion` term that wasn't in code), LangGraph framing
  (plain-Python `run_campaign` is canonical; `build_langgraph` is an optional
  drop-in). All in `docs/TODO.md` context.

## What's LEFT (Thursday — minimal)

1. **Plug in the LLMs (config, not code).** Set in env, then run:
   - `JUDGE_BASE_URL`, `JUDGE_MODEL`, `JUDGE_API_KEY`
   - `REDTEAM_BASE_URL`, `REDTEAM_MODEL`, `REDTEAM_API_KEY`
   OpenAI-compatible endpoints (OpenAI / OpenRouter / LM Studio / Ollama).
   Both fail soft to deterministic if unset — nothing breaks without them.
   See `.env.example` and `docs/COST_ANALYSIS.md`.
2. **Record the demo video** (storyboard in `docs/DEMO_SCRIPT.md`) — Adam's
   doing this downstairs with better mic gain. Fill `<demo-link>` / `<repo-link>`
   in `docs/SOCIAL_POST.md` after.
3. **Upload / submit** Thursday evening, then drive to Austin Fri/Sat.

## Deferred by design (in `docs/TODO.md`, NOT for MVP — do only if asked)

- Small history DB (e.g. SQLite) for pass/fail rate **over time** + a dashboard
  trend tab. (Today's `pass_rate` is cumulative-per-category, not a time series.)
- Dashboard tab showing raw Judge/Red-Team responses, split **deterministic vs
  LLM-run**.
- Report polish: explicit `exploitability` field on `VulnerabilityReport`; make
  `evidence` required; a synthetic critical-severity example to exercise the
  `PENDING_HUMAN` gate; a determinism test on `store.summary()`.
- ATO packet: SBOM/dependency-version table, pip-audit/safety scan note,
  incident-response section, mention the dashboard's own HTTP Basic-auth gate.

> These are known, named, and intentionally left — Adam wants them visible as
> TODOs, not silently done.

## Standing constraints (don't violate)

- Work/push ONLY on the two branches above. Sync every change to BOTH repos.
- Never commit secrets — `.env` is gitignored (holds only dev `admin`/`pass`).
- Keep the model identifier out of commits/PRs/code — chat replies only.
- Commits: Conventional Commits + `--trailer "Assisted-by: Claude Code"`.
- Sandbox egress is Railway-scoped: external LLM/OpenRouter APIs 403 from here
  (WebSearch works; WebFetch of those APIs does not). So LLM wiring is verified
  by Adam in his own environment, not from this sandbox.

## Fast orientation commands

```bash
cd /home/user/openemr-base-clean/agentforge
PYTHONPATH=src pytest tests/ -q                       # 70 passed
PYTHONPATH=src python -m agentforge.web               # dashboard :8800
PYTHONPATH=src python -m agentforge.cli campaign --dry-run --mock-policy leaky
open docs/VERIFICATION_CHECKLIST.pdf                  # the rubric scorecard
cat docs/TODO.md                                      # what's deferred
```

Quack responsibly.
