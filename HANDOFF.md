# AgentForge — Handoff

**Read this first.** It lets a fresh agent in the network-enabled environment
continue this build without re-deriving anything.

## TL;DR

- **Project:** AgentForge — a multi-agent adversarial security platform that
  attacks the OpenEMR Clinical Co-Pilot (Gauntlet Week 3).
- **Target (live):** `https://abundant-art-production-d560.up.railway.app`
- **Deadlines:** MVP **Tue 2026-07-21 23:59**, Final **Fri 2026-07-24 12:00**.
- **Branch:** `claude/agentforge-adversarial-platform-up8w9m` (all work lives in
  `/agentforge/`). **`git pull` this branch first** — a fresh clone won't have it.
- **Locked decisions (A/A/A):** self-contained `/agentforge/` dir · Python +
  LangGraph · Red Team is the live MVP agent.

## Why this handoff exists (environment note)

The session that built this ran in an environment whose egress policy is
**Trusted**, which does **not** include Railway — every request to the target
got a `403 CONNECT` (policy denial). Rather than route around it, the target-
independent work was built here and handed off. **A new cloud environment was
created with Custom egress allowlisting `*.up.railway.app` (+ defaults).** You
are (or should be) running in that environment. **First action: confirm the
target is reachable** (below). If it still 403s, the allowlist didn't take —
verify the env's Network access = Custom, `*.up.railway.app` + `*.railway.app`
listed, "include defaults" checked, and that you started a *new* session after
saving.

## Step 0 — VERIFIED ✅ (target reachable, login + CSRF + full loop confirmed live)

**This is done.** The target is reachable (HTTP 200) and the whole handshake was
confirmed against the live Railway deploy with `admin`/`pass`:

- Login posts `authUser`/`clearPass`/`new_login_session_management`/
  `languageChoice`/`facility=user_default` to
  `interface/main/main_screen.php?auth=login` (the module's own verified bruno
  flow). The old client sent the wrong fields — **fixed** in `client.py`.
- The CSRF form token is scraped from
  `.../oe-module-clinical-copilot/public/doc.php?pid=<pid>` via the chat panel's
  `id="ccpChatCsrf"` hidden input (NOT `dashboard.php`/`csrf_token_form` as the
  original draft assumed) — **fixed**. Needs a pid with a seeded synthesis doc
  (`--pid 1` works on the deploy).
- Two client bugs the live path exposed were fixed: the CLI passed the whole
  `Config` where the client expects `cfg.target`; and httpx needs the egress
  proxy CA (`/root/.ccr/ca-bundle.crt`) set as `verify=` — the client now does
  both, plus a small retry on the proxy's transient chunked-read closes.
- **Real result:** the co-pilot **defended** the benign and cross-patient/
  injection asks it was given (`answer_status=refused` on agent.php;
  `verify_status=degraded`, "couldn't produce a verifiable answer" on chat.php).
  Evidence: `runs/camp-95fd476c.attempts.jsonl` (Red Team only) and the live
  `campaign` run's `runs/*.observability.jsonl` + `*.reports.json`.

Original step-0 checklist (kept for reference / re-verification):

### Step 0 (reference) — verify reachability + auth

```bash
# a) reachability
curl -sS -o /dev/null -w "%{http_code}\n" https://abundant-art-production-d560.up.railway.app/interface/login/login.php
# expect 200 (not 000/403)
```

Then verify the **OpenEMR login + CSRF handshake**, which is the ONE piece of
the target client that was written to convention but not verified live
(`src/agentforge/target/client.py`, `OpenEmrTargetClient.login` + `_ensure_csrf`):

1. Get target credentials (default OpenEMR dev is `admin`/`pass`; confirm what
   the Railway deploy uses). Put them in `.env`
   (`AGENTFORGE_TARGET_USERNAME` / `_PASSWORD`).
2. Confirm the **login POST** path/fields. The client posts
   `authUser/clearPass/authProvider/languageChoice` to
   `interface/main/main_screen.php?auth=login`. If OpenEMR's login flow on this
   deploy differs (some versions post to `interface/main/main_screen.php` with a
   pre-fetched login CSRF, or require `new_login_session_management`), adjust
   `login()` until the session cookie is set.
3. Confirm the **CSRF form-token source**. `_ensure_csrf()` scrapes
   `name="csrf_token_form" value="..."` from `dashboard.php`. If that page
   doesn't render one for the logged-in user (dashboard is admin-gated), scrape
   it from a page the clinician role renders instead (e.g. the chat UI page that
   `ModuleManagerListener` wires into the patient menu). Point `_ensure_csrf` at
   whichever page actually embeds the token.
4. Smoke test live:
   ```bash
   PYTHONPATH=src python -m agentforge.cli redteam --category prompt_injection --max-attempts 4
   ```
   You should see real target responses (not the mock). Pick a real `pid` that
   exists on the deploy with `--pid`.

> Until step 0 passes, everything still runs offline via `--dry-run` (mock
> target), so you are never blocked from developing the other agents.

## What is DONE (all committed on the branch, tests green)

| Artifact | Path | Notes |
|---|---|---|
| Threat model | `THREAT_MODEL.md` | ~500-word summary + full surface map, OWASP-mapped. Grounded in real recon of the module. |
| Architecture | `ARCHITECTURE.md` | 4-agent design, mermaid diagram, orchestration, judge-drift control, build-vs-configure, AI-use disclosure. |
| Users | `USERS.md` | AppSec / Eng Lead / CISO + UC1–UC6. |
| Contracts (v1) | `contracts/v1/*.schema.json` | Orchestrator→RedTeam, RedTeam→Judge, Judge→Doc, typed errors. Versioning policy in `contracts/README.md`. |
| Contract tests | `tests/test_contracts.py`, `test_models_roundtrip.py` | schemas valid + golden examples + model round-trips. |
| Seed eval suite | `evals/cases/*.json` (22 cases, 5 categories) | OWASP-tagged (web A01/03/04/05/06/07/09/10 + LLM01/02/04/05/06/07/08); each maps to boundary/invariant/regression dimension and carries its observed live/probe result. `evals/schema.json` enforces shape + unique ids. |
| Red Team agent | `src/agentforge/agents/redteam.py` | generate + 4 deterministic mutation operators (+ optional LLM variants); drives multi-turn; emits contract-valid `AttackAttempt`. |
| Target client | `src/agentforge/target/client.py` | `OpenEmrTargetClient` (**verified live**, see below) + `MockTargetClient` (offline, defended/leaky policies). |
| **Judge agent** | `src/agentforge/agents/judge.py` | independent verdict maker; deterministic rubric `RUBRIC_VERSION=1.0.0` (leak vs defense markers) + optional LLM refinement; ground-truth drift check; `critical`/`uncertain` → `escalate_to_human`. |
| **Ground-truth set** | `evals/ground_truth.json` | 4 labeled attempts (2 real defended + 2 synthetic leaks) that pin the rubric; drift check rejects a rubric that mislabels them. |
| **Documentation agent** | `src/agentforge/agents/documentation.py` | success `Verdict` → `VulnerabilityReport` (OWASP-tagged, reproducible) + regression case (invariant, not string match); data-quality gates; human gate on `critical`. |
| **Orchestrator** | `src/agentforge/agents/orchestrator.py` | scores (category×surface) by `base_priority·coverage_gap + open-severity`; emits contract-valid `AttackCampaignDirective`; budget/halt (`budget_exceeded`, `no_findings_in_window`); regression trigger on target-version change. |
| **Observability store** | `src/agentforge/observability/store.py` | append-only JSONL keyed by `correlation_id`; deterministic rollups (coverage, pass-rate, open findings, cost, timeline); the Orchestrator's input. |
| **Regression harness** | `src/agentforge/regression.py` | replays confirmed exploits; pass == invariant holds (target defended), not a string match; sibling replay across a category. |
| **Pipeline (LangGraph)** | `src/agentforge/pipeline.py` | wires Orchestrator→RedTeam→Judge→Documentation→Observability over the typed messages; dependency-free `run_campaign` runner + optional `build_langgraph` StateGraph. |
| CLI | `src/agentforge/cli.py` | `redteam`, `campaign` (full loop), `judge` (offline re-judge), `dashboard` (observability rollup); `--dry-run` offline mode on all. |
| Tests | `tests/` | contracts, models, redteam e2e, **observability, judge (+drift), documentation, orchestrator+pipeline, regression**. |

Run everything: `cd agentforge && PYTHONPATH=src pytest tests/ -q` → **39 passed**.
Run the full loop live: `PYTHONPATH=src python -m agentforge.cli campaign --pid 1 --rounds 2 --max-attempts 4`.

## What is NEXT (priority order)

### MVP — DONE ✅
The MVP hard gates are met: threat model ✅, evals ✅, one agent role live ✅,
architecture ✅, and Step 0 (Red Team firing against the live target) ✅ with
captured evidence. All four agents are now built beyond the MVP bar.
Remaining human-only action: **submit the deployed URL with the checkpoint**
(target: `https://abundant-art-production-d560.up.railway.app`).

### For the Final (Wed–Fri) — mostly DONE
Items 4–9 (Judge, Orchestrator, Documentation, Regression harness, Observability
store, LangGraph wiring) are implemented and tested. Since then:

10. **Deterministic probes** — ✅ DONE. `src/agentforge/probes.py` +
    `cli.py probe`. Runs live and found **3 real findings** (health.php version
    disclosure, ready.php dependency enumeration, ready.php rate-limiter
    fail-open) with the two auth-required invariants holding. Reported in
    `docs/VULNERABILITY_REPORTS.md`.
11. **LLM wiring for Judge/Red Team** — ✅ DONE (code + tests). `agents/llm.py`
    is a provider-agnostic OpenAI-compatible adapter: `LlmJudge.classify` and
    `LlmRedTeam.variants`, wired via `--use-llm-judge` / `--use-llm-redteam`,
    both fail-soft to the deterministic core. NOTE: could not be exercised live
    from this environment — egress is scoped to `*.up.railway.app`, so external
    LLM APIs return `403 CONNECT` and no key is present. Run it where a model
    endpoint + egress exist (local Ollama for Red Team; a frontier key for the
    independent Judge).
12. **Longer live campaigns for real findings** — still open. The deployed build
    defends the seeded LLM attacks (`pass_rate 1.00`). To surface genuine
    LLM-semantic findings, turn on `--use-llm-redteam` for novel mutations, add
    the prompt-only-refusal categories the threat model flags as unguarded
    (`AF-EXF-001`, `AF-ID-001`), and run more Orchestrator rounds on a larger
    budget.

### Submission artifacts — DONE (except the video recording)
- **≥3 vulnerability reports** → `docs/VULNERABILITY_REPORTS.md` (3 confirmed).
- **AI cost analysis** → `docs/COST_ANALYSIS.md` (100/1K/10K/100K).
- **Triage exercise** → `docs/TRIAGE_EXERCISE.md` (10-finding pass).
- **Baseline perf + 100-case load test** → `docs/LOAD_TEST.md` + `loadtest.py`
  + `cli loadtest` (real numbers captured; bottleneck identified).
- **ATO-style evidence packet** → `docs/ATO_EVIDENCE.md`.
- **Integration packet** → `docs/INTEGRATION_PACKET.md`.
- **Live-run evidence** → `docs/LIVE_RUN_EVIDENCE.md`.
- **Local GUI** → `src/agentforge/web.py` (`cli web`), stdlib-only dashboard.
- **Demo video** → script/storyboard ready in `docs/DEMO_SCRIPT.md`; the
  recording itself is the one human task left.
- **Social post** → drafts ready in `docs/SOCIAL_POST.md` (tag @GauntletAI).

### The only human tasks left
1. Submit the MVP (repo/branch + deployed URL) — content is all in place.
2. Record the 3–5 min demo from `docs/DEMO_SCRIPT.md` (run `cli web`, follow the
   shot list) and post it with `docs/SOCIAL_POST.md`.
3. (Optional) run a longer live `--use-llm-redteam` campaign where an LLM
   endpoint is reachable, to push for deeper LLM-semantic findings.

### Submission artifacts still owed (Final)
- **≥3 vulnerability reports** (Documentation output; format in ARCHITECTURE).
- **AI cost analysis** at 100/1K/10K/100K runs → `docs/COST_ANALYSIS.md`
  (there's an existing co-pilot `ops/cost-analysis.md` to reference for style).
- **Triage exercise** — simulated 10-finding scan report (crit/high/med/false-pos)
  with validate/remediate/defer/document decisions.
- **ATO-style evidence packet** + **integration packet** + baseline perf +
  100-case load test with identified bottleneck.
- **Demo video (3–5 min)** + **social post** (final only, tag @GauntletAI).

## Credentials / config the next agent needs

Fill `agentforge/.env` (copy from `.env.example`):
- `AGENTFORGE_TARGET_USERNAME` / `_PASSWORD` — the deploy's login (try `admin`/`pass`).
- `REDTEAM_*` — a **local/open** model endpoint (Ollama `llama3.1:8b` by
  default) so the Red Team won't refuse offensive prompts and stays cheap. If no
  local model is available, the Red Team still runs on the deterministic
  mutation operators.
- `JUDGE_*` — an **independent** frontier model API key (kept separate from the
  Red Team by design). Needed once you build the Judge (item 4).

## Gotchas (from recon — see THREAT_MODEL.md)

- **`agent.php` is the soft target:** tools are live there and it is **not**
  per-user rate-limited (only $50/day, $10/hr caps + circuit breaker). Best
  surface for tool/DoS tests — but that means *you* can burn the target's budget
  too; keep `--max-attempts` low on live runs and respect the breaker.
- **Chat tools are dormant** — don't waste tool-tampering attempts on `chat.php`.
- **Prompt-only refusals** (other-patient, general-medical, diagnosis) have **no
  verifier backstop** — these are the highest-yield live targets (`AF-EXF-001`,
  `AF-ID-001`).
- **Don't over-invest in the guarded invariants** (forged pid, fact-citation);
  recon shows they're structural. A couple of invariant tests each, then move on.
- **Never disable TLS / unset the proxy.** A `403 CONNECT` is a policy denial,
  not a bug to route around — fix the egress allowlist instead.

## Branch & push

All work is on `claude/agentforge-adversarial-platform-up8w9m`. Commit with
Conventional Commits + `Assisted-by: Claude Code`. Push with
`git push -u origin claude/agentforge-adversarial-platform-up8w9m`. Do not open
a PR unless asked.
