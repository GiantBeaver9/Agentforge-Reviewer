# AgentForge — Adversarial AI Security Platform

A multi-agent system that continuously discovers, evaluates, documents, and
regression-guards vulnerabilities in the OpenEMR **Clinical Co-Pilot**
(`oe-module-clinical-copilot`).

- **Target under test (live):** https://abundant-art-production-d560.up.railway.app
- **AgentForge platform:** **not** hosted at a public URL by default — it is the
  *attacker*, so it runs locally (`… cli` / `… web` dashboard) or as your own
  private service. Only the **target** is a standing deployment; stand AgentForge
  up yourself in minutes via [`DEPLOY.md`](DEPLOY.md) (Railway/Docker), then reach
  it at the URL your host assigns. Deliberately not left publicly running: an
  open panel can launch live campaigns, so it ships auth-gated and self-hosted.
- **Architecture:** [`ARCHITECTURE.md`](ARCHITECTURE.md) — the 4-agent design
- **Threat model:** [`THREAT_MODEL.md`](THREAT_MODEL.md) — the attack surface
- **Users:** [`USERS.md`](USERS.md)
- **Contracts:** [`contracts/`](contracts/) — versioned inter-agent JSON Schemas
- **Seed attack suite:** [`evals/`](evals/) — 29 cases across all 5 attack
  categories (incl. `state_corruption`), **tagged** across all 20 OWASP items
  (web A01–A10, LLM01–LLM10). **19 of 29 are executed** (15 pass / 2 fail / 2
  partial); the other **10 are honestly labeled `not_run`** — they target surfaces
  (ingest/doc, concurrency, SSRF collaborator) that need harnesses not yet wired,
  and each says so in-file. Coverage is *tagged everywhere, executed where the
  loop reaches*, not executed everywhere.
- **Deploy it standalone:** [`DEPLOY.md`](DEPLOY.md) — run AgentForge as its own
  Railway service, pointed at any OpenEMR instance via env vars
- **Continue this build:** [`HANDOFF.md`](HANDOFF.md)

## Status

| Component | State |
|---|---|
| Threat model | ✅ complete |
| Inter-agent contracts (v1) + tests | ✅ complete, tests green |
| Seed eval suite (5 categories, OWASP-tagged) | ✅ complete |
| Red Team agent | ✅ **verified live**; **closed feedback loop** (Judge verdict → ~10 variants) + **in-conversation multi-turn adaptation** (turn N reacts to the target's turn N-1) |
| Eval scoring | ✅ **reproducible + judge-independent invariant** (`agentforge eval`); committed `evals/OFFLINE_BASELINE.json`, CI-diffed; `subtle` leak proves non-circularity |
| Judge/Red-Team independence | ✅ **code-enforced** — campaign refuses generator==grader unless `--allow-same-model` |
| Target HTTP client (OpenEMR auth) | ✅ **auth + CSRF handshake verified live** |
| Judge agent (rubric `1.0.0` + ground-truth drift check) | ✅ complete, tests green |
| Orchestrator (coverage/severity scoring + budget/halt) | ✅ complete, tests green |
| Documentation agent (report + regression case) | ✅ complete; confirmed exploits **promoted into the live regression suite** |
| Human-approval gate (real, enforced) | ✅ `publish()`/`publish` CLI **refuse** a critical without a named approver (not a label) |
| Regression harness (invariant replay + siblings + cross-category) | ✅ **3-way** held/regressed/inconclusive (uncertain ≠ pass); triggered in-loop + `regression` CLI |
| Typed errors on the wire | ✅ `budget_exceeded`/`no_findings_in_window`/`target_unreachable`/`judge_timeout`/`regression_detected` emitted via schema-validated `AgentError` |
| Cost accounting (per-attempt → budget breaker + **per-component breakdown**) | ✅ drives `budget_exceeded` halt; `cost_breakdown()` splits target/Judge + per-attempt rate; LLM Judge billed from **real token usage** when reported |
| Contract validation (producer **and** consumer on all 3 boundaries) | ✅ directive now has a pydantic model + consumer-side check, tests green |
| PHI redaction on persisted evidence + dashboard | ✅ clinical values scrubbed at write time (`redact.py`); attack marker retained |
| Observability (per-version pass/fail + finding **lifecycle** open→resolved) | ✅ lifecycle driven live by regression outcome; answers all 6 required questions |
| History store (SQLite/Postgres): migrations + **indexed `findings`** (severity/category) | ✅ `docs/migrations/`; index-backed triage queries |
| CI (`.github/workflows`) | ✅ suite + offline smoke + regression-scan SLO |
| LangGraph runtime (4 agents over typed edges) | ✅ optional; invocable via `campaign --use-langgraph`, plain runner canonical |

All four agents and the deterministic substrate are implemented — **143 passing
tests** — and the full loop has been run live against the deployed co-pilot
(which defended the seeded attacks). The closed feedback loop, exploit promotion,
cost-based budget breaker, 3-way regression, consumer-side contract validation,
and Judge-drift gate are all wired into the running campaign (not just
unit-tested); see [`docs/INTEGRATION_PACKET.md`](docs/INTEGRATION_PACKET.md) for
ADRs and a single end-to-end correlation-id trace, and
[`docs/migrations/`](docs/migrations/) for the schema-versioning policy.

## Local GUI (web dashboard)

A pure-standard-library control panel — **no extra dependencies** — to launch
campaigns/probes and watch results in a browser:

```bash
cd agentforge
PYTHONPATH=src python -m agentforge.web        # then open http://127.0.0.1:8800
# or: PYTHONPATH=src python -m agentforge.cli web --port 8800
```

From the dashboard you can launch a campaign (offline **dry-run** by default —
unbounded, up to 100 rounds/attempts to generate test data — or live against the
target with enforced attempt/round/budget caps), run the deterministic **probe**
sweep, run the **baseline load test** (latency/throughput over a concurrency
sweep), watch coverage/pass-rate/findings update live, and click into any past
run's detail. Hover the form fields (ⓘ) for what each control does and its caps.
It's the same agents and observability store as the CLI, just with buttons — and
it doubles as the demo view.

## Quick start (CLI)

```bash
cd agentforge
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Run the contract + agent tests (no network needed):
PYTHONPATH=src pytest tests/ -q

# Run the FULL multi-agent loop against the OFFLINE mock target (no network):
PYTHONPATH=src python -m agentforge.cli campaign --dry-run --mock-policy defended
# Model a regressed build that leaks, to see the Judge confirm + Docs report it:
PYTHONPATH=src python -m agentforge.cli campaign --dry-run --mock-policy leaky

# Red Team only, or re-judge / inspect a captured run:
PYTHONPATH=src python -m agentforge.cli redteam --dry-run --category prompt_injection
PYTHONPATH=src python -m agentforge.cli judge runs/<campaign>.attempts.jsonl
PYTHONPATH=src python -m agentforge.cli dashboard runs/<campaign>.observability.jsonl

# Deterministic HTTP probes against the unauthenticated surface (runs live):
PYTHONPATH=src python -m agentforge.cli probe

# Opt into real models (needs endpoints + egress): independent LLM Judge and
# LLM-generated Red Team mutations (both fail soft to the deterministic core):
PYTHONPATH=src python -m agentforge.cli campaign --use-llm-judge --use-llm-redteam
```

> **Deterministic-first is deliberate, not a gap.** The default run is $0,
> reproducible, and needs no model or egress — the deterministic cores (rubric,
> scoring, mutation operators, probes, regression) carry a full campaign so CI and
> egress-restricted sandboxes work out of the box. The LLM path is a real opt-in
> (`--use-llm-*`), and it is **exercised end-to-end by the test suite** through the
> actual adapters over a fake transport (`tests/test_llm_e2e.py`), not only by
> stubbing `.classify`/`.variants`. Turn the models on where judgement quality pays
> (see `docs/COST_ANALYSIS.md`); the deterministic path is the safety net, not a
> placeholder.

## Reports & analysis (`docs/`)

- [`docs/VULNERABILITY_REPORTS.md`](docs/VULNERABILITY_REPORTS.md) — 3 confirmed
  live findings (info disclosure ×2, rate-limit fail-open) + resilience summary.
- [`docs/COST_ANALYSIS.md`](docs/COST_ANALYSIS.md) — AI spend at 100/1K/10K/100K,
  per-tier architecture changes, and dev-spend to date (~$0 AI).
- [`docs/TRIAGE_EXERCISE.md`](docs/TRIAGE_EXERCISE.md) — 10-finding triage pass.
- [`docs/LOAD_TEST.md`](docs/LOAD_TEST.md) — baseline perf + 100-req load test + bottleneck.
- [`docs/ATO_EVIDENCE.md`](docs/ATO_EVIDENCE.md) — ATO-style control/evidence packet.
- [`docs/INTEGRATION_PACKET.md`](docs/INTEGRATION_PACKET.md) — CI/CD + ops integration.
- [`docs/DATA_MODEL.md`](docs/DATA_MODEL.md) — the platform's own exploit-data stores + write-access controls.
- [`docs/evidence/`](docs/evidence/) — committed redacted trace + load sample (reproducible artifacts).
- [`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md) — 3–5 min demo storyboard.
- [`docs/SOCIAL_POST.md`](docs/SOCIAL_POST.md) — social post drafts (tag @GauntletAI).
- [`docs/LIVE_RUN_EVIDENCE.md`](docs/LIVE_RUN_EVIDENCE.md) — verified live-run log.

## Run against the live target

Requires (a) network egress to the Railway host and (b) target credentials.

```bash
cp .env.example .env      # fill in AGENTFORGE_TARGET_USERNAME/PASSWORD (admin/pass on the dev deploy)
# Full loop (Orchestrator -> Red Team -> Judge -> Documentation), low budget:
PYTHONPATH=src python -m agentforge.cli campaign --pid 1 --rounds 2 --max-attempts 4
```

> The live client performs the OpenEMR login + CSRF-token handshake (verified
> against the deployed module's own bruno auth flow): login posts to
> `interface/main/main_screen.php?auth=login`, and the CSRF form token is scraped
> from the module's `doc.php?pid=<pid>` chat panel. Keep `--max-attempts` low on
> live runs — `agent.php`/`chat.php` run real LLM calls behind a shared budget
> breaker. See [`HANDOFF.md`](HANDOFF.md) → "Step 0".

## Layout

```
agentforge/
  THREAT_MODEL.md ARCHITECTURE.md USERS.md HANDOFF.md README.md
  contracts/v1/          # versioned inter-agent message schemas + errors
  evals/cases/           # seed adversarial suite (JSON, schema-validated)
  evals/ground_truth.json# labeled attempts pinning the Judge rubric (drift check)
  src/agentforge/
    config.py            # env -> typed config
    contracts/models.py  # pydantic models mirroring the JSON Schemas
    target/client.py     # OpenEMR live client (verified) + offline mock
    observability/store.py  # append-only run log + deterministic rollups
    agents/redteam.py    # Red Team: generate + mutate + drive target
    agents/judge.py      # Judge: independent verdict + rubric + drift check
    agents/documentation.py # Documentation: report + regression case + human gate
    agents/orchestrator.py  # Orchestrator: scoring + budget/halt + regression trigger
    agents/llm.py        # optional LLM adapters for Judge (.classify) + Red Team (.variants)
    probes.py            # deterministic HTTP probes (unauth surface, IDOR, rate-limit)
    costs.py             # deterministic per-attempt cost model (budget breaker input)
    regression.py        # invariant-based regression replay (+ cross-category)
    pipeline.py          # wires the 4 agents (LangGraph-compatible) + drift/regression/cost gates
    web.py               # local web dashboard (stdlib only) — GUI control panel
    loadtest.py          # baseline load test of the cheap unauth surface
    redact.py            # PHI redaction for persisted evidence + dashboard
    evalrunner.py        # reproducible eval scoring via a judge-INDEPENDENT invariant
    cli.py               # redteam|campaign|judge|eval|regression|publish|lifecycle|dashboard|probe|web|loadtest
  tests/                 # contracts, models, redteam, observability, judge, documentation,
                         # orchestrator+pipeline, regression, wiring, adaptive, llm-e2e, evalrunner,
                         # versioning/lifecycle, typed-errors, redact, fix-validation (143 green)
```
