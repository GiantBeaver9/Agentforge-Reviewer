# AgentForge — Adversarial AI Security Platform

A multi-agent system that continuously discovers, evaluates, documents, and
regression-guards vulnerabilities in the OpenEMR **Clinical Co-Pilot**
(`oe-module-clinical-copilot`).

- **Target under test:** https://abundant-art-production-d560.up.railway.app
- **Architecture:** [`ARCHITECTURE.md`](ARCHITECTURE.md) — the 4-agent design
- **Threat model:** [`THREAT_MODEL.md`](THREAT_MODEL.md) — the attack surface
- **Users:** [`USERS.md`](USERS.md)
- **Contracts:** [`contracts/`](contracts/) — versioned inter-agent JSON Schemas
- **Seed attack suite:** [`evals/`](evals/) — 17 cases across 5 categories
- **Deploy it standalone:** [`DEPLOY.md`](DEPLOY.md) — run AgentForge as its own
  Railway service, pointed at any OpenEMR instance via env vars
- **Continue this build:** [`HANDOFF.md`](HANDOFF.md)

## Status

| Component | State |
|---|---|
| Threat model | ✅ complete |
| Inter-agent contracts (v1) + tests | ✅ complete, tests green |
| Seed eval suite (5 categories, OWASP-tagged) | ✅ complete |
| Red Team agent | ✅ **verified live** against the deployed target |
| Target HTTP client (OpenEMR auth) | ✅ **auth + CSRF handshake verified live** |
| Judge agent (rubric `1.0.0` + ground-truth drift check) | ✅ complete, tests green |
| Orchestrator (coverage/severity scoring + budget/halt) | ✅ complete, tests green |
| Documentation agent (report + regression case + human gate) | ✅ complete, tests green |
| Regression harness (invariant replay + siblings) | ✅ complete, tests green |
| Observability store (append-only, deterministic rollups) | ✅ complete, tests green |
| LangGraph pipeline wiring (4 agents over typed edges) | ✅ complete (`pipeline.py`) |

All four agents and the deterministic substrate are implemented — **39 passing
tests** — and the full loop has been run live against the deployed co-pilot
(which defended the seeded attacks). Remaining work is submission packaging
(cost analysis, triage exercise, ATO/load evidence, demo) — see
[`HANDOFF.md`](HANDOFF.md).

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

## Reports & analysis (`docs/`)

- [`docs/VULNERABILITY_REPORTS.md`](docs/VULNERABILITY_REPORTS.md) — 3 confirmed
  live findings (info disclosure ×2, rate-limit fail-open) + resilience summary.
- [`docs/COST_ANALYSIS.md`](docs/COST_ANALYSIS.md) — AI spend at 100/1K/10K/100K.
- [`docs/TRIAGE_EXERCISE.md`](docs/TRIAGE_EXERCISE.md) — 10-finding triage pass.
- [`docs/LOAD_TEST.md`](docs/LOAD_TEST.md) — baseline perf + 100-req load test + bottleneck.
- [`docs/ATO_EVIDENCE.md`](docs/ATO_EVIDENCE.md) — ATO-style control/evidence packet.
- [`docs/INTEGRATION_PACKET.md`](docs/INTEGRATION_PACKET.md) — CI/CD + ops integration.
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
    regression.py        # invariant-based regression replay
    pipeline.py          # wires the 4 agents (LangGraph-compatible)
    web.py               # local web dashboard (stdlib only) — GUI control panel
    loadtest.py          # baseline load test of the cheap unauth surface
    cli.py               # redteam | campaign | judge | dashboard | probe | web | loadtest
  tests/                 # contracts, models, redteam, observability, judge,
                         # documentation, orchestrator+pipeline, regression (39 green)
```
