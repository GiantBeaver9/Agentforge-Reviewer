# AgentForge — Integration Packet

How AgentForge drops into an existing SDLC and ops stack to run continuously
against the Clinical Co-Pilot. It is built to be integrated, not just demoed:
typed contracts at every seam, a deterministic core with defined exit codes, and
an append-only store other tools can read.

## 1. Integration points

| Seam | Interface | Consumer |
|---|---|---|
| Target under test | Authenticated HTTP (session + CSRF), one pinned host | `target/client.py` |
| Red Team model | OpenAI-compatible `/chat/completions` (`REDTEAM_*`) | `agents/llm.py` |
| Judge model (independent) | OpenAI-compatible `/chat/completions` (`JUDGE_*`) | `agents/llm.py` |
| Inter-agent messages | Versioned JSON Schema (`contracts/v1/*`) | any consumer |
| Run history / metrics | Append-only JSONL, keyed by `correlation_id` | dashboards, SIEM, next Orchestrator run |
| Findings | `runs/*.reports.json` (structured) + `docs/VULNERABILITY_REPORTS.md` | ticketing, triage |

Every seam is typed and versioned, so a downstream system (a SIEM, a ticketing
bot, a metrics pipeline) integrates against a schema, not a scrape.

## 2. CI/CD integration

AgentForge fits a pipeline in three tiers, cheapest-first:

**Tier 1 — every PR (fast, no network, no cost).**
```yaml
# .github/workflows/agentforge.yml (sketch)
- run: cd agentforge && PYTHONPATH=src pytest tests/ -q
- run: cd agentforge && PYTHONPATH=src python -m agentforge.cli campaign \
        --dry-run --mock-policy leaky --rounds 1 --max-attempts 4
```
Proves the platform and contracts are green and the pipeline wiring works,
entirely offline against the mock target.

**Tier 2 — on deploy to staging (cheap live probes).**
```yaml
- run: cd agentforge && PYTHONPATH=src python -m agentforge.cli probe
- run: cd agentforge && PYTHONPATH=src python -m agentforge.cli loadtest --n 100
```
Deterministic unauth-surface probes + a perf baseline. No LLM spend. Fail the
job if a new probe finding appears (see exit-code hook below).

**Tier 3 — scheduled (nightly) against the deployed target (bounded LLM spend).**
```yaml
# cron: nightly
- run: cd agentforge && PYTHONPATH=src python -m agentforge.cli campaign \
        --pid 1 --rounds 2 --max-attempts 4 --use-llm-redteam
```
The Orchestrator enforces the budget cap and halts on `no_findings_in_window`, so
a nightly run has a known cost ceiling.

**Gating.** Wrap any tier in a check that greps the run's `open_findings`/probe
`secure=false` count and exits non-zero on a *new* finding (diff against the last
committed baseline), so a regression blocks the deploy. Confirmed exploits are
auto-promoted to regression cases (`documentation.py`), so the suite grows itself.

## 3. Regression-on-version-change

The Orchestrator detects a target deploy-id change (`target_changed`) and signals
`regression_detected`; wire that to trigger the regression harness
(`regression.py`) before any new exploration. Each regression case passes only
when its **invariant** holds (not a string match), so a reworded-but-still-broken
response still fails — the correct behavior for catching silent regressions.

## 4. Ops / runbook

| Task | Command |
|---|---|
| Launch the control panel (GUI) | `python -m agentforge.cli web` → http://127.0.0.1:8800 |
| One offline smoke campaign | `... campaign --dry-run --mock-policy leaky` |
| Live probe sweep | `... probe` |
| Bounded live campaign | `... campaign --pid 1 --rounds 2 --max-attempts 4` |
| Inspect a run | `... dashboard runs/<id>.observability.jsonl` |
| Re-judge an old run | `... judge runs/<id>.attempts.jsonl` |
| Perf baseline | `... loadtest --n 100` |

**Secrets:** `agentforge/.env` (git-ignored) holds `AGENTFORGE_TARGET_*` and the
`REDTEAM_*`/`JUDGE_*` model endpoints. In CI, inject these as pipeline secrets;
never commit them. The client trusts the standard CA bundle and never disables
TLS.

**Alerting hooks:** the observability store answers open-findings, pass-rate, and
cost; a scheduled job can diff `summary()` against the last run and page on a new
critical or a pass-rate drop in any (category × surface) cell.

## 5. Dependencies & rate limits

| Dependency | Auth | Limit handling |
|---|---|---|
| Clinical Co-Pilot (target) | OpenEMR session + CSRF | respect 60 turns/user/hr; back off on 429/breaker; live attempts kept low |
| Red Team LLM (local) | endpoint key | local; effectively unlimited |
| Judge LLM (frontier) | API key | queue + backoff on `rate_limited`; fail-soft to deterministic rubric |

Core (contracts, probes, load test, observability, dashboard, deterministic
Judge/Red Team cores) requires **only Python 3.11+ stdlib + `httpx`/`pydantic`/
`jsonschema`** — no model, no network — so Tier‑1 CI needs no external service.
The LLM adapters are optional and fail soft, so their outage degrades quality,
never availability.

## 6. Packaging

- **Self-contained** under `agentforge/` — no coupling to the OpenEMR app it
  tests beyond the HTTP interface.
- **Runtime:** `pip install -r requirements.txt` (or just the core deps for
  Tier 1). The GUI and load test are stdlib-only.
- **Artifacts:** `runs/` (git-ignored, ephemeral) for machine output; `docs/` for
  the human-facing reports. Point CI to archive `runs/*.json` as build artifacts.
