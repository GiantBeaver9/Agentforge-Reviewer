# AgentForge — Demo Script (3–5 min)

A shot-by-shot script for the submission video. It uses the **local web
dashboard** as the visual so you never touch a terminal on camera. Total runtime
~4 min. Everything below has been verified to work; the only prep is one command.

## Before you hit record (2 min prep)

```bash
cd agentforge
# creds for the LIVE parts (dry-run needs nothing):
cp .env.example .env    # set AGENTFORGE_TARGET_USERNAME=admin / _PASSWORD=pass
PYTHONPATH=src python -m agentforge.cli web      # open http://127.0.0.1:8800
```
Have two browser tabs ready: the dashboard, and the repo (or `ARCHITECTURE.md`)
for the one architecture beat.

---

## Shot list

### 0:00–0:30 — The problem (talking head or architecture diagram)
> "Clinical AI co-pilots touch PHI and make clinical suggestions. How do you know
> one stays in its lane — every deploy, not just once? AgentForge is a multi-agent
> system that continuously red-teams our co-pilot and produces *verified*
> vulnerability reports."

Show the mermaid diagram in `ARCHITECTURE.md` for 5 seconds. One line:
> "Four agents, and the key move: the agent that *generates* attacks is never the
> one that *grades* them — different models, so no conflict of interest."

### 0:30–1:15 — Live campaign against the real target (dashboard)
On the dashboard: **uncheck "Dry-run"**, set category = `data_exfiltration`,
rounds 2, attempts 4. Click **Launch campaign**.
> "This is running live against our deployed co-pilot on Railway. The Orchestrator
> picks the highest-value attack surface, the Red Team drives multi-turn attacks,
> and an independent Judge rules on each one."

While it runs, narrate the live log. When it finishes, point at the coverage row:
> "Pass rate 1.00 — the co-pilot *defended* every cross-patient exfiltration
> attempt. It answered: 'I can only provide information for the patient pinned to
> this conversation.' That's the result we want, and the Judge confirms it rather
> than us taking the model's word for it."

### 1:15–2:15 — Finding real vulnerabilities (probe sweep)
Click **Run probe sweep**.
> "The LLM attacks are only half the platform. These are deterministic probes of
> the classic web surface — cheap, no LLM cost."

When it completes, point at the three findings:
> "Three confirmed findings on the live target: the readiness endpoint enumerates
> internal dependencies to anonymous callers, the liveness endpoint leaks the
> build version, and — the real one — the per-IP rate limiter fails open under
> load. And notice the auth checks *held*: unauthenticated requests get nothing."

### 2:15–3:00 — Why it's trustworthy (Judge independence + regression)
Back to the repo, show `evals/ground_truth.json` for 3 seconds.
> "Two things keep this honest. One: the Judge is drift-checked against a
> ground-truth set of labeled attacks every run — if a rubric change mislabels a
> known case, it's rejected. Two: every confirmed exploit becomes a deterministic
> regression case that passes only when the *safe behavior invariant* holds, not
> a string match — so a reworded-but-still-broken response still fails."

### 3:00–3:45 — Cost & scale (one slide or the cost doc)
Show the `COST_ANALYSIS.md` table.
> "Cost scales with a decision: the high-volume attack generation runs on a local
> model — effectively free — and we spend a frontier model only where judgment
> matters. 100,000 attempts lands around $240, and hard budget caps stop a run
> before it overspends. The load test found the target's real ceiling is
> budget-bound, not throughput-bound."

### 3:45–4:00 — Close
> "Threat model, four working agents verified live, three real findings, a
> regression net, a cost model, and a one-command local dashboard. AgentForge
> turns 'is our clinical AI still safe?' into a question you can answer on every
> deploy. Thanks — and thanks @GauntletAI."

---

## If you want a zero-risk take
Do the whole thing with **Dry-run checked** and mock policy = **leaky**. It
produces confirmed findings + reports on camera (no target budget spent, no
network needed), and the narration barely changes — say "modeling a regressed
build that leaks" instead of "live target." Record the live version first; keep
the dry-run as a safety net.

## Tips
- Screen-record at 1280×720+; the dashboard is responsive and dark/light aware.
- The live campaign takes ~60–90 s (multi-turn LLM); either let it run while you
  talk, or start it just before recording and cut to it "finishing."
- Keep it under 5:00 — the rubric caps it there.
