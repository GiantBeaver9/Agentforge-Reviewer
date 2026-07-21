# AgentForge — Social Post (draft)

Pick the platform, paste, attach the demo video, post. Tag **@GauntletAI**.
Swap `<demo-link>` / `<repo-link>` before posting.

---

## Option A — X / LinkedIn (medium)

> How do you know a clinical AI co-pilot stays in its lane — on *every* deploy,
> not just once?
>
> I built **AgentForge**: a multi-agent system that continuously red-teams an
> OpenEMR clinical co-pilot and produces *verified* vulnerability reports.
>
> The core idea: the agent that **generates** attacks is never the one that
> **grades** them. A low-trust local model attacks; an independent frontier-model
> Judge rules success/fail against a versioned rubric; a Documentation agent
> writes the report — behind a human gate for anything critical.
>
> Run live against the deployed target, it:
> ✅ confirmed the co-pilot **defends** cross-patient PHI exfiltration and
>    prompt-injection (pass rate 1.00)
> 🔎 found 3 real issues on the classic web surface (info disclosure + a rate
>    limiter that fails open)
> 🧪 turns every confirmed exploit into a deterministic regression test that
>    checks the *safe-behavior invariant*, not a string match
>
> Cheap by design: high-volume attack generation runs on a local model (~free);
> the frontier model is spent only where judgment matters. ~$240 for 100k attempts,
> with hard budget caps.
>
> Plus a one-command local dashboard to drive it all.
>
> Week 3 of the @GauntletAI gauntlet. Demo 👇
> <demo-link>  ·  <repo-link>
>
> #AISecurity #LLMSecurity #HealthcareAI #RedTeam

---

## Option B — X (short / thread starter)

> Built **AgentForge** for @GauntletAI week 3: 4 AI agents that continuously
> red-team a clinical co-pilot and produce *verified* vuln reports.
>
> Key: the attacker model never grades itself — an independent Judge does.
>
> Live results: co-pilot defended every PHI-exfil attempt; found 3 real web-surface
> bugs; every exploit becomes a regression test.
>
> Demo 👇 <demo-link>

Thread follow-ups (optional):
> 2/ Why separate the Judge? An agent that invents *and* blesses its own attacks
> has a conflict of interest by construction. Different model, different context,
> versioned rubric, drift-checked against a ground-truth set every run.
>
> 3/ Cost scales with a decision, not a surprise: local model does the expensive
> high-volume generation (~free); frontier model only judges. Hard budget caps +
> a "stop if no findings" halt. ~$240 / 100k attempts.
>
> 4/ Deterministic where it can be (unauth probes, regression replay, budget math),
> LLM where it must be (creative attacks, natural-language judgment, prose reports).
> Cheaper, reproducible, doesn't drift.

---

## Option C — one-liner (for a reply / caption)

> AgentForge: 4 agents that continuously red-team a clinical AI co-pilot, with an
> independent Judge so the attacker never grades itself. Verified findings +
> auto-generated regression tests. @GauntletAI week 3. <demo-link>

---

### Notes
- Lead with the problem (trust in clinical AI), not the tech stack.
- The "generator ≠ grader" line is the memorable hook — keep it.
- Attach the 3–5 min demo (see `DEMO_SCRIPT.md`). Video > text for reach.
- Don't name real patient data or paste internal URLs; keep the target link to the
  repo/demo, not the raw deploy, unless you intend it to be public.
