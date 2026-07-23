# AgentForge — Multi-Agent Adversarial Evaluation Platform

## Summary

AgentForge is a multi-agent system that continuously discovers, evaluates,
documents, and regression-guards vulnerabilities in the OpenEMR Clinical
Co-Pilot. It is deliberately **not** a single agent or a linear pipeline:
attack generation and attack evaluation are separated into different agents on
different models because an agent that both generates and grades its own attacks
has a conflict of interest by construction. Four agents, each with a distinct
role, trust level, and model, coordinate over **versioned JSON-Schema messages**
(see `/contracts`); a deterministic substrate (exploit DB, regression harness,
observability store) sits underneath them.

**The four agents.**
1. **Orchestrator** (trust: high; deterministic-first). Reads the observability
   state — coverage per category, open high-severity findings, suspected
   regressions, budget spent — and decides the next campaign: which surface and
   category the Red Team probes, with what budget. It owns cost/halt decisions
   and triggers regression runs when the target version changes. It is mostly
   rules over metrics, not an LLM, so its decisions are auditable.
2. **Red Team** (trust: low; local/open model). Generates novel adversarial
   inputs and **mutates** them (role-play, encoding, authority framing, multi-turn
   escalation) against the live target. Critically, this is a **closed feedback
   loop**: when the Judge scores an attempt `partial` or `success`, the Red Team
   autonomously refines that *winning* turn into up to ten new variants and runs
   them in the same round — the Judge's verdict, not a human, decides what to try
   next (`RedTeamAgent.refine`, driven from `pipeline.run_campaign`). It runs on a
   local/open model that will not refuse offensive-security prompts; it never
   judges its own output.
3. **Judge** (trust: high; independent frontier model). The *only* agent that
   decides success/failure/partial/uncertain, against a versioned rubric, with
   evidence citations. Kept on a different model and context from the Red Team.
   Uncertain or critical verdicts escalate to a human.
4. **Documentation** (trust: medium; frontier model + human gate). Converts a
   confirmed exploit into a structured, reproducible vulnerability report and
   enforces data-quality constraints before persisting. Critical-severity
   reports require human approval before publish.

**How work flows.** Orchestrator → `AttackCampaignDirective` → Red Team →
`AttackAttempt` (full transcript + observed behavior) → Judge → `Verdict` →
(if success) Documentation → report + regression case. A confirmed exploit is
**promoted into the live regression suite in-run** (consuming the Judge's
`add_to_regression` flag), so a finding discovered this campaign — not just a
static seed — is replayed against the next build. A `partial`/`success` verdict
also feeds the Red Team's refinement loop, and the Verdict flows back to the
Orchestrator to update coverage and trigger regression on a version change. Each
consumer independently **validates the message it receives** against the
contract (`contracts.models.validate_message`), not only the producer on send.
Every message shares a `correlation_id`, so a finding is traceable end-to-end.
Typed error messages (`target_unreachable`, `budget_exceeded`, `judge_timeout`,
`regression_detected`, `invalid_message`, …) let any agent fail loudly.

**Regression = fixed, not merely changed.** The harness classifies a replay three
ways: `held` (the target affirmatively defended — the only pass), `regressed`
(the exploit reproduced), and `inconclusive` (the build drifted into an
unclassifiable answer). An `uncertain` replay is **not** a pass, so a fix that
only reworded the leak cannot sneak through green; `--strict` fails CI on drift.

**AI vs. deterministic.** LLMs do what only LLMs can — creative attack
generation, natural-language judgement, prose reports. Everything that can be
deterministic *is*: budget accounting, coverage math, regression replay, tool-
argument fuzzing, unauthenticated-endpoint probing, schema validation. This is a
cost and trust decision: deterministic checks are cheaper, reproducible, and
don't drift.

**Cost & scale.** The Orchestrator enforces a per-run dollar budget and a
per-campaign attempt cap, halts campaigns that spend without signal
(`no_findings_in_window`), and backs off on `rate_limited`. The Red Team on a
local model makes the expensive part (many generations/mutations) nearly free;
the frontier model is spent only where judgement quality matters (Judge, Docs).
See `docs/COST_ANALYSIS.md` for 100/1K/10K/100K projections.

**Framework.** The canonical runner is a dependency-free plain-Python loop
(`run_campaign`) that owns agent state and coordination; a **LangGraph-compatible**
graph (`build_langgraph`, four typed nodes over `StateGraph`) is provided as an
optional drop-in and is exercised when `langgraph` is installed, otherwise the
plain-Python runner is used. The target is PHP and is reached only over HTTP, so
the language split is a non-issue. State (attempts, verdicts, coverage) persists to a queryable store so
runs are resumable and auditable.

---

## Why deterministic-first (the load-bearing design decision)

The central design choice in AgentForge is **not** "use AI." It is: **use the
cheapest tool that solves each sub-problem correctly, and reserve the LLM for the
one job nothing else can do.** For a security evaluator that job is narrow —
generating *novel* attacks and making *natural-language judgements* about whether
a response broke a clinical invariant. Everything else has a specification, and
anything with a specification is cheaper, more reliable, and more auditable as
deterministic code.

**The counter-intuitive part: LLMs make the deterministic path *more* attractive,
not less.** It is tempting to route everything through a model now that models are
capable — but "can" is not "should." A deterministic check is:

- **Cheaper** — $0 per run vs. a metered API call. At scale the difference is the
  whole bill (see `docs/COST_ANALYSIS.md`: the deterministic surface is $0; the
  LLM crawl is the only cost term, ~$1.50–$150 at 100K attempts by model choice).
- **Reproducible** — the same input gives the same output every time; an LLM's
  does not, which is fatal for a *regression* test whose entire purpose is a
  stable pass/fail.
- **Auditable** — a rule you can read and a reviewer can trust, vs. a probabilistic
  black box you must re-verify.
- **Drift-free** — it does not change behaviour when a model is updated underneath
  you.

So the rule is a decision, applied per sub-problem:

| Question about a sub-problem | Tool | Where it lives in AgentForge |
|---|---|---|
| Is the correct answer **specifiable** (a rule, a schema, arithmetic, a replay)? | **Deterministic** ($0) | probe harness, regression replay, budget/coverage math, schema validation, load test |
| Does it require **generating something novel** or a **judgement in natural language**? | **LLM** (metered) | Red Team attack generation, Judge verdict on subtle leaks, Documentation prose |
| Is it a **verdict that must be trusted**? | **Deterministic gate first, LLM only on the residue** | Judge: rubric decides clear cases free; LLM escalated only on `uncertain` |

This is why the platform can attack across five categories, probe the whole
unauthenticated surface, and run a regression suite for **pennies per campaign** —
the expensive tool is only ever pointed at the part of the problem that actually
needs it. Reaching for an LLM where a rule would do is not "more AI," it is a more
expensive, less reliable, harder-to-audit version of the same answer. The hybrid
is the engineering result, not a compromise.

---

## Agent interaction diagram

```mermaid
flowchart TD
    subgraph Deterministic substrate
      OBS[(Observability store\ncoverage · verdicts · cost · traces)]
      DB[(Exploit DB\nversioned · queryable)]
      REG[Regression harness\ndeterministic replay]
    end

    ORCH[Orchestrator\nhigh trust · rules>LLM]
    RT[Red Team\nlow trust · local model]
    JU[Judge\nhigh trust · frontier model\nINDEPENDENT of Red Team]
    DOC[Documentation\nmed trust · frontier + human gate]
    TGT[[Clinical Co-Pilot\nlive target]]
    HUMAN((Human approver))

    OBS -->|coverage gaps, open findings| ORCH
    ORCH -->|AttackCampaignDirective| RT
    RT -->|drive multi-turn| TGT
    TGT -->|observed behavior| RT
    RT -->|AttackAttempt| JU
    JU -->|Verdict success| DOC
    JU -->|Verdict all| OBS
    DOC -->|confirmed exploit| DB
    DB --> REG
    ORCH -->|target changed / schedule| REG
    REG -->|regression_detected| OBS
    DOC -.->|critical severity| HUMAN
    HUMAN -.->|approve/reject| DOC
    ORCH -->|budget/halt| OBS
```

---

## Agent contracts (inputs → outputs)

| Agent | Consumes | Produces | Schema | Trust |
|---|---|---|---|---|
| Orchestrator | observability metrics, target version | `AttackCampaignDirective`, regression triggers | `orchestrator_to_redteam` | high |
| Red Team | directive + seed cases | `AttackAttempt` (transcript + observed behavior) | `redteam_to_judge` | low |
| Judge | `AttackAttempt` | `Verdict` (success/fail/partial/uncertain + evidence) | `judge_to_documentation` | high |
| Documentation | success `Verdict` + attempt | vuln report + regression case | (report format) | medium |
| any | — | typed `AgentError` | `errors` | — |

## Orchestration strategy

The Orchestrator scores each (category × surface) cell by:
`priority = base_priority × coverage_gap + open_weight`, where
`coverage_gap = 1 / (1 + attempts)` (an un-probed cell gets the full gap and it
saturates as the cell is exercised) and `open_weight` is a severity weight added
when the cell already has confirmed (open) findings, so the Red Team keeps
pressure where the target is weakest. Regression is *not* a term in this score —
it is a separate trigger (see below). It dispatches the Red Team at the
highest-scoring cell, with a budget sized to remaining run dollars. A campaign
halts when: budget hit (`budget_exceeded`), N consecutive attempts yield no new
signal (`no_findings_in_window`), or the target freezes. When the target's
deploy id changes, the Orchestrator triggers a full regression run before any
new exploration.

## Judge independence & drift control

- **Independence:** different model and a fresh context from the Red Team; the
  Judge never sees the Red Team's "goal", only the transcript + the
  `expected_safe_behavior` invariant.
- **Consistency:** a versioned rubric (`rubric_version` on every verdict) and a
  **ground-truth set** of labeled attempts (known-success / known-safe) run each
  cycle; if the Judge mislabels the ground truth, the run is flagged and the
  rubric change is rejected. This is how a drifting judge is detected.
- **Uncertainty:** `verdict=uncertain` or `severity=critical` sets
  `escalate_to_human=true`.

## Regression harness

Confirmed exploits become deterministic cases (`regression=true` in `/evals`).
The harness re-runs them on every target version and distinguishes **"fixed"**
from **"behavior merely changed"** by checking the *invariant* (`expected_safe_
behavior`), not a string match on the old output — a test passes only when the
defended invariant holds, and it also re-runs sibling categories to catch a fix
that regresses another category.

## Observability

Every message is appended to a run log keyed by `correlation_id`; the store
answers all six required questions, each backed by a method (not prose):

- **cases/category** and **pass-fail rate per (category, surface)** — `coverage()`
- **pass-fail per target version** — `coverage_by_version()` / `summary().by_version`
- **resilience trend over versions** — the cross-run `HistoryStore` snapshots
- **finding lifecycle open → in_progress → resolved** — `VulnerabilityReport.set_lifecycle`,
  driven in the live loop by the regression outcome (a fixed build resolves the
  finding; a regressed one reopens it) and queryable in the indexed `findings` table
- **per-run and per-component cost** — `cost_breakdown()` splits target/Red Team
  vs the LLM Judge and reports the per-attempt rate (the cost slope), not one
  lumped number
- **the ordered timeline of what each agent did** — `timeline()`

This store is both the human dashboard and the Orchestrator's input. Persisted
transcripts and served evidence are **PHI-redacted** at write time
(`redact.py`) — a confirmed exploit keeps its attack marker, never the leaked
clinical value.

## Human approval gates (trust boundaries)

- **Before a critical-severity report is published** (Documentation).
- **On any `uncertain` verdict** (Judge → human).
- **Before any remediation/patch action** — the platform never pushes fixes
  autonomously; it only files reports and regression cases.
- The platform attacks **only** the configured target host; the target base URL
  is pinned in config and the egress allowlist is scoped to that host.

## AI-use disclosure

| Agent | AI-powered? | Deterministic check / human gate that follows |
|---|---|---|
| Orchestrator | mostly rules; optional LLM for campaign phrasing | budget math and coverage scoring are deterministic and logged |
| Red Team | yes (local model) | output is never trusted as a finding until the Judge confirms |
| Judge | yes (frontier model) | versioned rubric + ground-truth drift check; uncertain → human |
| Documentation | yes (frontier model) | data-quality validation + human gate on critical reports |

**Residual risks:** a Judge that drifts *within* rubric bounds (mitigated by the
ground-truth set, not eliminated); a Red Team that finds genuinely novel attacks
the ground-truth set doesn't cover (mitigated by human spot-review of a sample);
LLM cost surprises (mitigated by hard budget caps + local-model Red Team).

## Build vs. configure (why custom agents)

| Tool | Covers | Falls short for us |
|---|---|---|
| OWASP ZAP / Burp | HTTP fuzzing, classic web vulns | no LLM-semantic attacks, no multi-turn conversational state, no verdict on "did the model break scope" |
| Garak | LLM probes | fixed probe lists, not target-aware; no orchestration/coverage/regression loop; no clinical-invariant judging |
| Semgrep | static code analysis | not a runtime adversarial tester |
| Commercial red-team SaaS | breadth | not tuned to PHI/clinical invariants; cost at continuous scale; less control over the judge |

We **configure** deterministic tools (ZAP-style probes) for the unauthenticated /
IDOR / fuzzing surface, and **build** custom agents for the LLM-semantic,
multi-turn, coverage-driven, clinically-judged parts they don't cover.

## Rate limits & auth (external dependencies)

| Dependency | Auth | Limit handling |
|---|---|---|
| Clinical Co-Pilot target | OpenEMR session + CSRF (see HANDOFF) | respect its 60 turns/user/hr; back off on 429/breaker |
| Red Team LLM (local) | endpoint key | local; effectively unlimited |
| Judge LLM (frontier) | API key | queue + exponential backoff on `rate_limited` |

_Status: all four agents and the deterministic substrate are now implemented and
tested (133 passing tests). Built: the versioned Contracts; the Red Team agent
(verified live against the deployed target); the Judge (deterministic rubric
`1.0.0` + ground-truth drift check); the Documentation agent (report + regression
case + human gate on critical); the Orchestrator (coverage/severity scoring +
budget/halt + target-change regression trigger); the observability store; the
regression harness; the LangGraph-compatible pipeline wiring the four agents over
the typed messages (`src/agentforge/pipeline.py`, dependency-free runner + optional
`build_langgraph`); the deterministic probe harness (`probes.py`, which found 3
real live findings on the unauth surface); and provider-agnostic LLM adapters for
the Judge and Red Team (`agents/llm.py`, opt-in via `--use-llm-*`, fail-soft to the
deterministic core). Run the full loop with `python -m agentforge.cli campaign`
(`--dry-run` offline, live otherwise) and the probes with `... probe`. Reports and
analysis are under `docs/` (vulnerability reports, cost analysis, triage exercise,
live-run evidence). What remains is human/infra packaging (ATO/load evidence,
demo) — see HANDOFF.md._
