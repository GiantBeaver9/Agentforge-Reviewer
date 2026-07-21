# AgentForge — Users & Use Cases

AgentForge's users are **not** the clinicians who use the Co-Pilot. They are the
people responsible for keeping an AI-in-the-loop clinical system safe over time.

## Primary users

### 1. Application Security Engineer (AppSec) — primary
**Job:** continuously assure that the Clinical Co-Pilot resists prompt injection,
PHI exfiltration, and tool misuse as the product changes weekly.
**Pain today:** testing is manual prompting against a static list; findings
aren't reproducible; a fix is validated once and never re-checked; no visibility
into which attack categories are actually covered.
**Uses AgentForge to:** launch autonomous campaigns, get reproducible
vulnerability reports, and gate deploys on a regression suite.
**Why automation:** the attack space mutates faster than a human can enumerate.
A human writes ~dozens of payloads; the Red Team generates and mutates hundreds
per campaign and the Judge scores them consistently — the human reviews
confirmed findings, not raw output.

### 2. Engineering Lead / Release Manager
**Job:** decide whether a Co-Pilot build is safe to ship.
**Uses AgentForge to:** read the resilience trend across versions and require a
green regression run before release; approve/reject critical findings at the
human gate.
**Why automation:** deterministic regression replay on every version is the only
way to know a fix *held* and didn't regress a sibling category — a human can't
re-run the full suite by hand each deploy.

### 3. Compliance / Security Officer (CISO office)
**Job:** demonstrate due diligence for an AI system touching PHI.
**Uses AgentForge to:** pull the ATO-style evidence packet, audit what each
agent did overnight (per-`correlation_id` trace), and confirm human approval
gates fired on critical findings.
**Why automation:** continuous, logged, auditable testing is the evidence a
regulator/CISO wants — not a one-time pentest PDF.

## Representative use cases

| UC | Trigger | AgentForge action | Human involvement |
|----|---------|-------------------|-------------------|
| UC1 | New Co-Pilot deploy | Orchestrator triggers full regression run | notified only on regression |
| UC2 | Nightly campaign | Explore least-covered high-severity category | reviews confirmed reports next morning |
| UC3 | Partial exploit found | Red Team mutates it 10× to find the bypass | none until Judge confirms |
| UC4 | Critical exploit confirmed | Documentation drafts report, **holds at human gate** | approves before publish |
| UC5 | New published attack technique | Add as seed cases; Red Team extends them | AppSec adds the seed |
| UC6 | Cost spike | Orchestrator halts on `budget_exceeded` | notified with spend report |

## Where automation stops (deliberately)

AgentForge **files and regression-guards**; it does **not** patch the target,
publish critical reports without approval, or attack any host but the configured
target. Remediation is a human decision; the platform makes that decision
well-informed and reproducible.
