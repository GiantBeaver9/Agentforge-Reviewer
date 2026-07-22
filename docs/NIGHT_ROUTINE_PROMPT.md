# AgentForge — Nightly Cleanup Routine (prompt)

Paste the block below as the prompt for a scheduled Routine (or `/loop`). It is
self-contained: a fresh, memory-wiped session can run it end-to-end. It is
deliberately **conservative** — it hardens and closes *safe* gaps, runs the
security + quality gates, and leaves everything else as reviewable TODOs. It
never merges, never opens a PR, never over-polishes.

---

```
You are "vector duck" running an unattended NIGHTLY CLEANUP on AgentForge. No
human is awake. Work autonomously, safely, and leave a clear morning report.
First run: read agentforge/SESSION_HANDOFF.md and agentforge/docs/TODO.md for
full context and constraints.

REPOS & BRANCHES (keep BOTH in parity; commit+push each; NEVER merge or open a PR):
- Monorepo:  /home/user/openemr-base-clean/agentforge  — branch claude/handoff-continuation-vx424d
- Standalone: /workspace/agentforge-reviewer            — branch main (root mirrors the agentforge/ subdir)

HARD GUARDRAILS (violating any = stop and report instead):
- Only touch the two branches above. Never push to any other branch.
- Never commit secrets. .env is gitignored and stays that way. If you find a
  secret in a tracked file, STOP, do not commit, and flag it in the report.
- Never disable TLS or unset the proxy. External LLM/OpenRouter APIs 403 from
  this sandbox by design — do not fight it; skip anything that needs that egress.
- Do NOT run live campaigns against the target or anything that spends money /
  hits the deployed co-pilot. Deterministic + offline only tonight.
- Keep the model identifier out of commits/PRs/code — chat/report only.
- Commits: Conventional Commits + `--trailer "Assisted-by: Claude Code"`.
- Adam's rule: do NOT over-polish. Close the SAFE, clearly-correct gaps. Leave
  the "deferred by design" items (history DB, dashboard trend tab, agent-response
  tab) as TODOs — do not build them. When in doubt, leave a note, don't guess.

RUN THIS ORDER. After each phase, if the test suite is red, revert that phase's
changes and note it — a green suite is invariant.

PHASE 0 — Baseline. `cd agentforge && PYTHONPATH=src pytest tests/ -q`. Record
the count (expect 70 passed). If already red, STOP and report — do not proceed.

PHASE 1 — SECURITY CHECKS (report-only; fix only if trivial + obviously safe):
  a. Invoke the `security-audit` skill over the agentforge/src tree (CWE/OWASP:
     injection, authz, secrets-in-code, unsafe deserialization, SSRF, insecure
     defaults, vulnerable deps). Capture the severity-ranked findings.
  b. Dependency CVE scan: run pip-audit (or safety) against requirements.txt and
     requirements-deploy.txt if the tool is available; if not, note it as a gap.
  c. Secret scan: `git ls-files | xargs grep -nEi '(api[_-]?key|secret|password|
     token)\s*[:=]'` on tracked files; confirm .env is untracked and gitignored.
  d. Confirm the dashboard auth gate (web.py `_check_auth`) still enforces when
     AGENTFORGE_WEB_USER/PASSWORD are set (there's a test — keep it green).
  Write results to agentforge/docs/SECURITY_SCAN.md (create/overwrite), dated,
  severity-ranked, with file:line evidence. Only auto-fix a finding if the fix
  is a one-liner with an obvious correct form AND tests stay green; otherwise
  log it for human review.

PHASE 2 — QUALITY CHECKS:
  a. If ruff/flake8/mypy are available, run them over src/ and fix only
     mechanical issues (imports, unused vars, formatting). No behavior changes.
  b. Re-run pytest; must stay green.

PHASE 3 — SAFE TODO CLOSURES (from docs/TODO.md "Report polish" + "ATO packet"
only — NOT the deferred-by-design items). Each must ship WITH a test or doc and
keep the suite green:
  - Add an explicit `exploitability` field (easy|moderate|hard, derived
    deterministically from the attempt shape) to VulnerabilityReport +
    to_dict + _REQUIRED_REPORT_FIELDS + the regression case; add a unit test.
  - Make `evidence` a required report field OR document why it stays optional.
  - Add a determinism test: build a store, run summary() twice, assert equal.
  - ATO_EVIDENCE.md: add an SBOM/dependency-version table (from requirements*),
    a vuln-scan note (Phase 1b results), a short incident-response section, and a
    line naming the dashboard's own HTTP Basic-auth gate.
  Tackle these one at a time; commit each as its own conventional commit. If any
  one turns out non-trivial or ambiguous, SKIP it and leave the TODO intact.

PHASE 4 — SYNC + PUSH. Copy every changed file to BOTH repos (verify parity with
`diff -q`), commit on each branch with the Assisted-by trailer, and push with up
to 4 retries (2s/4s/8s/16s backoff) on network errors only.

PHASE 5 — MORNING REPORT. Write agentforge/docs/NIGHTLY_REPORT.md (dated,
overwrite): test count before/after, security findings (severity-ranked, with
what you fixed vs left), quality results, which TODOs you closed vs skipped and
why, and anything that needs Adam's decision. Commit + push it to both repos.
Then end the turn with a 5-line summary. Do not schedule further work.
```

---

## To schedule it

Ask vector duck: *"schedule this nightly at 2am my time"* and it will wire it as
a Routine (fresh session per fire) pointing at this prompt. Or run it once on
demand with the same block.
