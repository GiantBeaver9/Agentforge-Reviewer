# AgentForge — Post-MVP TODO

This list is the output of an independent, adversarial verification pass: ten
sub-agent auditors checked the platform against the Gauntlet Week-3 rubric, plus
a docs-vs-code drift audit. **The MVP passes** — four agents + deterministic
substrate implemented, 70 tests green, verified live against the deployed
co-pilot. Nothing below blocks submission; these are the honest remaining gaps,
kept visible on purpose rather than smoothed over.

## Deferred by design (planned, not built for MVP)

- [ ] **Over-time history store + dashboard tab.** Pass/fail rate is currently a
  *cumulative per-category* ratio, not a time series. Add a small DB (e.g.
  SQLite) to retain per-window history, and a dashboard tab to view trends over
  time. (`observability/store.py` `pass_rate` is cumulative today.)
- [ ] **Agent-response visibility tab.** Surface each Judge and Red Team raw
  response in the dashboard, **tabbed by deterministic vs LLM-run**, so it's
  clear which path produced each attack/verdict.

## Report / schema polish

- [ ] **Exploitability field.** `VulnerabilityReport` carries `severity` and a
  Judge `confidence` float, but no explicit `exploitability` rating (easy /
  moderate / hard). The rubric asks for severity **and** exploitability. Add the
  field (derive from attempt shape) and thread it into the regression case.
- [ ] **Require `evidence`.** `evidence` defaults to `[]` and is not in
  `_REQUIRED_REPORT_FIELDS`, so a report can ship with empty evidence. Consider
  making it required.
- [ ] **Critical-severity example.** All 3 published findings are Low/Med probe
  findings, so the `PENDING_HUMAN` critical-approval gate is never exercised by a
  real example. Add a synthetic critical finding to demonstrate the gate.
- [ ] **Determinism test.** Rollups are code-deterministic but no test guards it.
  Add a "run twice, assert equal" test on `store.summary()`.

## ATO packet gaps (`docs/ATO_EVIDENCE.md`)

- [ ] Add an **SBOM / dependency-version table** (source from `requirements.txt`).
- [ ] Add a **dependency/platform vulnerability-scan note** (pip-audit / safety)
  with results.
- [ ] Add an **incident-response / postmortem section** (PHI-in-response
  detection → containment → review runbook).
- [ ] State **AgentForge's own dashboard HTTP Basic-auth gate** (`web.py`
  `_check_auth` / `_auth_credentials`) in the auth/authz section — currently only
  the target handshake is described.

## Config, not code (submission-day)

- [ ] **Plug in the LLMs (optional).** Set `JUDGE_BASE_URL` / `REDTEAM_BASE_URL`
  (+ model + key) in env to upgrade the Judge and Red Team to real models. Both
  fail soft to the deterministic core if unset — the platform is fully functional
  without them.
