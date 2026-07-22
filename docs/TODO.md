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

- [x] **Exploitability field.** `VulnerabilityReport` now carries an explicit
  `exploitability` rating (easy / moderate / hard) derived deterministically
  from the attempt shape (`documentation.py` `_derive_exploitability`), threaded
  into `to_dict`, `_REQUIRED_REPORT_FIELDS`, and the regression case, with unit
  tests.
- [x] **Require `evidence`.** `evidence` is now in `_REQUIRED_REPORT_FIELDS`; the
  deterministic Judge always emits >=1 evidence item on a success verdict, so an
  evidence-less report is rejected by the data-quality gate. Test added.
- [ ] **Critical-severity example.** All 3 published findings are Low/Med probe
  findings, so the `PENDING_HUMAN` critical-approval gate is never exercised by a
  real example. Add a synthetic critical finding to demonstrate the gate.
  *(Left for human review — the existing `data_exfiltration` success test already
  exercises the `PENDING_HUMAN` path; a published synthetic finding is a
  judgement call.)*
- [x] **Determinism test.** Added `test_summary_is_deterministic` — builds a
  store, runs `summary()` twice, asserts equal (and byte-identical JSON).

## ATO packet gaps (`docs/ATO_EVIDENCE.md`)

- [x] Added an **SBOM / dependency-version table** (§6, resolved versions +
  deploy-runtime subset).
- [x] Added a **dependency/platform vulnerability-scan note** (§7) — `pip-audit`:
  declared closure clean; base-image CVEs called out as out-of-boundary.
- [x] Added an **incident-response / postmortem section** (§8) — PHI-in-response
  detect → contain → eradicate/recover → review runbook.
- [x] Stated **AgentForge's own dashboard HTTP Basic-auth gate** (`web.py`
  `_check_auth` / `_auth_credentials`) as an AC-3 control row in §3.

## Config, not code (submission-day)

- [ ] **Plug in the LLMs (optional).** Set `JUDGE_BASE_URL` / `REDTEAM_BASE_URL`
  (+ model + key) in env to upgrade the Judge and Red Team to real models. Both
  fail soft to the deterministic core if unset — the platform is fully functional
  without them.
