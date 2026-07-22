# AgentForge — Nightly Cleanup Report

**Date:** 2026-07-22
**Run:** unattended nightly cleanup routine (`docs/NIGHT_ROUTINE_PROMPT.md`)
**Branch:** `claude/night-routine-prompt-uh90g1`
**Result:** ✅ all phases completed, suite green throughout.

## TL;DR

Closed the safe, clearly-correct report-polish and ATO-packet TODOs; ran the
security and quality gates. **Test count 70 → 75** (all green). No high/critical
security findings, declared dependencies scan clean. Left the deferred-by-design
items and one judgement-call TODO untouched, as instructed. Two things worth
Adam's eye are in "Needs Adam's decision" below.

## Environment deviations from the prompt (worth knowing)

The routine prompt was written for a two-repo setup; this session only had one:

- **One repo, not two.** Only `giantbeaver9/agentforge-reviewer` was in scope,
  at `/home/user/Agentforge-Reviewer` with content at the repo **root** (not an
  `agentforge/` subdir). So the "sync to both repos + `diff -q` parity" step was
  a no-op — nothing to mirror.
- **Branch `claude/night-routine-prompt-uh90g1`, not `main`.** The session's
  branch rules pinned work here; I did not touch `main`.
- Dependencies weren't preinstalled — installed from `requirements.txt`. Note
  the `pytest` on `PATH` uses a different interpreter, so tests must run as
  `PYTHONPATH=src python -m pytest`.

## Phase 0 — Baseline

`PYTHONPATH=src python -m pytest tests/ -q` → **70 passed** (after installing
requirements). Green, so proceeded.

## Phase 1 — Security (report-only)

Full write-up: `docs/SECURITY_SCAN.md`. Summary:

- **AgentForge's own code:** 0 critical / 0 high / 0 medium. No dynamic-code or
  deserialization sinks; path traversal guarded; dashboard XSS closed via
  consistent `esc()`; auth gate uses constant-time `hmac.compare_digest`; TLS
  never disabled.
- **Dependencies (`pip-audit`):** `requirements.txt` and
  `requirements-deploy.txt` both **clean**. The base-image packages `pip-audit`
  flagged (`setuptools`, `wheel`, `urllib3`, `pyjwt`) are **not** AgentForge
  deps — recorded as an out-of-boundary hygiene note, not a finding.
- **Secret sweep:** clean — only placeholders, config field names, and test
  constants are tracked; `.env` untracked and gitignored.
- **Auth-gate regression test:** stayed green.
- **One LOW (left for review):** `esc()` doesn't escape `'`, and one dashboard
  sink is a single-quoted JS context. Not currently reachable (filenames are
  server-generated), flagged as defense-in-depth. Not auto-fixed — it changes a
  shared helper's contract.

## Phase 2 — Quality

- **ruff:** found 5 issues, all mechanical — **fixed** (3 unused imports, 1
  ambiguous var name, 1 unused local + its dangling import). Committed as
  `chore: remove unused imports and fix lint in src`.
- **mypy:** ran for signal (`--ignore-missing-imports`) → 6 errors, all
  type-annotation / union-narrowing issues (pre-existing, in `redteam.py`,
  `web.py`, `cli.py`). **Not fixed** — none are "mechanical" per the routine's
  fix-only rule; proper fixes are annotation/behavior judgement calls. Logged
  here for a future typing pass.
- **pytest:** re-ran, stayed green.

## Phase 3 — Safe TODO closures (each shipped with a test/doc)

| TODO | Status | How |
|---|---|---|
| `exploitability` field on `VulnerabilityReport` | ✅ closed | Deterministic `easy/moderate/hard` from attempt shape; threaded into `to_dict`, `_REQUIRED_REPORT_FIELDS`, regression case + validator; 3 unit tests. |
| Require `evidence` | ✅ closed | Added to `_REQUIRED_REPORT_FIELDS`; deterministic Judge always supplies it, so no path breaks; rejection test added. |
| Determinism test on `store.summary()` | ✅ closed | `test_summary_is_deterministic` — twice, assert equal + byte-identical JSON. |
| ATO: SBOM table | ✅ closed | `ATO_EVIDENCE.md` §6 — declared deps + resolved versions + deploy-runtime subset. |
| ATO: vuln-scan note | ✅ closed | §7 — pip-audit results, base-image CVEs called out as out-of-boundary. |
| ATO: incident-response section | ✅ closed | §8 — PHI-in-response detect → contain → eradicate/recover → review runbook. |
| ATO: dashboard Basic-auth gate | ✅ closed | §3 — new AC-3 control row for `_check_auth`/`_auth_credentials`. |
| Critical-severity synthetic example | ⏭️ skipped | Judgement call — publishing a synthetic finding isn't clearly-correct; the existing `data_exfiltration` success test already exercises the `PENDING_HUMAN` gate. TODO left intact. |
| Deferred-by-design (history DB, dashboard trend/agent-response tabs) | ⏭️ untouched | Per Adam's rule — left visible as TODOs, not built. |

## Phase 4 — Commits (branch `claude/night-routine-prompt-uh90g1`)

Four conventional commits, each with the `Assisted-by: Claude Code` trailer:

1. `chore: remove unused imports and fix lint in src`
2. `feat: harden vulnerability report schema (exploitability + required evidence)`
3. `test: assert store.summary() is deterministic`
4. `docs: add security scan and ATO evidence (SBOM, vuln scan, IR, auth gate)`

(No PR opened, no merge — per the guardrails.)

## Phase 5 — Final state

- **Tests: 75 passed** (`PYTHONPATH=src python -m pytest tests/ -q`).
- **ruff: clean** on `src/`.
- No secrets committed; `.env` still untracked + gitignored.

## Follow-up (2026-07-22, after Adam's review)

- **#1 (LOW-1 escaper hardening) — done.** `esc()` now escapes `'`, and the
  dashboard run list dropped its inline `onclick` for `data-` attributes + a
  delegated listener. `docs/SECURITY_SCAN.md` updated.
- **#3 (mypy typing pass) — done.** All 6 type errors fixed with annotations /
  narrowing (no behavior change); `mypy --ignore-missing-imports src/` is clean.
- **#2 (critical-severity synthetic example) — still open**, discussing scope
  with Adam before implementing.

## Needs Adam's decision

1. **LOW-1 escaper hardening** (`docs/SECURITY_SCAN.md`): harden `esc()` to also
   escape `'`, or move the inline `onclick` to a `data-` attribute +
   `addEventListener`. Safe but touches a shared helper's contract — left for a
   human call.
2. **Critical-severity synthetic example** (TODO): do you want a published
   synthetic critical finding to demonstrate the `PENDING_HUMAN` gate end-to-end,
   or is the existing test coverage enough? I skipped it as a judgement call.
3. **mypy typing pass** (optional): 6 pre-existing type errors are logged in
   Phase 2 — not fixed tonight because they aren't mechanical. Worth a dedicated
   typing ticket if you care about a clean `mypy` run.
