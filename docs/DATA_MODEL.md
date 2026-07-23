# AgentForge — data model & write-access controls

The platform generates and stores its own sensitive data: attack transcripts,
confirmed exploits, and (potentially) PHI the target disclosed. This is the
explicit write-access model for that data — who writes what, where, in what
state, and what protects it. (Deliverable #15.)

## Stores

| Store | Backing | Written by | Mutability | Contents |
|---|---|---|---|---|
| **Observability log** | append-only JSONL (`runs/<id>.observability.jsonl`) | the pipeline, one writer per campaign | **append-only** — never mutated in place (`ObservabilityStore.record`) | directives, attempts, verdicts, typed errors, cost/drift/regression/lifecycle events |
| **Findings** (reports) | `runs/<id>.reports.json` + indexed `findings` table | Documentation agent | report `status`/`lifecycle` transition via guarded methods only | confirmed exploits (redacted) |
| **Regression suite** | `evals/*` seeds + `runs/discovered_regression.jsonl` | Documentation agent (promotion) | append/upsert by id | replayable confirmed exploits |
| **History** | SQLite / Postgres (`campaign_snapshots`, `findings`) | CLI after a run | upsert by natural key; schema-versioned migrations | cross-run trends, indexed findings |
| **Eval baseline** | `evals/OFFLINE_BASELINE.json` | `agentforge eval` | regenerated, diffed in CI | reproducible offline results |

## Write rules (enforced in code, not convention)

1. **Append-only observability.** `record()` only appends; nothing rewrites a
   prior event. A run is therefore an immutable audit trail. Concurrent
   campaigns use distinct log paths (one per `campaign_id`) and are merged at
   read time — no shared-writer contention.
2. **No un-adjudicated write to a finding.** A report is only produced from a
   Judge `verdict=success` (Documentation refuses otherwise), and data-quality
   invariants must pass before it persists (`_validate`).
3. **State transitions are guarded.** Report **publish** requires the approval
   gate (a critical needs a named approver — `ApprovalRequired`); **lifecycle**
   moves are validated (`open→in_progress→resolved`, illegal moves rejected).
   No free-text status write.
4. **Contracts on every inter-agent write.** Producers validate on `to_wire`;
   consumers validate on receipt (`validate_message`). A malformed message is
   rejected at the boundary before it is stored.
5. **PHI is redacted before it is written or served.** Every persisted
   transcript/report/evidence and the dashboard pass through `redact.py`
   (§ below). Redaction runs on the stored copy only, never before adjudication.

## PHI at rest

The target can disclose PHI in a transcript. AgentForge must not become the
long-term store of it. Clinical values (labs, medications, cross-patient values)
are replaced with `[PHI-REDACTED]`/`[MED-REDACTED]` at write time; the attack
marker is retained for triage. See `docs/SECURITY_SCAN.md` §PHI handling and
`src/agentforge/redact.py`.

## Access control on reads

- **Dashboard** (`web.py`) is fail-closed: every route except `/healthz` requires
  HTTP Basic auth (`AGENTFORGE_WEB_USER`/`_PASSWORD`), constant-time compared;
  unset credentials → the panel is locked (503). It also re-redacts on serve as
  defense-in-depth against any raw legacy log.
- **`runs/`** is git-ignored and ephemeral; nothing sensitive is committed. The
  one committed artifact (`docs/evidence/`) is redaction-verified.
- **Secrets** (target creds, model keys) live only in `.env` (git-ignored) or CI
  secrets; never in tracked files (verified by the secret sweep in SECURITY_SCAN).

## Retention

`runs/` is ephemeral on the PaaS disk (lost on redeploy) — by design for
interactive use; attach a volume to retain. The durable stores (history DB,
promoted regression cases) are the intended long-lived data, and they hold
redacted/aggregate data, not raw PHI transcripts.
