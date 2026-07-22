# AgentForge — ATO-Style Evidence Packet

An Authority-To-Operate–style security package for **AgentForge** (the adversarial
evaluation platform), in the shape a reviewer expects: system description,
authorization boundary, control implementation with evidence, residual risk, and
a POA&M. Framed against NIST SP 800‑53 families; this is a course deliverable,
not a federal ATO, but it is written to that discipline.

> Scope note: this packet authorizes **AgentForge** (the tester). The *target*
> (the Clinical Co-Pilot) has its own security posture; AgentForge's findings
> against it live in `VULNERABILITY_REPORTS.md`.

## 1. System description

AgentForge is a four-agent system that continuously red-teams an AI clinical
co-pilot and produces verified, reproducible vulnerability findings. It runs as a
Python application (CLI + local web dashboard) that reaches the target only over
authenticated HTTP. It stores run logs, verdicts, and reports to an append-only
local store. It contains no PHI of its own and never writes to the target's
chart.

**Data types handled:** adversarial prompts (synthetic), target responses
(which *may* transit PHI if the target were to leak — treated as sensitive and
never persisted to shareable artifacts; see AC/AU below), verdicts, and reports.

## 2. Authorization boundary

```
                    ┌─────────────────────── AgentForge boundary ───────────────────────┐
   operator ──CLI/GUI──▶ Orchestrator ─▶ Red Team ─▶ Judge ─▶ Documentation ─▶ reports  │
                    │        │              │          │            │                    │
                    │        └── Observability store (append-only, local) ──────────────┤
                    └───────────────────────────────┬───────────────────────────────────┘
                                                     │ authenticated HTTPS (pinned host)
                                                     ▼
                                        Clinical Co-Pilot (target, OUT of boundary)
              external LLMs (Red Team local model; independent Judge model) ── OUT of boundary
```

- **In boundary:** the four agents, the deterministic substrate (observability,
  regression, probes), the CLI/web front ends, local config/secrets handling.
- **Out of boundary, with a defined interface:** the target co-pilot (attacked
  over HTTP only, one pinned host); the Red Team LLM and the independent Judge
  LLM (reached over their own authenticated APIs).

## 3. Control implementation & evidence (800‑53 mapping)

| Family | Control | How AgentForge implements it | Evidence |
|---|---|---|---|
| **AC** Access Control | Least privilege to the target | Attacks a single **pinned host** from config; no lateral scope. `--pid` pins one patient. | `config.py` `TargetConfig`; `ARCHITECTURE.md §Human approval gates` |
| **AC-4** Information Flow | Egress scoping | Platform reaches only the configured target + declared LLM endpoints; deploy runs under a Custom egress allowlist scoped to the target host. | `HANDOFF.md` env note; `.env.example` |
| **AU** Audit | Full run audit trail | Every inter-agent message is appended to an immutable JSONL log keyed by `correlation_id`; a finding is traceable end-to-end. | `observability/store.py`; `dashboard` CLI |
| **CM** Config Mgmt | Versioned contracts | Inter-agent messages are versioned JSON Schemas; changes are additive-checked. | `contracts/v1/*`, `contracts/README.md` |
| **IA** Identification & Auth | Target auth handled correctly | Verified OpenEMR session + CSRF handshake; secrets read from `.env` (git-ignored), never logged. | `target/client.py`; `LIVE_RUN_EVIDENCE.md`; `.gitignore` |
| **AC-3** Access Enforcement | AgentForge's *own* dashboard gate | The web dashboard enforces HTTP Basic auth when `AGENTFORGE_WEB_USER`/`AGENTFORGE_WEB_PASSWORD` are set — credentials compared with constant-time `hmac.compare_digest`, `401`+`WWW-Authenticate` otherwise; the server warns before binding a public interface without it. | `web.py` `_check_auth`/`_auth_credentials`; `tests/test_web.py` |
| **SI** System Integrity | Independent verification | The Judge (separate model/context) decides success, not the Red Team; a versioned rubric + ground-truth drift check guards judge integrity. | `agents/judge.py`, `evals/ground_truth.json` |
| **RA** Risk Assessment | Threat modeling | STRIDE/OWASP-mapped threat model precedes testing; findings severity-ranked. | `THREAT_MODEL.md`, `VULNERABILITY_REPORTS.md` |
| **CA** Assessment & Auth | Continuous assessment + regression | Confirmed exploits become deterministic regression cases re-checked by invariant on every target version. | `regression.py`; `documentation.py` `regression_case` |
| **CP/SC** Availability | DoS-safety of the tester | Hard budget/attempt caps + halt (`budget_exceeded`, `no_findings_in_window`); live runs clamped in the GUI. | `agents/orchestrator.py`, `web.py` `LIVE_MAX_*` |
| **PL** Planning | Human authorization gates | Critical reports require human approval before publish; any `uncertain` verdict escalates; no autonomous remediation. | `documentation.py` (PENDING_HUMAN); `judge.py` escalate flags |
| **SA** Acquisition | Build-vs-buy justified | Deterministic tools configured for the classic-web surface; custom agents only for LLM-semantic parts. | `ARCHITECTURE.md §Build vs configure`; `probes.py` |

## 4. Separation of duties (key SI/PL control)

The single most important control is **generator ≠ grader**: the Red Team (low
trust, local model) proposes; the Judge (high trust, independent model) disposes;
Documentation (medium trust) only publishes what the Judge confirmed, behind a
human gate for criticals. No single agent can both invent and bless a finding —
this is enforced structurally (separate classes, separate models, separate
contexts), not by policy alone.

## 5. Test evidence summary

- **Automated assurance:** 85 passing tests (contracts, agents, drift check,
  probes, load, web, history) — `pytest tests/ -q`.
- **Live verification:** auth handshake + full four-agent loop run against the
  deployed target; the co-pilot defended all seeded LLM attacks
  (`LIVE_RUN_EVIDENCE.md`).
- **Deterministic findings:** 3 confirmed on the unauth surface
  (`VULNERABILITY_REPORTS.md`).
- **Performance baseline:** `LOAD_TEST.md`.

## 6. Software bill of materials (SBOM)

Direct dependencies as declared in `requirements.txt`, with the versions
resolved in the assessment environment (2026-07-22). The deployed dashboard runs
the smaller `requirements-deploy.txt` subset (marked ✓); the remaining packages
are dev/optional (LLM SDKs, LangGraph, CLI/formatting) and are lazily imported or
test-only, so they are not in the deployed runtime.

| Package | Constraint | Resolved | In deploy runtime | Purpose |
|---|---|---|---|---|
| langgraph | >=0.2.0 | 1.2.9 | — (lazy) | Optional graph orchestration drop-in |
| langchain-core | >=0.3.0 | 1.5.0 | — | Transitive of langgraph |
| pydantic | >=2.7 | 2.13.4 | ✓ | Typed contracts |
| jsonschema | >=4.22 | 4.26.0 | ✓ | Wire-contract validation |
| httpx | >=0.27 | 0.28.1 | ✓ | HTTP client to target + LLM adapters |
| tenacity | >=8.3 | 9.1.4 | — | Retry/backoff |
| psycopg[binary] | >=3.1 | — | ✓ (opt-in) | Postgres history backend; imported only when `DATABASE_URL` is set |
| openai | >=1.30 | 2.46.0 | — (opt-in) | OpenAI-compatible LLM client |
| google-generativeai | >=0.7 | 0.8.6 | — (opt-in) | Optional Gemini judge |
| python-dotenv | >=1.0 | 1.2.2 | ✓ | `.env` loading |
| rich | >=13.7 | 15.0.0 | — | CLI formatting |
| typer | >=0.12 | 0.27.0 | — | CLI |
| pytest | >=8.2 | 9.1.1 | — (test) | Test runner |

The web server, probes, and load test are Python-stdlib only. The history store
defaults to stdlib `sqlite3`; `psycopg` is pulled in only when `DATABASE_URL`
selects the Postgres backend, so the dashboard serves with no third-party
runtime beyond the campaign-path packages.

## 7. Dependency & platform vulnerability scan

Scanned with `pip-audit` (OSV/PyPI advisory DB) on 2026-07-22:

| Target | Result |
|---|---|
| `requirements.txt` | **No known vulnerabilities** |
| `requirements-deploy.txt` | **No known vulnerabilities** |

AgentForge's declared dependency closure is clean. A full-environment audit
additionally flagged `setuptools`, `wheel`, `urllib3`, and `pyjwt` — these are
**sandbox base-image** packages that AgentForge neither declares nor imports, so
they are outside the authorization boundary and tracked as an environment-hygiene
note, not an AgentForge finding. `pip-audit` is not preinstalled in the base
image; adding it to a dev-requirements file would let the nightly scan run
without a network install (POA&M #4). Full method and output:
`docs/SECURITY_SCAN.md`.

## 8. Incident response & postmortem

The one incident class AgentForge must handle is **PHI transiting a target leak
response** — i.e. the co-pilot under test discloses real patient data in a reply
that AgentForge captures. The runbook:

1. **Detect.** The Judge flags a `success` verdict on a `data_exfiltration` /
   `identity_role_exploitation` category with a leak marker in the last target
   turn (`judge.py` `_score`). Any such finding is **critical** and is gated at
   `PENDING_HUMAN` — it is never auto-published (`documentation.py`).
2. **Contain.** Target responses are held only in the local append-only run log
   keyed by `correlation_id`; they are **not** copied into shareable artifacts,
   and report prose is PHI-scrubbed by the rationale rule. Stop the campaign
   (hard caps/halt already bound blast radius) and treat the run log as
   sensitive: restrict to the operator host, do not commit it (`runs/` is a
   local working dir), and rotate/delete after triage.
3. **Eradicate & recover.** The finding is the *target's* defect, not
   AgentForge's — hand the reproduction (deterministic regression case) to the
   co-pilot owner; AgentForge performs **no** remediation on the target
   (reports-only, no autonomous action).
4. **Review (postmortem).** Confirmed leaks become deterministic regression
   cases (`documentation.py` `regression_case`) re-checked by invariant on every
   future target version, so a fixed leak cannot silently regress. Human
   spot-review of a sample of verdicts each cycle catches Judge drift.

Trigger for a *tester-side* incident (e.g. a run log with PHI committed by
mistake): purge from history, rotate any exposed credentials, and record the
event here. None has occurred in this assessment.

## 9. Residual risk

| Risk | Likelihood | Impact | Disposition |
|---|---|---|---|
| Judge drifts *within* rubric bounds | Low | Med | Mitigated by ground-truth set; not eliminated — human spot-review of a sample each cycle. |
| Red Team finds a novel attack the ground truth doesn't cover | Med | Med | Accept + monitor; human review of `uncertain` verdicts is the catch-net. |
| A live run transits PHI in a target leak response | Low | High | Responses are not persisted to shareable artifacts; reports are PHI-scrubbed by policy (see `judge.py` rationale rule). |
| LLM cost overrun | Low | Low | Hard caps enforced in code (Orchestrator + GUI clamps). |

## 10. POA&M (open items)

| # | Item | Priority | Owner |
|---|---|---|---|
| 1 | Wire a live independent Judge model (adapter built; needs egress+key) | Med | Eng |
| 2 | Automate the human-review sample for `uncertain` verdicts | Low | AppSec |
| 3 | ~~Persist observability to a queryable DB for multi-run trend (JSONL today)~~ **Done** — `observability/history.py` (Postgres via `DATABASE_URL`, SQLite fallback) + dashboard trends card | — | Eng |
| 4 | Add `pip-audit` to dev-requirements so the dependency scan runs offline | Low | AppSec |

## 11. Recommendation

AgentForge implements its in-boundary controls with test and live evidence, has a
defined and least-privilege interface to the out-of-boundary target, and carries
only low/medium residual risk with a tracked POA&M. **Recommended for authority
to operate** in the assessment context, subject to the POA&M above.
