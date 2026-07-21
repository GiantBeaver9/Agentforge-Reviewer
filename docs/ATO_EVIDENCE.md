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

- **Automated assurance:** 63 passing tests (contracts, agents, drift check,
  probes, load, web) — `pytest tests/ -q`.
- **Live verification:** auth handshake + full four-agent loop run against the
  deployed target; the co-pilot defended all seeded LLM attacks
  (`LIVE_RUN_EVIDENCE.md`).
- **Deterministic findings:** 3 confirmed on the unauth surface
  (`VULNERABILITY_REPORTS.md`).
- **Performance baseline:** `LOAD_TEST.md`.

## 6. Residual risk

| Risk | Likelihood | Impact | Disposition |
|---|---|---|---|
| Judge drifts *within* rubric bounds | Low | Med | Mitigated by ground-truth set; not eliminated — human spot-review of a sample each cycle. |
| Red Team finds a novel attack the ground truth doesn't cover | Med | Med | Accept + monitor; human review of `uncertain` verdicts is the catch-net. |
| A live run transits PHI in a target leak response | Low | High | Responses are not persisted to shareable artifacts; reports are PHI-scrubbed by policy (see `judge.py` rationale rule). |
| LLM cost overrun | Low | Low | Hard caps enforced in code (Orchestrator + GUI clamps). |

## 7. POA&M (open items)

| # | Item | Priority | Owner |
|---|---|---|---|
| 1 | Wire a live independent Judge model (adapter built; needs egress+key) | Med | Eng |
| 2 | Automate the human-review sample for `uncertain` verdicts | Low | AppSec |
| 3 | Persist observability to a queryable DB for multi-run trend (JSONL today) | Low | Eng |

## 8. Recommendation

AgentForge implements its in-boundary controls with test and live evidence, has a
defined and least-privilege interface to the out-of-boundary target, and carries
only low/medium residual risk with a tracked POA&M. **Recommended for authority
to operate** in the assessment context, subject to the POA&M above.
