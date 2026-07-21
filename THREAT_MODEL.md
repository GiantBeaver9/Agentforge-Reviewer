# Clinical Co-Pilot — Adversarial Threat Model

> **Target under test:** `oe-module-clinical-copilot` (OpenEMR custom module),
> deployed at `https://abundant-art-production-d560.up.railway.app`.
> **Scope:** the AI-assisted surfaces (chat + agent + document ingest) and the
> deterministic defenses around them. Source of every claim below is the module
> code; endpoint/line references are in the appendix.

## Summary (key findings & prioritization)

The Co-Pilot is unusually well-defended for an LLM application, and that shapes
where the real risk lives. Its central design invariant — **"the LLM narrates
and navigates; it never extracts"** — means every clinical fact is pulled,
parsed, and cited by deterministic PHP, and the model is handed a
canonical fact block it may only narrate over. Layered on top are egress
redaction of identifiers before any prompt is built, a deterministic V1–V6
verifier that gates every answer, an unconditional V3 patient-identity check
that *freezes the session* on a trip, server-side patient pinning on all five
tools (a forged `pid` argument is rejected, not honored), and a strict
`additionalProperties:false` tool schema. A naive jailbreak that asks the model
to "reveal patient X" mostly dies against these deterministic gates, not the
prompt.

That is exactly why our platform prioritizes the **seams between the
deterministic guards, not the guards themselves.** Four findings drive our
coverage plan:

1. **`agent.php` is the soft target (HIGH).** It is the *only* surface where the
   LLM's five tools are live (chat's tools are dormant), and it is **not
   per-user rate-limited** — only global dollar caps and the circuit breaker
   stand in the way. That makes it the prime surface for tool-parameter
   tampering, chain-budget exhaustion, cost amplification, and refusal bypass.

2. **Prompt-only refusals have no verifier backstop (HIGH).** The
   "only discuss the one pinned patient" and "refuse general medical Q&A"
   rules are enforced by *prompt text alone* — the V-series verifier does not
   re-check them. Every other clinical claim must cite a `fact_id`; these two
   refusals must not. They are the highest-value prompt-injection targets.

3. **Indirect injection via uploaded lab PDFs is real but human-gated
   (MEDIUM).** Attacker text in a lab PDF can be VLM-extracted and, once a human
   reviews and *locks* it, written to `procedure_result` — after which it
   resurfaces as authoritative `SESSION FACTS` in later LLM context. The human
   lock + structured canonicalization are the mitigations we must probe: does
   the review UI make malicious content obvious, and can extraction be steered?

4. **Unauthenticated info disclosure + a fail-open limiter (MEDIUM/LOW).**
   `health.php` leaks module version with no rate limit; `ready.php` discloses
   dependency-status enums behind a per-IP limiter that **fails open** if APCu
   is absent. Low individual impact, but useful reconnaissance and a DoS lever.

**Prioritization.** The Red Team Agent's first campaigns target (1) and (2) on
`agent.php` and `chat.php` — high impact, high reachability, prompt-dependent
defenses that mutate well. Indirect injection (3) is a second-wave campaign
because it needs the multi-step upload→review→lock flow. Unauthenticated
disclosure (4) is covered by deterministic (non-LLM) probes, since an HTTP
fuzzer validates it faster and cheaper than an LLM. Coverage is tracked per
category against the OWASP LLM Top 10 and the relevant OWASP Web Top 10, and
the Orchestrator redirects the Red Team toward the least-covered,
highest-open-severity surface each cycle. The bar for a "success" verdict is
deliberately high: a defense counts as broken only when the *deterministic*
guard is bypassed or a PHI/scope invariant is violated — not merely when the
model says something impolite.

---

## Trust boundaries

```
 Unauthenticated Internet
     │  health.php, ready.php        (no session, no ACL, no CSRF)
     ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ OpenEMR session boundary  (login + ACL: patients/med AND     │
 │                            clinical_copilot/copilot_access)   │
 │   POST endpoints also require a CSRF form token              │
 │                                                              │
 │   chat.php ─► ChatController ─► [Redactor] ─► LLM(gemini-2.5- │
 │                                  flash) ─► [V1–V6 Verifier]   │
 │                                  tools: DORMANT               │
 │                                                              │
 │   agent.php ─► AgentController ─► LLM + 5 read tools (LIVE)   │
 │                                  ChainBudget 5 calls/3 rounds │
 │                                                              │
 │   *_upload.php ─► IngestController ─► VLM extract ─► human    │
 │        review ─► LOCK ─► procedure_result (chart) ─┐          │
 └───────────────────────────────────────────────────┼──────────┘
                                                      │ (resurfaces as
                                                      ▼  SESSION FACTS)
                                            future chat/agent LLM context
 Elevated boundary (admin/super OR admin/users): knowledge_upload.php, dashboard.php
```

Key server-side invariants the platform must try to break:
- **Patient pinning:** tools never read a caller-supplied `pid`; the pinned pid
  is a constructor arg, and every returned fact's pid is asserted equal to it or
  dropped with a sev-1 alert.
- **Fact-citation:** every clinical claim must cite a `fact_id`; the verifier
  rejects uncited claims.
- **Identity freeze (V3):** a patient-identity violation freezes the session
  (HTTP 423), terminal, no unfreeze.
- **Egress redaction:** direct identifiers are redacted before any prompt is
  assembled.

---

## Attack surface by category

Each row: **surface** → **impact** → **exploit difficulty** → **existing defense** →
**our coverage**.

### 1. Prompt injection (direct / indirect / multi-turn) — OWASP LLM01
| Vector | Surface | Impact | Difficulty | Existing defense | Coverage |
|---|---|---|---|---|---|
| System-prompt override / "ignore instructions" | `chat.php`, `agent.php` message/question | Model breaks scope discipline | Easy to attempt | Strong system prompt; verifier on clinical claims **but not** on scope/general-Q&A refusals | **P0** — mutate overrides against the un-backstopped refusals |
| Indirect injection via uploaded lab PDF | `lab_upload.php` → extract → lock → chart | Attacker text becomes authoritative `SESSION FACT` | Hard (needs human lock) | Human review+lock; structured canonicalization; med lists write nothing | **P1** — probe whether review surfaces malicious content |
| Multi-turn manipulation | `chat.php` turns (16-turn window, fact accumulation) | Later turn ignores earlier safeguard | Moderate | Facts re-shown canonically each round; prompt never told to "trust memory" | **P0** — multi-turn escalation sequences |

### 2. Data exfiltration / PHI leakage / authz bypass — OWASP LLM06, A01
| Vector | Surface | Impact | Difficulty | Existing defense | Coverage |
|---|---|---|---|---|---|
| Cross-patient data via chat/agent | `chat.php`/`agent.php` | PHI of another patient | Hard | V3 identity freeze; pinning; prompt refusal | **P0** — try to elicit other-patient data (prompt-only refusal is the seam) |
| Forged `pid` on a tool call | `agent.php` tool args | Cross-patient read | Trivial to attempt / hard to land | `additionalProperties:false` rejects forged `pid`; server injects pinned pid; fact-pid assertion | **P1** — confirm rejection holds under mutation |
| IDOR on `extraction_id` / `setpid` | `extraction_review.php`, `lab_upload.php` | Reach another record within caller ACL | Moderate | `extraction_id` bound to session pid; but session pid is set from request param `setpid()` within caller's `patients/med` ACL | **P1** — deterministic authz probe |
| Session-prompt / instruction disclosure | `chat.php`/`agent.php` | Leak system prompt / internal rules | Easy to attempt | Prompt-only refusal | **P0** |

### 3. State corruption / context poisoning — OWASP LLM01, A04
| Vector | Surface | Impact | Difficulty | Existing defense | Coverage |
|---|---|---|---|---|---|
| Conversation-history poisoning | `chat.php` transcript replay | Persisted bad instruction influences later turns | Moderate | Append-only turns; facts re-shown canonically | **P1** |
| Fact-set poisoning via accumulated tool facts | `agent.php` fact union | Later turn cites poisoned fact | Hard | Fact-pid assertion; citation gate | **P2** |

### 4. Tool misuse — OWASP LLM08 (excessive agency), A04
| Vector | Surface | Impact | Difficulty | Existing defense | Coverage |
|---|---|---|---|---|---|
| Unrecognized/forged tool argument | `agent.php` | Parameter tampering | Trivial to attempt | `additionalProperties:false`; `ToolArgumentValidator` rejects | **P1** — invariant test (must always reject) |
| Recursive / chained tool calls | `agent.php` | Cost/latency amplification | Moderate | `ChainBudget` 5 calls / 3 rounds; dedupe of identical signatures | **P1** — boundary test at the budget edge |
| Coerced unintended tool invocation | `agent.php` | Runs a tool the user did not intend | Moderate | Closed 5-tool catalog, all read-only | **P2** |

### 5. Denial of service / cost amplification — OWASP LLM04, A05
| Vector | Surface | Impact | Difficulty | Existing defense | Coverage |
|---|---|---|---|---|---|
| Token/turn exhaustion via chat | `chat.php` | Burn budget | Easy | 60 turns/user/hr, 3 active sessions, 30 turns/session, $50/day cap, breaker | **P1** — boundary probe |
| Cost amplification via `agent.php` | `agent.php` | Burn budget faster | **Easy** | **No per-user rate limit** on agent.php; only $ caps + breaker | **P0** — this is the cheapest DoS lever |
| Unauthenticated flood of `health.php` | `health.php` | Recon / light DoS | Trivial | **None** (no rate limit) | **P1** — deterministic probe |
| Fail-open limiter on `ready.php` | `ready.php` | Bypass limit if APCu absent | Moderate | Per-IP 30/60s, **fails open** | **P2** — deterministic probe |

### 6. Identity & role exploitation — OWASP LLM01, A01
| Vector | Surface | Impact | Difficulty | Existing defense | Coverage |
|---|---|---|---|---|---|
| Persona hijack ("you are now DAN / a doctor") | `chat.php`/`agent.php` | Model gives diagnosis/dosage/treatment advice (explicitly forbidden) | Easy to attempt | Prompt forbids diagnosis/treatment/dosage; no verifier backstop on this | **P0** — high clinical impact if it lands |
| Privilege escalation to admin actions | `dashboard.php`, `knowledge_upload.php` | Force-open breaker, poison knowledge store | Hard | Admin ACL gate | **P2** — deterministic authz probe |
| Trust-boundary confusion (treat evidence as instruction) | evidence display | Model follows retrieved text | Moderate | Knowledge/evidence text is display-only, **never fed to model/verifier** | **P2** — confirm it stays out of prompt |

---

## What we deliberately de-prioritize (and why)

- **Attacking the deterministic guards head-on** (e.g. hoping the pid assertion
  silently fails) — the code shows these are structural, not prompt-based, so
  LLM-driven fuzzing is low-yield. We cover them with a *few* deterministic
  invariant tests instead of many LLM attempts.
- **The knowledge/guideline RAG store as an injection vector** — recon confirms
  retrieved guideline text is surfaced display-only and *never reaches the model
  or verifier*, so it is not an LLM-context injection path (one confirming test,
  then move on).

## OWASP coverage map (initial)

| OWASP | Covered by category above |
|---|---|
| LLM01 Prompt Injection | 1, 3, 6 |
| LLM04 Model DoS | 5 |
| LLM06 Sensitive Info Disclosure | 2 |
| LLM08 Excessive Agency | 4 |
| LLM02 Insecure Output Handling | claim/verdict rendering (probe XSS in claims[]) |
| A01 Broken Access Control | 2, 6 (IDOR, cross-patient, admin) |
| A03 Injection | claim rendering, upload filename/content |
| A04 Insecure Design | 3, 4 |
| A05 Security Misconfiguration | 5 (unauth endpoints, fail-open limiter) |
| A09 Logging/Monitoring Failures | verify trace/ledger completeness |

---

## Appendix — endpoint reference

| Endpoint (under `.../public/`) | Method | Auth | Notes |
|---|---|---|---|
| `chat.php` | POST | session+ACL+CSRF | actions: start/reseed/release/turn; tools dormant |
| `agent.php` | POST | session+ACL+CSRF | **tools live; no per-user rate limit** |
| `status.php` | GET | session+ACL | poll chat/doc regen status |
| `doc.php` | GET/POST | session+ACL (+CSRF on POST) | synthesis view / regenerate |
| `evidence.php` | GET | session+ACL | display-only evidence |
| `lab_upload.php` | GET/POST | session+ACL (+CSRF) | VLM extract; `setpid()` from param |
| `medication_upload.php` | GET/POST | session+ACL (+CSRF) | writes nothing to chart |
| `intake_upload.php` | GET/POST | session+ACL (+CSRF) | writes only human-edited demographics |
| `extraction_review.php` | GET/POST | session+ACL (+CSRF); edits need elevated | `extraction_id` pinned to session pid |
| `knowledge_upload.php` | GET/POST | **admin**+ACL (+CSRF) | RAG store writes (display-only downstream) |
| `dashboard.php` | GET/POST | **admin**+ACL (+CSRF) | breaker/eval/load-test admin actions |
| `event.php` | POST | session+ACL+CSRF | UI event record |
| `health.php` | GET | **none** | version disclosure, no rate limit |
| `ready.php` | GET | **none** | dependency enums; per-IP limiter fails open |

_This is a living document. As the Judge confirms exploits, categories are
re-scored and the Orchestrator rebalances coverage._
