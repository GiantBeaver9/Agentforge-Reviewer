# Inter-Agent Contracts

Every message that crosses an agent boundary in AgentForge conforms to a
versioned JSON Schema published here. Producers validate before sending;
consumers validate on receipt. Contract tests (`tests/test_contracts.py`)
verify both sides against these files.

## Message flow

```
Orchestrator ──orchestrator_to_redteam──▶ Red Team
Red Team     ──redteam_to_judge─────────▶ Judge
Judge        ──judge_to_documentation───▶ Documentation  (and ▶ Orchestrator, for coverage/regression state)
any agent    ──error────────────────────▶ caller         (typed failure modes)
```

## Schemas (v1)

| File | Message | From → To |
|------|---------|-----------|
| `v1/orchestrator_to_redteam.schema.json` | `AttackCampaignDirective` | Orchestrator → Red Team |
| `v1/redteam_to_judge.schema.json` | `AttackAttempt` | Red Team → Judge |
| `v1/judge_to_documentation.schema.json` | `Verdict` | Judge → Documentation / Orchestrator |
| `v1/errors.schema.json` | `AgentError` | any agent → caller |

## Shared envelope

Every message carries the same envelope fields so any consumer can route and
correlate without parsing the payload:

`schema_version`, `message_id`, `correlation_id`, `type`, `producer`, `created_at`.

`correlation_id` is stable for the life of a campaign, so a single finding can
be traced Orchestrator → Red Team → Judge → Documentation through the logs.

## Versioning policy

- Schemas are semver'd via `schema_version` (currently `1.0.0`) and live under a
  major-version directory (`v1/`).
- **Additive, optional** field → minor bump, same directory. (An optional
  property that leaves every prior message valid — e.g. `attack_source` on
  `redteam_to_judge`, `decision_path` on `judge_to_documentation` — may keep the
  same `schema_version`, since bumping the `const` would instead *reject* older
  messages, violating the invariant below. Consumers default the field when a
  pre-existing log omits it.)
- **Breaking** change (new required field, removed field, changed enum/type) →
  new major directory (`v2/`), a migration note in `../docs/migrations/`, and
  updated contract tests for both sides. Old consumers keep reading `v1`.
- Never mutate a published schema in place in a way that would reject a message
  a prior version accepted.

## Error handling by code

| `error_code` | Emitted when | Caller should |
|--------------|--------------|---------------|
| `target_unreachable` | target host/DNS/egress denied | abort run, surface to human |
| `target_refused` | target returned an application-level refusal | record as a *failure* verdict, continue |
| `rate_limited` | 429 / provider throttle | back off `retry_after_ms`, then retry |
| `budget_exceeded` | campaign hit `max_usd`/`max_attempts` | halt campaign, Orchestrator re-plans |
| `judge_timeout` | Judge did not return in window | re-queue attempt once, else mark `uncertain` |
| `no_findings_in_window` | N attempts, 0 signal | Orchestrator redirects to another surface |
| `regression_detected` | a fixed exploit reappeared | Orchestrator triggers full regression run |
| `invalid_message` | schema validation failed | drop, log, do not process |
