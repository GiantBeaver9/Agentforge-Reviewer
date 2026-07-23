# Committed run evidence

Live campaign logs are written under `runs/` which is **git-ignored** (ephemeral
PaaS disk), so no machine-readable trace normally ships with the repo. This
directory fixes that with a committed, inspectable artifact.

## `sample_campaign_trace.jsonl`

A single campaign's full event trace, filtered to one `correlation_id`, exactly
as the append-only observability store writes it — every hop of
Orchestrator → Red Team → Judge → Documentation, plus the cost/regression/typed-
error events, sharing one id.

**Honest provenance:** this sample was generated **offline against the mock
target** (`campaign --dry-run --mock-policy leaky`), not against the live Railway
deployment. It is committed to show the **wire shape and end-to-end flow** a
reviewer can grep and validate — not to stand in as live evidence. It is
**PHI-redacted** by the same code path a live run uses (`src/agentforge/redact.py`),
so it doubles as proof the redaction lands before anything is persisted (grep it:
no `A1c … 8.1%`, no medication names — only `[PHI-REDACTED]` / `[MED-REDACTED]`).

Inspect it:

```bash
# every hop of one finding, one id:
python -c "import json; [print(e['producer'], e['type']) for e in map(json.loads, open('docs/evidence/sample_campaign_trace.jsonl'))]"

# confirm it is PHI-clean:
grep -c 'PHI-REDACTED' docs/evidence/sample_campaign_trace.jsonl   # >0
grep -c '8.1%\|metformin' docs/evidence/sample_campaign_trace.jsonl # 0
```

## Live-run evidence — status

The hard-gate expectation is a live run against the deployed target. Two honest
facts a reviewer should have:

1. **The platform is built to run live** — the authenticated client + CSRF
   handshake are verified (`docs/LIVE_RUN_EVIDENCE.md`), and the CLI runs the
   full loop against the Railway host with `campaign --pid 1`.
2. **This repo does not ship a committed *live* trace.** The campaign ids cited
   in `docs/LIVE_RUN_EVIDENCE.md` (e.g. `camp-0cc5dbaf`) are from prior live
   sessions whose raw logs were ephemeral and are not in the tree, and the build
   sandbox that produced this commit has **outbound egress proxy-blocked (403)**,
   so a fresh live run cannot be executed from here.

To produce committed live evidence for submission, run from an environment with
egress + credentials and commit the redacted trace here:

```bash
PYTHONPATH=src python -m agentforge.cli campaign --pid 1 --rounds 2 --max-attempts 4
# then copy the redacted runs/<id>.observability.jsonl into docs/evidence/
```

The observability log is already PHI-redacted at write time, so the copied trace
is safe to commit.
