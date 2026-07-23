# Deploying AgentForge as a standalone service

AgentForge runs as its **own** service, separate from the OpenEMR instance it
tests, and points at **any** Clinical Co-Pilot deployment via environment
variables. Nothing about the target is hardcoded — swap the address and
credentials and it re-targets.

The deployable unit is the **web dashboard** (`agentforge.web`): a control panel +
viewer that launches campaigns/probes against the configured target. It is
stdlib-based; the container installs only `httpx`, `pydantic`, `jsonschema`,
`python-dotenv`.

---

## Railway (Dockerfile deploy)

1. **New service → Deploy from GitHub repo**, pick this repo/branch.
2. **Settings → Root Directory:** set to `agentforge` (so `Dockerfile` /
   `railway.toml` are found).
3. Railway auto-detects the Dockerfile and builds. It injects `$PORT`; the app
   binds `0.0.0.0:$PORT` automatically (via `AGENTFORGE_WEB_HOST=0.0.0.0` in the
   image).
4. Set the environment variables below (Settings → Variables).
5. Deploy. Open the generated URL — you'll get the dashboard (behind the auth
   prompt if you set credentials, which you should).

Health checks hit `/healthz` (unauthenticated) — already wired in `railway.toml`.

> Other hosts (Render, Fly.io, Cloud Run, plain Docker) work the same way: build
> the `agentforge/Dockerfile`, provide the env vars, expose `$PORT`.
> Plain Docker: `docker build -t agentforge agentforge/ && docker run -p 8800:8800
> --env-file agentforge/.env agentforge`.

---

## Environment variables

### Target under test (required — this is what makes it reusable)
| Var | Meaning | Example |
|---|---|---|
| `AGENTFORGE_TARGET_BASE_URL` | Base URL of the OpenEMR instance to attack | `https://my-openemr.up.railway.app` |
| `AGENTFORGE_TARGET_USERNAME` | Login user on that instance | `admin` |
| `AGENTFORGE_TARGET_PASSWORD` | Login password | `pass` |
| `AGENTFORGE_TARGET_AUTH_MODE` | `session` (default) | `session` |

Point these at a **different** target and AgentForge attacks that one instead —
no code change.

### Dashboard access control (REQUIRED — the login gate)
| Var | Meaning |
|---|---|
| `AGENTFORGE_WEB_USER` | HTTP Basic username for the dashboard |
| `AGENTFORGE_WEB_PASSWORD` | HTTP Basic password |

Auth is **mandatory and fail-closed**. Every route except `/healthz` requires a
valid login; the panel can launch runs (even a dry-run spins up a campaign), so
an open panel is a self-DoS vector and is not allowed. Three states:

- **Both vars set** → the browser shows a login prompt; valid credentials serve,
  bad/missing ones get `401`.
- **Either var unset** → the dashboard is **locked**: every route except
  `/healthz` returns `503` ("authentication is not configured…"). Nothing runs.
- `/healthz` is always open (no data) so Railway's liveness probe still works.

Set both in Railway → **Variables**, then redeploy. The startup log prints
`auth: HTTP Basic REQUIRED …` when configured, or `auth: LOCKED …` when not.

#### How to verify the gate (for a reviewer)

```bash
BASE=https://your-agentforge.up.railway.app

# 1) No credentials -> refused (401 once configured; 503 if not yet configured):
curl -s -o /dev/null -w "%{http_code}\n" "$BASE/api/state"          # 401

# 2) A spend/live action is refused without login:
curl -s -o /dev/null -w "%{http_code}\n" -X POST "$BASE/api/campaign" \
     -H 'content-type: application/json' -d '{"dry_run":false}'      # 401

# 3) With credentials -> allowed:
curl -s -o /dev/null -w "%{http_code}\n" -u "$AGENTFORGE_WEB_USER:$AGENTFORGE_WEB_PASSWORD" \
     "$BASE/api/state"                                               # 200

# 4) Liveness stays open (no auth, no data):
curl -s "$BASE/healthz"                                             # {"ok": true, ...}
```

Automated proof: `tests/test_web.py::test_fail_closed_when_auth_unconfigured`
and `::test_healthz_open_and_auth_gate`.

### Bind / port (usually automatic)
| Var | Meaning | Default |
|---|---|---|
| `PORT` | Injected by Railway/Heroku | — |
| `AGENTFORGE_WEB_HOST` | Bind host | `0.0.0.0` in the image |
| `AGENTFORGE_WEB_PORT` | Fallback port if `$PORT` unset | `8800` |

### Optional — turn on the LLMs

Both agents use deterministic cores by default. Set a role's `*_BASE_URL` (any
OpenAI-compatible `/chat/completions` endpoint) to switch that role to an LLM;
leave it empty to stay deterministic. The dashboard header shows which are
active, and the campaign log states it per run. **No code change or toggle** —
set the vars and redeploy.

| Role | Vars | Notes |
|---|---|---|
| Judge | `JUDGE_BASE_URL` / `JUDGE_MODEL` / `JUDGE_API_KEY` | Independent frontier model recommended; refines uncertain verdicts |
| Red Team | `REDTEAM_BASE_URL` / `REDTEAM_MODEL` / `REDTEAM_API_KEY` | Generates attack variants; use a model that won't refuse offensive prompts |

Concrete examples (pick one per role):

```
# OpenAI
JUDGE_BASE_URL=https://api.openai.com/v1
JUDGE_MODEL=gpt-4o-mini
JUDGE_API_KEY=sk-...

# OpenRouter (gives you Claude/others behind one OpenAI-compatible URL)
REDTEAM_BASE_URL=https://openrouter.ai/api/v1
REDTEAM_MODEL=meta-llama/llama-3.1-8b-instruct
REDTEAM_API_KEY=sk-or-...

# Local runtime (LM Studio / Ollama / vLLM) — free, no refusals, private.
# Best for the Red Team; must be reachable from the service (localhost only if
# you run AgentForge locally, else point at the host's IP / a tunnel).
REDTEAM_BASE_URL=http://localhost:1234/v1          # LM Studio default (Ollama: :11434/v1)
REDTEAM_MODEL=<the model you loaded>
REDTEAM_API_KEY=lm-studio                          # any non-empty string
```

### Optional — durable history (Trends over time)

The dashboard's **"Trends over time"** card retains one snapshot per campaign
(totals + per-category pass rates) so you can see the defended-rate trend across
runs. It uses two backends, chosen automatically:

| Backend | When | Durability |
|---|---|---|
| **Postgres** | `DATABASE_URL` is set | Survives redeploys — **recommended in prod** |
| SQLite | `DATABASE_URL` unset | Local file `runs/history.db`; **lost on redeploy** (ephemeral PaaS disk) |

On **Railway**: open your project → **New → Database → Add PostgreSQL**. Railway
provisions it and injects `DATABASE_URL` into your service automatically — no
manual value to copy. Redeploy and the app creates its `campaign_snapshots`
table on first write. `psycopg` is already in `requirements*.txt`; it's imported
only when `DATABASE_URL` points at Postgres, so nothing changes if you skip it.

| Var | Meaning | Default |
|---|---|---|
| `DATABASE_URL` | Postgres connection string (Railway injects it) | unset → SQLite |
| `AGENTFORGE_HISTORY_DB` | Local SQLite path (only when `DATABASE_URL` unset) | `runs/history.db` |

> **Recommended when you have the hardware:** run the Red Team on a local
> open model via **LM Studio** or Ollama. It's free, never refuses offensive-
> security prompts, and keeps attack generation off any third-party API. For a
> *deployed* Railway service the local runtime must be reachable (host IP or a
> tunnel); for local dev it's just `localhost`.

The deployed service needs outbound egress to whatever endpoint you set; if the
LLM call fails, the agent falls back to its deterministic core (a run never
stalls on an LLM outage).

### Optional — budget guardrails
`AGENTFORGE_MAX_USD_PER_RUN`, `AGENTFORGE_MAX_ATTEMPTS_PER_CAMPAIGN`,
`AGENTFORGE_MAX_TURNS`. The dashboard also clamps every **live** run it launches
to ≤3 rounds, ≤6 attempts/round, ≤$2 regardless of form input.

---

## Networking

The AgentForge service needs outbound HTTPS to:
- the **target** OpenEMR instance (required), and
- your **LLM endpoints** (only if you set `REDTEAM_*` / `JUDGE_*`).

On Railway both services can be public; AgentForge reaches the target over the
public internet using standard TLS (system CA — no proxy CA needed outside the
build sandbox). If you keep both in one Railway project you can also use the
target's private domain for `AGENTFORGE_TARGET_BASE_URL`.

---

## Operational notes

- **Ephemeral storage.** Run logs write to `/app/runs` inside the container and
  are lost on redeploy/restart — fine for interactive use. Attach a volume at
  `/app/runs` if you want run history to persist.
- **Jobs are in-memory.** A launched campaign runs in a background thread; a
  container restart cancels in-flight jobs (completed runs are already on disk).
- **Cost safety.** Live attacks spend the *target's* LLM budget. Keep runs small,
  set the dashboard auth, and prefer dry-run for demos.
- **Health:** `GET /healthz` → `{"ok": true}` (no auth) for uptime probes.

## Smoke test after deploy

```bash
curl -s https://<your-agentforge-url>/healthz          # {"ok": true, ...}
# then open the URL in a browser, log in, and click "Launch campaign"
# with Dry-run checked to confirm the panel works before going live.
```
