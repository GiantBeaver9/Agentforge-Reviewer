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
2. **Root Directory:** leave as the repo root — the `Dockerfile` and
   `railway.toml` are at the top level of this standalone repo.
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

### Dashboard access control (strongly recommended for a public URL)
| Var | Meaning |
|---|---|
| `AGENTFORGE_WEB_USER` | HTTP Basic username for the dashboard |
| `AGENTFORGE_WEB_PASSWORD` | HTTP Basic password |

If both are set, every request (except `/healthz`) requires them and the browser
shows a login prompt. **If you deploy publicly without these, anyone who finds
the URL can launch live attacks and spend the target's LLM budget** — the app
prints a loud warning in that case.

### Bind / port (usually automatic)
| Var | Meaning | Default |
|---|---|---|
| `PORT` | Injected by Railway/Heroku | — |
| `AGENTFORGE_WEB_HOST` | Bind host | `0.0.0.0` in the image |
| `AGENTFORGE_WEB_PORT` | Fallback port if `$PORT` unset | `8800` |

### Optional — LLM upgrades (fail soft to the deterministic cores if unset)
| Var | Meaning |
|---|---|
| `REDTEAM_BASE_URL` / `REDTEAM_MODEL` / `REDTEAM_API_KEY` | Local/open model for richer Red Team mutations |
| `JUDGE_BASE_URL` / `JUDGE_MODEL` / `JUDGE_API_KEY` | Independent model for LLM-assisted judging |

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
