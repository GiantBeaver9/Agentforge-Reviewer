"""AgentForge local web dashboard — a control panel + viewer.

Run it locally with no extra dependencies (pure standard library):

    cd agentforge
    PYTHONPATH=src python -m agentforge.web         # then open http://127.0.0.1:8800

What it gives you:
* Launch a **campaign** (offline dry-run by default, or live against the target
  with attempt/round caps) and a **probe** sweep, from buttons.
* Watch the run's coverage / pass-rate / findings update as it progresses.
* Browse past runs (observability logs, vuln reports, probe results) written
  under ``runs/``.

Safety: live runs spend the target's LLM budget, so the form defaults to a
dry-run, caps attempts/rounds, and clamps the live budget. Everything the
dashboard does is also available on the CLI (``agentforge.cli``); this is just a
GUI over the same agents and the same observability store.
"""
from __future__ import annotations

import base64
import glob
import hmac
import json
import os
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
RUNS_DIR = ROOT / "runs"
CASES_DIR = ROOT / "evals" / "cases"

# In-memory job registry. Each job: {id, kind, status, log[], result, error}.
_JOBS: dict[str, dict] = {}
_JOBS_LOCK = threading.Lock()

# Hard ceilings the GUI will not exceed on a LIVE run, regardless of form input.
LIVE_MAX_ATTEMPTS = 6
LIVE_MAX_ROUNDS = 3
LIVE_MAX_USD = 2.0


# --------------------------------------------------------------------------- #
#  Job runners (executed on a background thread)
# --------------------------------------------------------------------------- #
def _set(job_id: str, **kw) -> None:
    with _JOBS_LOCK:
        _JOBS[job_id].update(kw)


def _log(job_id: str, msg: str) -> None:
    with _JOBS_LOCK:
        _JOBS[job_id]["log"].append(msg)


def _load_seed_cases(category):
    from agentforge.agents.redteam import SeedCase
    seeds = []
    for f in sorted(glob.glob(str(CASES_DIR / "*.json"))):
        for d in json.loads(Path(f).read_text()):
            if category and d["attack_category"] != category:
                continue
            if d["target_surface"] in ("chat", "agent"):
                seeds.append(SeedCase.from_eval(d))
    return seeds


def _run_campaign_job(job_id: str, params: dict) -> None:
    from agentforge import config as cfgmod
    from agentforge.agents.orchestrator import CampaignState, OrchestratorAgent
    from agentforge.observability.store import ObservabilityStore
    from agentforge.pipeline import run_campaign
    from agentforge.target.client import MockTargetClient, OpenEmrTargetClient, TargetClient

    try:
        dry_run = bool(params.get("dry_run", True))
        category = params.get("category") or None
        pid = int(params.get("pid", 1))
        if dry_run:
            rounds = max(1, int(params.get("rounds", 2)))
            max_attempts = max(1, int(params.get("max_attempts", 6)))
            max_usd = float(params.get("max_usd", 2.0))
        else:  # clamp live runs to protect the target's budget
            rounds = min(LIVE_MAX_ROUNDS, max(1, int(params.get("rounds", 2))))
            max_attempts = min(LIVE_MAX_ATTEMPTS, max(1, int(params.get("max_attempts", 4))))
            max_usd = min(LIVE_MAX_USD, float(params.get("max_usd", 1.5)))

        cfg = cfgmod.load()
        _set(job_id, status="running")
        target: TargetClient
        if dry_run:
            policy = params.get("mock_policy", "defended")
            target = MockTargetClient(policy=policy)
            _log(job_id, f"dry-run mock target (policy={policy})")
        else:
            if not cfg.target.base_url:
                _set(job_id, status="error",
                     error="AGENTFORGE_TARGET_BASE_URL is not set — set it to the "
                           "target's URL (e.g. https://your-openemr.up.railway.app)")
                return
            _log(job_id, f"live target {cfg.target.base_url} — logging in…")
            client = OpenEmrTargetClient(cfg.target, csrf_pid=pid)
            client.login()
            target = client
            _log(job_id, "authenticated; starting campaign "
                         f"(rounds={rounds}, attempts/round={max_attempts})")

        seeds = _load_seed_cases(category)
        if not seeds:
            _set(job_id, status="error", error="no seed cases for that category")
            return

        # Auto-engage the LLMs when they're configured (JUDGE_* / REDTEAM_* env).
        # build_* return None when the base_url is unset, so an unconfigured
        # deploy silently stays on the deterministic cores — no toggle needed.
        from agentforge.agents.judge import JudgeAgent
        from agentforge.agents.llm import build_judge_llm, build_redteam_llm
        judge_llm = build_judge_llm(cfg)
        redteam_llm = build_redteam_llm(cfg)
        judge = JudgeAgent(llm=judge_llm, model_name=cfg.judge.model) if judge_llm else JudgeAgent()
        _log(job_id, "judge: " + (f"LLM {cfg.judge.model}" if judge_llm else "deterministic rubric")
                     + " | red team: " + (f"LLM {cfg.redteam.model}" if redteam_llm else "mutation operators"))

        run_id = f"camp-{uuid4().hex[:8]}"
        store = ObservabilityStore(RUNS_DIR / f"{run_id}.observability.jsonl")
        # Dry-run is for generating test data offline, so let every requested
        # round run (don't stop early on no-new-findings); live keeps the halt.
        empty_windows = (rounds + 1) if dry_run else 3
        orch = OrchestratorAgent(store, CampaignState(
            max_attempts=max_attempts * rounds, max_usd=max_usd,
            halt_after_empty_windows=empty_windows))
        result = run_campaign(
            target=target, seeds=seeds, store=store, orchestrator=orch,
            judge=judge, redteam_llm=redteam_llm,
            pinned_pid=pid, max_rounds=rounds, max_attempts_per_round=max_attempts,
        )

        reports_path = RUNS_DIR / f"{run_id}.reports.json"
        reports_path.write_text(json.dumps([r.to_dict() for r in result.reports], indent=2))

        summary = store.summary()
        # Persist a cross-run snapshot for the trends view. Fail-soft: a history
        # write (e.g. Postgres unreachable) must never fail a completed campaign.
        try:
            from agentforge.observability.history import HistoryStore
            hist = HistoryStore(sqlite_path=RUNS_DIR / "history.db")
            hist.record_snapshot(run_id, summary, mode="dry-run" if dry_run else "live")
            _log(job_id, f"history snapshot recorded ({hist.backend})")
        except Exception as exc:  # noqa: BLE001
            _log(job_id, f"note: history snapshot skipped ({type(exc).__name__}: {exc})")
        _log(job_id, f"done: {summary['attempts']} attempts, "
                     f"{summary['verdicts']} verdicts, {summary['open_findings']} findings, "
                     f"halt={result.halt.reason if result.halt else None}")
        _set(job_id, status="done", result={
            "run_id": run_id,
            "observability": store.path.name,
            "summary": summary,
            "reports": [r.to_dict() for r in result.reports],
            "halt": result.halt.reason if result.halt else None,
        })
    except Exception as exc:  # noqa: BLE001 — surface any failure to the UI
        _set(job_id, status="error", error=f"{type(exc).__name__}: {exc}")
        _log(job_id, traceback.format_exc().splitlines()[-1])


def _run_probe_job(job_id: str, params: dict) -> None:
    from agentforge import config as cfgmod
    from agentforge.probes import ProbeHarness
    try:
        cfg = cfgmod.load()
        if not cfg.target.base_url:
            _set(job_id, status="error",
                 error="AGENTFORGE_TARGET_BASE_URL is not set — set it to the "
                       "target's URL (e.g. https://your-openemr.up.railway.app)")
            return
        _set(job_id, status="running")
        _log(job_id, f"probing {cfg.target.base_url}")
        results = ProbeHarness(cfg.target.base_url).run_all()
        out = RUNS_DIR / f"probes-{uuid4().hex[:8]}.json"
        RUNS_DIR.mkdir(exist_ok=True)
        out.write_text(json.dumps([r.to_dict() for r in results], indent=2))
        findings = [r.to_dict() for r in results if not r.secure]
        _log(job_id, f"{len(findings)} finding(s) / {len(results)} probes")
        _set(job_id, status="done", result={
            "file": out.name,
            "results": [r.to_dict() for r in results],
            "findings": findings,
        })
    except Exception as exc:  # noqa: BLE001
        _set(job_id, status="error", error=f"{type(exc).__name__}: {exc}")
        _log(job_id, traceback.format_exc().splitlines()[-1])


def _run_loadtest_job(job_id: str, params: dict) -> None:
    from agentforge import config as cfgmod
    from agentforge.loadtest import sweep
    try:
        cfg = cfgmod.load()
        if not cfg.target.base_url:
            _set(job_id, status="error",
                 error="AGENTFORGE_TARGET_BASE_URL is not set — set it to the "
                       "target's URL (e.g. https://your-openemr.up.railway.app)")
            return
        # Bounded from the UI: hits the cheap unauth health endpoint (no LLM
        # budget), but keep the burst modest against a live target.
        n = min(200, max(10, int(params.get("n", 50))))
        _set(job_id, status="running")
        _log(job_id, f"baseline load test: {n} req/level vs {cfg.target.base_url} (health.php)")
        summaries = [s.summary() for s in sweep(cfg.target.base_url, n=n)]
        out = RUNS_DIR / f"loadtest-{uuid4().hex[:8]}.json"
        RUNS_DIR.mkdir(exist_ok=True)
        out.write_text(json.dumps(summaries, indent=2))
        _log(job_id, f"done: {len(summaries)} concurrency levels, {n} req each")
        _set(job_id, status="done", result={"file": out.name, "levels": summaries})
    except Exception as exc:  # noqa: BLE001
        _set(job_id, status="error", error=f"{type(exc).__name__}: {exc}")
        _log(job_id, traceback.format_exc().splitlines()[-1])


def _start_job(kind: str, runner, params: dict) -> str:
    job_id = f"job-{uuid4().hex[:8]}"
    with _JOBS_LOCK:
        _JOBS[job_id] = {"id": job_id, "kind": kind, "status": "queued",
                         "log": [], "result": None, "error": None, "params": params}
    threading.Thread(target=runner, args=(job_id, params), daemon=True).start()
    return job_id


# --------------------------------------------------------------------------- #
#  Read helpers for the viewer
# --------------------------------------------------------------------------- #
def _list_runs() -> dict:
    from agentforge.observability.store import ObservabilityStore
    RUNS_DIR.mkdir(exist_ok=True)
    campaigns = []
    for f in sorted(glob.glob(str(RUNS_DIR / "*.observability.jsonl")), reverse=True):
        p = Path(f)
        try:
            summary = ObservabilityStore(p).summary()
        except Exception:  # noqa: BLE001
            summary = {"attempts": 0, "verdicts": 0, "open_findings": 0, "coverage": []}
        campaigns.append({"file": p.name, "summary": summary})
    probes = [Path(f).name for f in sorted(glob.glob(str(RUNS_DIR / "probes-*.json")), reverse=True)]
    loadtests = [Path(f).name for f in sorted(glob.glob(str(RUNS_DIR / "loadtest-*.json")), reverse=True)]
    return {"campaigns": campaigns, "probes": probes, "loadtests": loadtests}


def _read_json_file(name: str):
    # Only serve files from RUNS_DIR (no path traversal).
    safe = Path(name).name
    p = RUNS_DIR / safe
    if not p.exists():
        return None
    try:
        if safe.endswith(".jsonl"):
            from agentforge.observability.store import ObservabilityStore
            store = ObservabilityStore(p)
            return {"summary": store.summary(), "open_findings": store.open_findings(),
                    "timeline": store.timeline(),
                    "agent_responses": store.agent_responses()}
        return json.loads(p.read_text())
    except Exception as exc:  # noqa: BLE001 — a partial/malformed run file is not fatal
        return {"error": f"could not parse {safe}: {type(exc).__name__}"}


def _history() -> dict:
    """Cross-run trend series for the dashboard. Fail-soft: an unreachable DB
    returns an empty series with the error, never a 500."""
    try:
        from agentforge.observability.history import HistoryStore
        return HistoryStore(sqlite_path=RUNS_DIR / "history.db").trends()
    except Exception as exc:  # noqa: BLE001
        return {"backend": "unavailable", "count": 0, "series": [],
                "error": f"{type(exc).__name__}: {exc}"}


def _categories() -> list[str]:
    cats = set()
    for f in glob.glob(str(CASES_DIR / "*.json")):
        for d in json.loads(Path(f).read_text()):
            cats.add(d["attack_category"])
    return sorted(cats)


def _llm_status() -> dict:
    """Report which LLMs are configured (JUDGE_* / REDTEAM_* env), for the UI."""
    from agentforge import config as cfgmod
    cfg = cfgmod.load()
    return {
        "judge": cfg.judge.model if cfg.judge.base_url else None,
        "redteam": cfg.redteam.model if cfg.redteam.base_url else None,
        "target": cfg.target.base_url,
    }


# --------------------------------------------------------------------------- #
#  HTTP handler
# --------------------------------------------------------------------------- #
def _auth_credentials() -> tuple[str, str] | None:
    """Optional HTTP Basic credentials from the environment.

    When ``AGENTFORGE_WEB_USER`` and ``AGENTFORGE_WEB_PASSWORD`` are both set, the
    dashboard requires them on every request except ``/healthz``. This matters
    for a public deployment: the panel can spend the target's LLM budget and
    drive attacks, so it must not be left open. Locally (loopback) it is optional.
    """
    user = os.environ.get("AGENTFORGE_WEB_USER")
    pw = os.environ.get("AGENTFORGE_WEB_PASSWORD")
    return (user, pw) if user and pw else None


class Handler(BaseHTTPRequestHandler):
    server_version = "AgentForge/1.0"

    def log_message(self, *args):  # quiet the default stderr access log
        pass

    def _check_auth(self) -> bool:
        """Mandatory HTTP Basic auth. Returns False (and writes the response)
        when the request is not authorized. Every route except ``/healthz``
        goes through this — the panel can launch runs (even dry-run ones spin up
        campaigns and hit local resources), so an open panel is a self-DoS
        vector. Fail-closed: with no credentials configured, nothing serves.

        Three states:
          * not configured           -> 503, panel is locked until creds are set
          * configured, bad/missing  -> 401 + WWW-Authenticate (browser prompts)
          * configured, valid Basic   -> allow
        """
        creds = _auth_credentials()
        if creds is None:
            # Fail-closed: refuse rather than run open. No WWW-Authenticate — a
            # login prompt would be futile since no credentials exist to accept.
            body = (b'{"error":"dashboard authentication is not configured; set '
                    b'AGENTFORGE_WEB_USER and AGENTFORGE_WEB_PASSWORD to enable login"}')
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return False
        header = self.headers.get("Authorization", "")
        if header.startswith("Basic "):
            try:
                decoded = base64.b64decode(header[6:]).decode("utf-8", "replace")
                user, _, pw = decoded.partition(":")
                # constant-time compare to avoid timing oracles
                if (hmac.compare_digest(user, creds[0])
                        and hmac.compare_digest(pw, creds[1])):
                    return True
            except Exception:  # noqa: BLE001
                pass
        body = b'{"error":"authentication required"}'
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="AgentForge"')
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return False

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj).encode(), "application/json")

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0) or 0)
        if not length:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return {}

    def do_GET(self):  # noqa: N802
        # A single bad file or unexpected error must never take the panel down;
        # always return a clean JSON error rather than a half-sent 500.
        try:
            path = urlparse(self.path).path
            if path == "/healthz":          # unauthenticated liveness for the PaaS
                return self._json({"ok": True, "service": "agentforge"})
            if not self._check_auth():
                return
            self._route_get(path)
        except Exception as exc:  # noqa: BLE001
            self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)

    def _route_get(self, path: str) -> None:
        if path in ("/", "/index.html"):
            return self._send(200, _INDEX_HTML.encode(), "text/html; charset=utf-8")
        if path == "/api/state":
            return self._json({"runs": _list_runs(), "categories": _categories(),
                               "llm": _llm_status(),
                               "live_caps": {"max_attempts": LIVE_MAX_ATTEMPTS,
                                             "max_rounds": LIVE_MAX_ROUNDS,
                                             "max_usd": LIVE_MAX_USD}})
        if path.startswith("/api/job/"):
            job_id = path.rsplit("/", 1)[-1]
            with _JOBS_LOCK:
                job = _JOBS.get(job_id)
            return self._json(job or {"error": "unknown job"}, 200 if job else 404)
        if path.startswith("/api/file/"):
            name = path.split("/api/file/", 1)[1]
            data = _read_json_file(name)
            return self._json(data if data is not None else {"error": "not found"},
                              200 if data is not None else 404)
        if path == "/api/history":
            return self._json(_history())
        return self._json({"error": "not found"}, 404)

    def do_POST(self):  # noqa: N802
        try:
            if not self._check_auth():
                return
            path = urlparse(self.path).path
            body = self._body()
            if path == "/api/campaign":
                return self._json({"job_id": _start_job("campaign", _run_campaign_job, body)})
            if path == "/api/probe":
                return self._json({"job_id": _start_job("probe", _run_probe_job, body)})
            if path == "/api/loadtest":
                return self._json({"job_id": _start_job("loadtest", _run_loadtest_job, body)})
            return self._json({"error": "not found"}, 404)
        except Exception as exc:  # noqa: BLE001
            self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)


_INDEX_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentForge — control panel</title>
<style>
  :root { color-scheme: light dark; --bg:#0f1420; --card:#182031; --ink:#e7edf6;
          --mut:#93a1b5; --line:#273246; --acc:#5b9dff; --ok:#3fb984; --warn:#e0a638;
          --crit:#e5484d; --hi:#f2762e; }
  @media (prefers-color-scheme: light){ :root{ --bg:#f4f6fb; --card:#fff; --ink:#141c28;
          --mut:#5a6a7d; --line:#e2e8f2; } }
  *{box-sizing:border-box} body{margin:0;font:14px/1.5 system-ui,sans-serif;
    background:var(--bg);color:var(--ink)}
  header{padding:14px 20px;border-bottom:1px solid var(--line);display:flex;
    align-items:baseline;gap:12px}
  header h1{font-size:17px;margin:0} header .sub{color:var(--mut);font-size:12px}
  .wrap{display:grid;grid-template-columns:340px 1fr;gap:16px;padding:16px;
    max-width:1200px;margin:0 auto} @media(max-width:820px){.wrap{grid-template-columns:1fr}}
  .card{background:var(--card);border:1px solid var(--line);border-radius:10px;
    padding:14px;margin-bottom:16px}
  .card h2{font-size:13px;text-transform:uppercase;letter-spacing:.05em;
    color:var(--mut);margin:0 0 10px}
  label{display:block;font-size:12px;color:var(--mut);margin:8px 0 3px}
  label.help{cursor:help} label.help:hover{color:var(--acc)}
  input,select{width:100%;padding:7px 9px;background:var(--bg);color:var(--ink);
    border:1px solid var(--line);border-radius:7px;font:inherit}
  .row{display:flex;gap:8px} .row>*{flex:1}
  .chk{display:flex;align-items:center;gap:8px;margin:10px 0}
  .chk input{width:auto}
  button{width:100%;margin-top:12px;padding:9px;border:0;border-radius:8px;
    background:var(--acc);color:#fff;font:inherit;font-weight:600;cursor:pointer}
  button.ghost{background:transparent;border:1px solid var(--line);color:var(--ink)}
  button:disabled{opacity:.5;cursor:not-allowed}
  .pill{display:inline-block;padding:1px 7px;border-radius:20px;font-size:11px;
    font-weight:600}
  .s-running{background:var(--acc)} .s-done{background:var(--ok)}
  .s-error{background:var(--crit)} .s-queued{background:var(--warn)}
  .sev-critical{color:var(--crit);font-weight:700} .sev-high{color:var(--hi);font-weight:700}
  .sev-medium{color:var(--warn);font-weight:600} .sev-low{color:var(--mut)}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line)}
  th{color:var(--mut);font-weight:600;font-size:11px;text-transform:uppercase}
  .mut{color:var(--mut)} .mono{font-family:ui-monospace,Menlo,monospace;font-size:12px}
  .log{background:var(--bg);border:1px solid var(--line);border-radius:7px;
    padding:8px;font-family:ui-monospace,monospace;font-size:12px;max-height:150px;
    overflow:auto;white-space:pre-wrap} .warn{color:var(--warn)}
  .finding{border-left:3px solid var(--warn);padding:6px 10px;margin:6px 0;
    background:var(--bg);border-radius:0 7px 7px 0}
  .runitem{display:flex;justify-content:space-between;padding:6px 0;
    border-bottom:1px solid var(--line);cursor:pointer}
  .runitem:hover{color:var(--acc)}
  .tabs{display:flex;gap:6px;margin:6px 0 10px}
  .tab{width:auto;margin:0;padding:5px 12px;background:transparent;
    border:1px solid var(--line);color:var(--mut);font-weight:600;border-radius:20px}
  .tab.active{background:var(--acc);color:#fff;border-color:var(--acc)}
  h4{font-size:12px;margin:12px 0 4px}
</style></head><body>
<header><h1>⚔️ AgentForge</h1>
  <span class="sub">control panel — multi-agent adversarial evaluation of the Clinical Co-Pilot</span>
  <span class="sub" id="llmStatus" style="margin-left:auto"></span>
</header>
<div class="wrap">
  <div class="left">
    <div class="card">
      <h2>Run a campaign</h2>
      <div class="chk"><input type="checkbox" id="dry" checked>
        <label for="dry" style="margin:0">Dry-run (offline mock — safe, free)</label></div>
      <div id="mockRow"><label>Mock policy</label>
        <select id="policy"><option value="defended">defended (target resists)</option>
          <option value="leaky">leaky (regressed build that leaks)</option></select></div>
      <label class="help" title="Which attack category to focus on. 'all' lets the Orchestrator pick the highest-priority category×surface cell each round.">Category ⓘ</label>
      <select id="category" title="Which attack category to focus on. 'all' lets the Orchestrator pick the highest-priority category×surface cell each round."><option value="">all categories</option></select>
      <div class="row">
        <div><label class="help" title="Orchestrator rounds. Each round the Orchestrator picks the highest-priority attack cell (category × surface) and dispatches the Red Team at it. More rounds = broader coverage across categories. The run also stops early if a round finds nothing new (no_findings_in_window) or the budget cap is hit. LIVE runs are capped at ≤3 rounds; DRY-RUN is unbounded (up to 100 here) since it spends no target budget.">Rounds ⓘ</label><input id="rounds" type="number" value="2" min="1" max="100" title="Orchestrator rounds — more = broader coverage. Live cap ≤3; dry-run up to 100."></div>
        <div><label class="help" title="Attempts the Red Team runs per round = one seed attack plus its mutations, each a full multi-turn exchange with the target. Higher = deeper probing of one cell, but more of the target's LLM budget spent per round. LIVE runs are capped at ≤6 attempts/round; DRY-RUN is unbounded (up to 100 here). The actual count is also bounded by the seeds available in the cell (seed + 4 mutations each).">Attempts/round ⓘ</label><input id="attempts" type="number" value="4" min="1" max="100" title="Per round: seed + mutations, each a full multi-turn exchange. Live cap ≤6; dry-run up to 100 (also bounded by available seeds)."></div>
        <div><label class="help" title="The patient ID the co-pilot session is pinned to. The target scopes its answers to this one patient; attacks try to make it leak or act outside that scope. Must be a patient that exists on the target with a seeded synthesis doc (pid 1 on the dev deploy). It's also the pid whose page the CSRF token is scraped from.">Pinned pid ⓘ</label><input id="pid" type="number" value="1" min="1" title="Patient ID the session is pinned to. Attacks try to break out of this patient's scope. Must exist on the target with a seeded doc (pid 1 on dev); also the pid the CSRF token is scraped from."></div>
      </div>
      <p id="liveWarn" class="warn" style="display:none;font-size:12px;margin:8px 0 0"></p>
      <button id="runCamp">▶ Launch campaign</button>
    </div>
    <div class="card">
      <h2>Deterministic probes</h2>
      <p class="mut" style="margin:0 0 4px;font-size:12px">
        Cheap HTTP checks of the unauthenticated surface (health/ready/auth). Runs live.</p>
      <button class="ghost" id="runProbe">▶ Run probe sweep</button>
    </div>
    <div class="card">
      <h2>Baseline load test</h2>
      <p class="mut" style="margin:0 0 4px;font-size:12px">
        Latency/throughput baseline over a concurrency sweep against the cheap
        unauth <code>health.php</code> (no LLM budget spent). Identifies the
        throughput knee.</p>
      <label class="help" title="Requests fired at each concurrency level (1, 5, 10, 20). Bounded 10–200 from the UI to stay gentle on a live target.">Requests / level ⓘ</label>
      <input id="loadN" type="number" value="50" min="10" max="200"
        title="Requests per concurrency level (1/5/10/20). 10–200.">
      <button class="ghost" id="runLoad">▶ Run baseline load test</button>
    </div>
  </div>

  <div class="right">
    <div class="card" id="jobCard" style="display:none">
      <h2>Current job <span id="jobStatus" class="pill"></span></h2>
      <div class="log" id="jobLog"></div>
      <div id="jobResult"></div>
    </div>
    <div class="card">
      <h2>Trends over time <span id="histBackend" class="mut" style="font-size:11px"></span></h2>
      <div id="trends" class="mut">loading…</div>
    </div>
    <div class="card">
      <h2>Runs</h2>
      <div id="runs" class="mut">loading…</div>
    </div>
    <div class="card" id="detailCard" style="display:none">
      <h2 id="detailTitle">Detail</h2>
      <div id="detail"></div>
    </div>
  </div>
</div>
<script>
const $ = s => document.querySelector(s);
const sevClass = s => "sev-" + (s||"low");
let poll = null;

function caps(){ fetch("/api/state").then(r=>r.json()).then(st=>{
  const sel=$("#category"); (st.categories||[]).forEach(c=>{
    const o=document.createElement("option"); o.value=c; o.textContent=c; sel.appendChild(o); });
  window._caps = st.live_caps; renderRuns(st.runs); renderLlm(st.llm); updateLiveWarn();
}); }

function renderLlm(llm){
  if(!llm) return; const el=$("#llmStatus");
  const j = llm.judge ? `Judge: <b>${esc(llm.judge)}</b>` : `Judge: <span class="mut">rubric</span>`;
  const r = llm.redteam ? `Red Team: <b>${esc(llm.redteam)}</b>` : `Red Team: <span class="mut">operators</span>`;
  el.innerHTML = `${j} &nbsp;·&nbsp; ${r}`;
}

function updateLiveWarn(){
  const dry=$("#dry").checked; $("#mockRow").style.display = dry?"block":"none";
  const w=$("#liveWarn"), c=window._caps||{max_attempts:6,max_rounds:3,max_usd:2};
  const rounds=$("#rounds"), att=$("#attempts");
  w.style.display="block";
  if(dry){
    rounds.max=100; att.max=100;              // dry-run is unbounded (offline mock)
    w.style.color="var(--mut)";
    w.textContent="Dry-run (offline mock): unbounded — set rounds / attempts up to "
      +"100 to generate more test items. Spends no target budget.";
  }else{
    rounds.max=c.max_rounds; att.max=c.max_attempts;   // live is clamped
    if(+rounds.value>c.max_rounds) rounds.value=c.max_rounds;
    if(+att.value>c.max_attempts) att.value=c.max_attempts;
    w.style.color="";
    w.textContent=`Live run spends the target's LLM budget. Capped to ≤${c.max_rounds} `
      +`rounds, ≤${c.max_attempts} attempts/round, ≤$${c.max_usd} — higher values are `
      +`clamped down.`;
  }
}
$("#dry").addEventListener("change", updateLiveWarn);

function launch(url, payload, btn){
  btn.disabled=true;
  fetch(url,{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify(payload)}).then(r=>r.json()).then(d=>{
    if(d.job_id){ watch(d.job_id); } else { alert(d.error||"failed"); btn.disabled=false; }
  }).catch(e=>{ alert(e); btn.disabled=false; });
}

$("#runCamp").addEventListener("click", ()=> launch("/api/campaign",{
  dry_run:$("#dry").checked, mock_policy:$("#policy").value,
  category:$("#category").value, rounds:+$("#rounds").value,
  max_attempts:+$("#attempts").value, pid:+$("#pid").value
}, $("#runCamp")));

$("#runProbe").addEventListener("click", ()=> launch("/api/probe",{}, $("#runProbe")));

$("#runLoad").addEventListener("click", ()=> launch("/api/loadtest",{n:+$("#loadN").value}, $("#runLoad")));

function watch(jobId){
  $("#jobCard").style.display="block";
  if(poll) clearInterval(poll);
  poll = setInterval(()=> fetch("/api/job/"+jobId).then(r=>r.json()).then(job=>{
    const st=job.status||"?";
    $("#jobStatus").className="pill s-"+st; $("#jobStatus").textContent=st;
    $("#jobLog").textContent=(job.log||[]).join("\n");
    if(st==="done"||st==="error"){
      clearInterval(poll); poll=null;
      ["#runCamp","#runProbe","#runLoad"].forEach(s=>$(s).disabled=false);
      renderJobResult(job); fetch("/api/state").then(r=>r.json()).then(s=>renderRuns(s.runs));
    }
  }), 1200);
}

function renderJobResult(job){
  const el=$("#jobResult");
  if(job.status==="error"){ el.innerHTML=`<p class="sev-critical">Error: ${esc(job.error)}</p>`; return; }
  const r=job.result||{};
  if(job.kind==="probe"){
    el.innerHTML = probeTable(r.results||[]); return;
  }
  if(job.kind==="loadtest"){
    el.innerHTML = loadTable(r.levels||[]); return;
  }
  let h="";
  if(r.summary){ h+=coverageTable(r.summary); }
  const reps=r.reports||[];
  if(reps.length){ h+="<h3>Findings</h3>"+reps.map(findingHtml).join(""); }
  else { h+=`<p class="mut">No confirmed findings — target defended (halt: ${esc(r.halt)}).</p>`; }
  el.innerHTML=h;
}

function coverageTable(s){
  let rows=(s.coverage||[]).map(c=>`<tr><td>${esc(c.attack_category)}</td>
    <td class="mut">${esc(c.target_surface)}</td><td>${c.attempts}</td><td>${c.verdicts}</td>
    <td>${c.successes}</td><td>${c.pass_rate==null?"n/a":c.pass_rate.toFixed(2)}</td></tr>`).join("");
  return `<p class="mut">attempts <b>${s.attempts}</b> · verdicts <b>${s.verdicts}</b> ·
    findings <b>${s.open_findings}</b> · cost <b>$${(s.cost_usd||0).toFixed(4)}</b></p>
    <table><tr><th>category</th><th>surface</th><th>att</th><th>ver</th><th>succ</th><th>pass</th></tr>
    ${rows||'<tr><td colspan=6 class="mut">no data</td></tr>'}</table>`;
}

function findingHtml(r){
  return `<div class="finding"><b class="${sevClass(r.severity)}">${esc(r.severity).toUpperCase()}</b>
    ${esc(r.title)} <span class="mut">(${esc(r.status)})</span><br>
    <span class="mono mut">${esc(r.finding_id)}</span> — ${esc(r.impact||"")}</div>`;
}

function probeTable(results){
  return "<table><tr><th></th><th>severity</th><th>probe</th><th>observed</th></tr>"+
    results.map(r=>`<tr><td>${r.secure?"✅":"⚠️"}</td>
      <td class="${sevClass(r.severity)}">${esc(r.severity)}</td>
      <td>${esc(r.title)}</td><td class="mut">${esc(r.observed)}</td></tr>`).join("")+"</table>";
}

function loadTable(levels){
  if(!levels.length) return '<p class="mut">no data</p>';
  return "<table><tr><th>conc</th><th>req</th><th>rps</th><th>p50</th><th>p95</th>"+
    "<th>p99</th><th>errs</th></tr>"+
    levels.map(l=>{const m=l.latency_ms||{};return `<tr>
      <td>${l.concurrency}</td><td>${l.requests}</td><td>${l.throughput_rps}</td>
      <td>${m.p50} ms</td><td>${m.p95} ms</td><td>${m.p99} ms</td>
      <td class="${l.errors?'sev-high':'mut'}">${l.errors}</td></tr>`;}).join("")+"</table>";
}

function renderRuns(runs){
  const el=$("#runs"); if(!runs){el.textContent="none yet";return;}
  let h="";
  (runs.campaigns||[]).forEach(c=>{ const s=c.summary;
    h+=`<div class="runitem" data-file="${esc(c.file)}" data-kind="campaign">
      <span class="mono">${esc(c.file)}</span>
      <span class="mut">${s.attempts} att · ${s.open_findings} find</span></div>`; });
  (runs.probes||[]).forEach(f=>{
    h+=`<div class="runitem" data-file="${esc(f)}" data-kind="probe">
      <span class="mono">${esc(f)}</span><span class="mut">probes</span></div>`; });
  (runs.loadtests||[]).forEach(f=>{
    h+=`<div class="runitem" data-file="${esc(f)}" data-kind="loadtest">
      <span class="mono">${esc(f)}</span><span class="mut">load test</span></div>`; });
  el.innerHTML = h || '<span class="mut">no runs yet — launch one above</span>';
}

// Delegated: run items carry data-file/data-kind (no inline handler, so a
// filename can never enter a JS-string context) and this listener on the stable
// parent survives renderRuns() replacing the children.
$("#runs").addEventListener("click", e=>{
  const item=e.target.closest(".runitem"); if(!item) return;
  openDetail(item.dataset.file, item.dataset.kind);
});

function openDetail(file, kind){
  fetch("/api/file/"+encodeURIComponent(file)).then(r=>r.json()).then(d=>{
    $("#detailCard").style.display="block"; $("#detailTitle").textContent=file;
    if(kind==="probe"){ $("#detail").innerHTML=probeTable(d.results||d||[]); return; }
    if(kind==="loadtest"){ $("#detail").innerHTML=loadTable(Array.isArray(d)?d:(d.levels||[])); return; }
    let h=d.summary?coverageTable(d.summary):"";
    const f=d.open_findings||[];
    h+= f.length ? "<h3>Open findings</h3>"+f.map(v=>`<div class="finding">
        <b class="${sevClass(v.severity)}">${esc(v.severity).toUpperCase()}</b>
        attempt <span class="mono">${esc(v.attempt_id)}</span> — ${esc(v.rationale||"")}</div>`).join("")
      : '<p class="mut">No open findings in this run.</p>';
    h+=agentResponsesHtml(d.agent_responses);
    $("#detail").innerHTML=h;
  });
}

// Agent responses, tabbed by which path produced each attack/verdict.
function agentResponsesHtml(ar){
  if(!ar || (!(ar.attempts||[]).length && !(ar.verdicts||[]).length)) return "";
  const det=provGroup(ar,"deterministic"), llm=provGroup(ar,"llm");
  return `<h3>Agent responses</h3>
    <div class="tabs" role="tablist">
      <button class="tab active" data-prov="deterministic">Deterministic (${det.n})</button>
      <button class="tab" data-prov="llm">LLM-run (${llm.n})</button></div>
    <div class="provpane" data-prov="deterministic">${det.html}</div>
    <div class="provpane" data-prov="llm" style="display:none">${llm.html}</div>`;
}

function provGroup(ar, prov){
  const at=(ar.attempts||[]).filter(a=>(a.attack_source||"deterministic")===prov);
  const vd=(ar.verdicts||[]).filter(v=>(v.decision_path||"deterministic")===prov);
  const n=at.length+vd.length;
  if(!n) return {n:0, html:`<p class="mut">Nothing was produced by the ${prov} path in this run.</p>`};
  let h="";
  if(at.length){
    h+=`<h4 class="mut">Red Team — ${at.length} attempt${at.length>1?"s":""}</h4>`+
      `<table><tr><th>technique</th><th>category / surface</th><th>attacker</th><th>target response</th></tr>`+
      at.map(a=>`<tr><td>${esc(a.attack_technique)}</td>
        <td class="mut">${esc(a.attack_category)} / ${esc(a.target_surface)}</td>
        <td>${esc(a.attacker)}</td><td class="mut">${esc(a.target)}</td></tr>`).join("")+`</table>`;
  }
  if(vd.length){
    h+=`<h4 class="mut">Judge — ${vd.length} verdict${vd.length>1?"s":""}</h4>`+
      `<table><tr><th>verdict</th><th>sev</th><th>conf</th><th>model</th><th>rationale</th></tr>`+
      vd.map(v=>`<tr><td>${esc(v.verdict)}</td>
        <td class="${sevClass(v.severity)}">${esc(v.severity)}</td>
        <td>${v.confidence==null?"":Number(v.confidence).toFixed(2)}</td>
        <td class="mono">${esc(v.judge_model)}</td>
        <td class="mut">${esc(v.rationale)}</td></tr>`).join("")+`</table>`;
  }
  return {n, html:h};
}

// Delegated: tab clicks toggle the visible provenance pane. Listener sits on the
// stable #detail parent so it survives openDetail() replacing the content.
$("#detail").addEventListener("click", e=>{
  const tab=e.target.closest(".tab"); if(!tab) return;
  const root=tab.closest("#detail"); const prov=tab.dataset.prov;
  root.querySelectorAll(".tab").forEach(t=>t.classList.toggle("active", t===tab));
  root.querySelectorAll(".provpane").forEach(p=>{
    p.style.display = (p.dataset.prov===prov) ? "" : "none"; });
});

function renderTrends(){
  fetch("/api/history").then(r=>r.json()).then(h=>{
    $("#histBackend").textContent = h.backend ? "· "+h.backend : "";
    const el=$("#trends"), s=(h.series||[]);
    if(!s.length){ el.innerHTML = h.error
        ? `<span class="mut">history unavailable (${esc(h.error)})</span>`
        : '<span class="mut">no campaigns recorded yet — launch one to start the trend</span>';
      return; }
    el.innerHTML = trendChart(s) + trendTable(s);
  }).catch(()=>{});
}

function trendChart(s){
  const pts=s.map((d,i)=>({i, v:d.pass_rate})).filter(p=>p.v!=null);
  if(!pts.length) return '<p class="mut">no judged runs yet</p>';
  const n=s.length, X=i=> n<=1?50:(i/(n-1))*100, Y=v=> 38-(v*36);
  const line=pts.map(p=>`${X(p.i).toFixed(1)},${Y(p.v).toFixed(1)}`).join(" ");
  const dots=pts.map(p=>`<circle cx="${X(p.i).toFixed(1)}" cy="${Y(p.v).toFixed(1)}" r="1.1" fill="var(--acc)"/>`).join("");
  return `<svg viewBox="0 0 100 40" preserveAspectRatio="none" role="img"
      aria-label="defended-rate over time"
      style="width:100%;height:90px;background:var(--bg);border:1px solid var(--line);border-radius:7px">
    <line x1="0" y1="2" x2="100" y2="2" stroke="var(--line)" stroke-width="0.3"/>
    <line x1="0" y1="20" x2="100" y2="20" stroke="var(--line)" stroke-width="0.3"/>
    <line x1="0" y1="38" x2="100" y2="38" stroke="var(--line)" stroke-width="0.3"/>
    <polyline points="${line}" fill="none" stroke="var(--acc)" stroke-width="0.8"/>${dots}
  </svg>
  <div class="mut" style="font-size:11px;display:flex;justify-content:space-between">
    <span>defended-rate (pass) over ${n} run${n>1?'s':''}</span><span>1.0 top · 0.0 bottom</span></div>`;
}

function trendTable(s){
  const rows=s.slice().reverse().slice(0,8).map(d=>`<tr>
    <td class="mono">${esc(d.run_id)}</td><td class="mut">${esc(d.mode)}</td>
    <td>${d.pass_rate==null?"n/a":d.pass_rate.toFixed(2)}</td>
    <td>${d.open_findings}</td>
    <td class="mut">${esc((d.recorded_at||"").slice(0,16).replace("T"," "))}</td></tr>`).join("");
  return `<table style="margin-top:8px"><tr><th>run</th><th>mode</th><th>pass</th>`+
    `<th>find</th><th>when</th></tr>${rows}</table>`;
}

function esc(s){ return String(s==null?"":s).replace(/[&<>"']/g,c=>(
  {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }

caps(); updateLiveWarn(); renderTrends();
setInterval(()=>{ if(!poll){ fetch("/api/state").then(r=>r.json()).then(s=>renderRuns(s.runs)); renderTrends(); } }, 5000);
</script>
</body></html>"""


def _resolve_host(host: str | None) -> str:
    # PaaS (Railway/Render/Fly) needs 0.0.0.0; locally default to loopback.
    return host or os.environ.get("AGENTFORGE_WEB_HOST") or "127.0.0.1"


def _resolve_port(port: int | None) -> int:
    # Railway/Heroku inject $PORT; honor it, else AGENTFORGE_WEB_PORT, else 8800.
    if port:
        return port
    return int(os.environ.get("PORT") or os.environ.get("AGENTFORGE_WEB_PORT") or 8800)


def main(host: str | None = None, port: int | None = None) -> None:
    host = _resolve_host(host)
    port = _resolve_port(port)
    RUNS_DIR.mkdir(exist_ok=True)

    if _auth_credentials() is not None:
        print("auth: HTTP Basic REQUIRED on every route except /healthz "
              "(AGENTFORGE_WEB_USER/PASSWORD)")
    else:
        print("auth: LOCKED — AGENTFORGE_WEB_USER/PASSWORD are not set, so the "
              "dashboard refuses every route except /healthz (503). Set both to "
              "enable login. This is intentional: an open panel can launch runs.")

    server = ThreadingHTTPServer((host, port), Handler)
    shown = host if host != "0.0.0.0" else "0.0.0.0 (all interfaces)"
    print(f"AgentForge dashboard → http://{shown}:{port}  (Ctrl-C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
        server.shutdown()


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(prog="agentforge.web")
    p.add_argument("--host", default=None, help="bind host (env AGENTFORGE_WEB_HOST)")
    p.add_argument("--port", type=int, default=None, help="bind port (env PORT)")
    args = p.parse_args()
    main(args.host, args.port)
