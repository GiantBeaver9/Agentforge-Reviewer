"""Web dashboard: read helpers, path-traversal guard, and a live server smoke
test that drives a dry-run campaign through the HTTP API (no network)."""
import json
import sys
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentforge import web


def test_categories_and_traversal_guard():
    cats = web._categories()
    assert "prompt_injection" in cats and "data_exfiltration" in cats
    # Path traversal is stripped to a basename -> the etc file never resolves.
    assert web._read_json_file("../../../../etc/passwd") is None
    assert web._read_json_file("does-not-exist.json") is None


def test_malformed_run_file_returns_error_not_crash():
    # A partially-written / malformed run file must degrade to an error dict,
    # never raise (the viewer stays usable while a live run is mid-write).
    web.RUNS_DIR.mkdir(exist_ok=True)
    bad = web.RUNS_DIR / "camp-UNITBAD.observability.jsonl"
    bad.write_text("{ not valid json\n")
    try:
        out = web._read_json_file("camp-UNITBAD.observability.jsonl")
        assert isinstance(out, dict) and "error" in out
    finally:
        bad.unlink(missing_ok=True)


def _free_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _authed(url_or_req, user="grader", pw="s3cret"):
    """Wrap a URL/Request with a valid HTTP Basic header (auth is mandatory)."""
    import base64 as _b64
    req = (url_or_req if isinstance(url_or_req, urllib.request.Request)
           else urllib.request.Request(url_or_req))
    req.add_header("Authorization", "Basic " + _b64.b64encode(f"{user}:{pw}".encode()).decode())
    return req


def test_dashboard_serves_and_runs_dry_campaign(monkeypatch):
    monkeypatch.setenv("AGENTFORGE_WEB_USER", "grader")
    monkeypatch.setenv("AGENTFORGE_WEB_PASSWORD", "s3cret")
    port = _free_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), web.Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{port}"
    try:
        # index + state (authenticated)
        assert b"AgentForge" in urllib.request.urlopen(_authed(base + "/")).read()
        state = json.loads(urllib.request.urlopen(_authed(base + "/api/state")).read())
        assert "prompt_injection" in state["categories"]
        assert state["live_caps"]["max_attempts"] >= 1

        # launch a dry-run leaky campaign (offline mock -> guaranteed findings)
        req = urllib.request.Request(
            base + "/api/campaign",
            data=json.dumps({"dry_run": True, "mock_policy": "leaky",
                             "rounds": 1, "max_attempts": 3}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        job_id = json.loads(urllib.request.urlopen(_authed(req)).read())["job_id"]

        result = None
        for _ in range(50):  # up to ~5s
            job = json.loads(urllib.request.urlopen(
                _authed(base + f"/api/job/{job_id}")).read())
            if job["status"] in ("done", "error"):
                result = job
                break
            time.sleep(0.1)
        assert result is not None and result["status"] == "done", result
        assert result["result"]["summary"]["open_findings"] >= 1
        assert result["result"]["reports"]              # leaky target -> reports

        # the completed campaign records a cross-run history snapshot
        hist = json.loads(urllib.request.urlopen(_authed(base + "/api/history")).read())
        assert hist["backend"] == "sqlite"             # no DATABASE_URL in tests
        run_id = result["result"]["run_id"]
        assert any(s["run_id"] == run_id for s in hist["series"]), hist

        # the run's observability file exposes agent responses with provenance
        detail = json.loads(urllib.request.urlopen(
            _authed(base + "/api/file/" + result["result"]["observability"])).read())
        ar = detail["agent_responses"]
        assert ar["attempts"] and ar["verdicts"]
        # deterministic dry-run -> everything tagged deterministic
        assert all(a["attack_source"] == "deterministic" for a in ar["attempts"])
        assert all(v["decision_path"] == "deterministic" for v in ar["verdicts"])
    finally:
        server.shutdown()


def test_fail_closed_when_auth_unconfigured(monkeypatch):
    # With no credentials set, every route except /healthz is locked (503) — an
    # open panel could launch runs, so it refuses rather than run open.
    monkeypatch.delenv("AGENTFORGE_WEB_USER", raising=False)
    monkeypatch.delenv("AGENTFORGE_WEB_PASSWORD", raising=False)
    port = _free_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), web.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    try:
        # /healthz stays open for the PaaS liveness probe
        assert json.loads(urllib.request.urlopen(base + "/healthz").read())["ok"] is True
        # everything else is locked closed
        for path, method in [("/", "GET"), ("/api/state", "GET")]:
            try:
                urllib.request.urlopen(base + path)
                assert False, f"expected 503 for {path}"
            except urllib.error.HTTPError as e:
                assert e.code == 503, (path, e.code)
        # a spend/live path (campaign launch) is also refused
        req = urllib.request.Request(
            base + "/api/campaign",
            data=json.dumps({"dry_run": True}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            urllib.request.urlopen(req)
            assert False, "expected 503 for /api/campaign"
        except urllib.error.HTTPError as e:
            assert e.code == 503
    finally:
        server.shutdown()


def test_unknown_job_is_404(monkeypatch):
    monkeypatch.setenv("AGENTFORGE_WEB_USER", "grader")
    monkeypatch.setenv("AGENTFORGE_WEB_PASSWORD", "s3cret")
    port = _free_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), web.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    try:
        # authenticated but unknown job -> 404
        try:
            urllib.request.urlopen(_authed(base + "/api/job/nope"))
            assert False, "expected 404"
        except urllib.error.HTTPError as e:
            assert e.code == 404
    finally:
        server.shutdown()


def test_healthz_open_and_auth_gate(monkeypatch):
    monkeypatch.setenv("AGENTFORGE_WEB_USER", "u")
    monkeypatch.setenv("AGENTFORGE_WEB_PASSWORD", "p")
    port = _free_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), web.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    import base64 as _b64
    try:
        # healthz needs no auth
        assert json.loads(urllib.request.urlopen(base + "/healthz").read())["ok"] is True
        # state without creds -> 401
        try:
            urllib.request.urlopen(base + "/api/state")
            assert False, "expected 401"
        except urllib.error.HTTPError as e:
            assert e.code == 401
        # state with correct creds -> 200
        req = urllib.request.Request(base + "/api/state")
        req.add_header("Authorization", "Basic " + _b64.b64encode(b"u:p").decode())
        assert urllib.request.urlopen(req).status == 200
    finally:
        server.shutdown()


def test_llm_status_reflects_env(monkeypatch):
    monkeypatch.delenv("JUDGE_BASE_URL", raising=False)
    monkeypatch.delenv("REDTEAM_BASE_URL", raising=False)
    st = web._llm_status()
    assert st["judge"] is None and st["redteam"] is None
    monkeypatch.setenv("JUDGE_BASE_URL", "https://api.openai.com/v1")
    monkeypatch.setenv("JUDGE_MODEL", "gpt-4o-mini")
    assert web._llm_status()["judge"] == "gpt-4o-mini"


def test_base_url_normalization_and_guard(monkeypatch):
    from agentforge import config as cfgmod
    # scheme-less URL gets https:// and trailing slash trimmed
    monkeypatch.setenv("AGENTFORGE_TARGET_BASE_URL", "my-host.up.railway.app/")
    assert cfgmod.load().target.base_url == "https://my-host.up.railway.app"
    # blank falls back to the default (not an empty string that breaks httpx)
    monkeypatch.setenv("AGENTFORGE_TARGET_BASE_URL", "   ")
    assert cfgmod.load().target.base_url.startswith("https://")
    # explicit http:// is preserved
    monkeypatch.setenv("AGENTFORGE_TARGET_BASE_URL", "http://localhost:8300")
    assert cfgmod.load().target.base_url == "http://localhost:8300"


def test_loadtest_job_runs(monkeypatch):
    # Job runner writes a levels result without hitting the network (sweep faked).
    from agentforge import loadtest as lt

    class _S:
        def summary(self):
            return {"concurrency": 1, "requests": 10, "throughput_rps": 5.0,
                    "errors": 0, "latency_ms": {"p50": 10, "p95": 20, "p99": 30}}

    monkeypatch.setattr(lt, "sweep", lambda base_url, n=100: [_S(), _S()])
    jid = "job-loadtest-unit"
    web._JOBS[jid] = {"id": jid, "kind": "loadtest", "status": "queued",
                      "log": [], "result": None, "error": None, "params": {}}
    web._run_loadtest_job(jid, {"n": 10})
    job = web._JOBS[jid]
    assert job["status"] == "done", job
    assert len(job["result"]["levels"]) == 2
