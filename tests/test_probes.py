"""Deterministic probe harness: findings vs. secure, using a fake HTTP client."""
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentforge.probes import ProbeHarness


@dataclass
class _Resp:
    status_code: int
    text: str = ""
    _json: dict | None = None

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json


class _FakeHttp:
    """Routes by URL substring; ``ready_codes`` lets a test script the burst."""
    def __init__(self, health=None, ready=None, agent=None, chat=None, ready_codes=None):
        self._health = health or _Resp(200, _json={"status": "ok", "version": "1"})
        self._ready = ready or _Resp(200, _json={"ready": True, "db": "ok",
                                                 "llm": "ok", "breaker": "closed"})
        self._agent = agent or _Resp(400)
        self._chat = chat or _Resp(400)
        self._ready_codes = list(ready_codes or [])

    def get(self, url, **kw):
        if "health.php" in url:
            return self._health
        if "ready.php" in url:
            if self._ready_codes:
                return _Resp(self._ready_codes.pop(0))
            return self._ready
        return _Resp(404)

    def post(self, url, **kw):
        if "agent.php" in url:
            return self._agent
        if "chat.php" in url:
            return self._chat
        return _Resp(404)


def _harness(**kw):
    return ProbeHarness("https://t.example", http=_FakeHttp(**kw))


def test_health_version_disclosure_is_a_finding():
    r = _harness().probe_health_unauth()
    assert r.secure is False
    assert r.evidence["version"] == "1"


def test_ready_dependency_enumeration_is_a_finding():
    r = _harness().probe_ready_unauth()
    assert r.secure is False
    assert len(r.evidence["disclosed_keys"]) >= 3


def test_ready_without_dependency_detail_is_secure():
    quiet = _Resp(200, _json={"ready": True})
    r = ProbeHarness("https://t.example", http=_FakeHttp(ready=quiet)).probe_ready_unauth()
    assert r.secure is True


def test_rate_limit_fail_open_is_a_finding():
    # Burst never 429s -> fail-open finding.
    r = _harness(ready_codes=[200] * 40).probe_ready_rate_limit(burst=40)
    assert r.secure is False
    assert r.evidence["http_429"] == 0


def test_rate_limit_engaging_is_secure():
    r = _harness(ready_codes=[200] * 20 + [429] * 20).probe_ready_rate_limit(burst=40)
    assert r.secure is True


def test_agent_and_chat_auth_required_secure_when_blocked():
    h = _harness()
    assert h.probe_agent_requires_auth().secure is True     # 400, no claims
    assert h.probe_chat_requires_auth().secure is True      # 400, no session_id


def test_agent_leak_without_auth_is_a_finding():
    leaky = _Resp(200, _json={"ok": True, "claims": [{"text": "A1c 7.2%"}]})
    h = ProbeHarness("https://t.example", http=_FakeHttp(agent=leaky))
    r = h.probe_agent_requires_auth()
    assert r.secure is False
    assert r.severity == "high"
