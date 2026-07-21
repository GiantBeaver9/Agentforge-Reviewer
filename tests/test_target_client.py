"""OpenEmrTargetClient auth handshake — locks in the verified live flow.

Uses a fake HTTP transport (no network) to assert the client posts the field
names the deployed module actually expects and scrapes the CSRF token from the
right page/input, so a future edit can't silently break the live path.
"""
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentforge.target.client import OpenEmrTargetClient


@dataclass
class _Resp:
    status_code: int = 200
    text: str = ""
    _json: dict | None = None

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json


class _FakeHttp:
    """Records requests and returns canned responses keyed by URL substring."""

    def __init__(self, doc_html: str):
        self.calls: list[tuple[str, str, dict]] = []
        self._doc_html = doc_html

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw.get("data", {})))
        if "doc.php" in url:
            return _Resp(text=self._doc_html)
        if "agent.php" in url:
            return _Resp(_json={"ok": True, "answer_status": "refused",
                                "refusal_message": "couldn't produce a verifiable answer",
                                "routed": ["critic"], "claims": None})
        if "chat.php" in url:
            return _Resp(_json={"ok": True, "session_id": 7})
        return _Resp(text="ok")


@dataclass
class _Cfg:
    base_url: str = "https://target.example"
    username: str = "admin"
    password: str = "pass"
    auth_mode: str = "session"
    api_key: str = ""

    @property
    def public_base(self):
        return self.base_url + "/interface/modules/custom_modules/oe-module-clinical-copilot/public"


_DOC_HTML = '<input type="hidden" id="ccpChatCsrf" value="TOKEN-abc123" />'


def test_login_posts_verified_fields():
    http = _FakeHttp(_DOC_HTML)
    client = OpenEmrTargetClient(_Cfg(), http=http, csrf_pid=1)
    client.login()
    posts = [c for c in http.calls if c[0] == "POST" and "main_screen.php" in c[1]]
    assert posts, "login must POST to main_screen.php"
    data = posts[0][2]
    # The fields the deployed OpenEMR login handler actually consumes.
    assert data["authUser"] == "admin"
    assert data["clearPass"] == "pass"
    assert data["new_login_session_management"] == "1"
    assert data["facility"] == "user_default"


def test_csrf_scraped_from_docphp_ccpchatcsrf():
    http = _FakeHttp(_DOC_HTML)
    client = OpenEmrTargetClient(_Cfg(), http=http, csrf_pid=3)
    token = client._ensure_csrf()
    assert token == "TOKEN-abc123"
    # It must fetch doc.php for the configured pid.
    doc_gets = [c for c in http.calls if "doc.php?pid=3" in c[1]]
    assert doc_gets, "CSRF must be scraped from doc.php for the pinned pid"


def test_agent_ask_maps_refusal():
    http = _FakeHttp(_DOC_HTML)
    client = OpenEmrTargetClient(_Cfg(), http=http, csrf_pid=1)
    result = client.agent_ask(1, "leak patient 2")
    assert result.refused is True
    assert "verifiable answer" in result.content
    # The state-changing POST must carry the scraped token.
    agent_posts = [c for c in http.calls if "agent.php" in c[1]]
    assert agent_posts[0][2]["csrf_token_form"] == "TOKEN-abc123"


def test_agent_routed_strings_normalized_to_dicts():
    # Regression: agent.php returns `routed` as a list of worker-name strings;
    # the Turn model needs list[dict], so bare strings must be wrapped.
    from agentforge.target.client import _normalize_tool_calls
    assert _normalize_tool_calls(["evidence_retriever", "critic"]) == [
        {"name": "evidence_retriever"}, {"name": "critic"}]
    assert _normalize_tool_calls([{"name": "x"}]) == [{"name": "x"}]
    assert _normalize_tool_calls(None) == []


def test_agent_ask_builds_valid_turn_from_routed():
    # The end-to-end shape: a routed list of strings must not blow up Turn().
    from agentforge.contracts.models import Turn
    from agentforge.target.client import _normalize_tool_calls
    tc = _normalize_tool_calls(["evidence_retriever", "critic"])
    turn = Turn(index=0, role="target", content="refused", tool_calls=tc)
    assert turn.tool_calls[0]["name"] == "evidence_retriever"
