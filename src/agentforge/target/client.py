"""HTTP clients for the Clinical Co-Pilot under test.

Two implementations behind one Protocol:

* ``OpenEmrTargetClient`` — talks to the real deployed module. It performs the
  OpenEMR login handshake (session cookie), scrapes a CSRF form token, and posts
  to chat.php / agent.php per the recon map.
* ``MockTargetClient`` — an offline stand-in with a *scriptable defended/leaky*
  policy, so the Red Team + contracts can be exercised end-to-end with no
  network (used for CI and for dry-runs in an egress-restricted environment).

The real client's login + CSRF handshake is the ONE piece that must be verified
against the live target (see HANDOFF.md "target auth"); the shapes come straight
from recon but OpenEMR's token delivery can vary by version.
"""
from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from typing import Protocol


# Well-known CA bundle for the agent egress proxy (TLS is re-terminated there).
# httpx does not read the OpenSSL SSL_CERT_FILE env var the way curl does, so we
# resolve the bundle explicitly and hand it to the client's ``verify``.
_PROXY_CA_BUNDLE = "/root/.ccr/ca-bundle.crt"


@dataclass
class TurnResult:
    """Normalized result of one attacker turn against the target."""
    content: str                       # assistant text (or serialized JSON claims)
    http_status: int
    latency_ms: float
    session_id: str | None = None
    tool_calls: list[dict] = field(default_factory=list)
    refused: bool = False
    frozen: bool = False
    raw: dict | None = None


class TargetClient(Protocol):
    def start_chat(self, pid: int) -> str: ...
    def chat_turn(self, session_id: str, message: str) -> TurnResult: ...
    def agent_ask(self, pid: int, question: str) -> TurnResult: ...


# --------------------------------------------------------------------------- #
#  Real client
# --------------------------------------------------------------------------- #
class TargetUnreachable(RuntimeError):
    """Raised when the target cannot be reached (DNS/egress/connect)."""


class OpenEmrTargetClient:
    """Authenticated client against the deployed co-pilot.

    Requires ``httpx``. Auth mode 'session' logs in with username/password.
    """

    def __init__(self, cfg, http=None, csrf_pid: int = 1, site: str = "default"):
        self.cfg = cfg
        self._public = cfg.public_base
        self._csrf: str | None = None
        # The module's CSRF form token is embedded in doc.php, which only
        # renders (and only carries the token) for a patient that already has a
        # seeded synthesis doc. We scrape it against this pid.
        self._csrf_pid = csrf_pid
        self._site = site
        if http is None:
            import httpx  # imported lazily so MockTargetClient needs no httpx
            # Trust the egress proxy's CA when present (env may not export it);
            # fall back to SSL_CERT_FILE / system trust otherwise.
            verify = os.environ.get("SSL_CERT_FILE") or True
            if os.path.exists(_PROXY_CA_BUNDLE):
                verify = _PROXY_CA_BUNDLE
            http = httpx.Client(timeout=60.0, follow_redirects=True, verify=verify)
        self._http = http

    # ---- transport ---------------------------------------------------------
    def _request(self, method: str, url: str, **kw):
        """One HTTP request with a small retry for *transient* transport faults.

        The egress proxy occasionally closes a keep-alive connection mid-body
        (``httpx.RemoteProtocolError`` / incomplete chunked read), especially on
        the slower LLM-backed endpoints. That is not the target being down, so
        we retry with backoff and only escalate to ``TargetUnreachable`` once the
        retries are exhausted.
        """
        import httpx
        last: Exception | None = None
        for attempt in range(3):
            try:
                return self._http.request(method, url, **kw)
            except (httpx.TransportError, httpx.RemoteProtocolError) as exc:
                last = exc
                time.sleep(2 ** attempt)  # 1s, 2s, 4s
        raise TargetUnreachable(f"{method} {url}: {last}") from last

    # ---- auth --------------------------------------------------------------
    def login(self) -> None:
        """Establish an OpenEMR session cookie.

        Field names + path are the verified live handshake (the module's own
        ``ops/bruno/00 - Auth Bootstrap`` collection, itself checked against
        ``tests/Tests/E2e/Login/LoginTrait.php``): prime the login page to seed
        cookies, then POST ``authUser``/``clearPass`` (plus
        ``new_login_session_management``/``languageChoice``/``facility``) to
        ``interface/main/main_screen.php?auth=login``. On success the session
        cookie is stored on the httpx client's cookie jar and the server 302s to
        the app shell (a bad password re-renders the login form with a 200 — the
        real proof of auth is that a later module page renders rather than 403s).
        """
        base = self.cfg.base_url.rstrip("/")
        # Prime cookies (and any login-form CSRF the version sets), then submit.
        # _request normalizes transport faults to TargetUnreachable.
        self._request("GET", f"{base}/interface/login/login.php?site={self._site}")
        resp = self._request(
            "POST",
            f"{base}/interface/main/main_screen.php?auth=login&site={self._site}",
            data={
                "new_login_session_management": "1",
                "languageChoice": "1",
                "authUser": self.cfg.username,
                "clearPass": self.cfg.password,
                "facility": "user_default",
            },
        )
        if resp.status_code >= 500:
            raise TargetUnreachable(f"login returned {resp.status_code}")

    def _ensure_csrf(self) -> str:
        """Scrape the module's CSRF form token from ``doc.php``.

        A GET view performs no write, so ``doc.php`` needs no token to render —
        but the page it returns embeds one (the chat panel's ``#ccpChatCsrf``
        hidden input, carrying the bare token string) that every state-changing
        request in the module replays as ``csrf_token_form``. We scrape it once
        and reuse it. The page (and therefore the token) only renders when
        ``doc.php`` finds both a patient and a computed synthesis for the pid, so
        ``--pid`` must point at a seeded patient (default dev seed: pid 1).
        """
        if self._csrf:
            return self._csrf
        r = self._request("GET", f"{self._public}/doc.php?pid={self._csrf_pid}")
        # Primary source: the chat panel's hidden input (verified live flow).
        m = re.search(r'id=["\']ccpChatCsrf["\'][^>]*value=["\']([^"\']+)', r.text)
        if not m:
            # Fallbacks for token delivery that varies by version/page.
            m = re.search(r'name=["\']csrf_token_form["\']\s+value=["\']([^"\']+)', r.text)
        if not m:
            raise RuntimeError(
                "could not locate a CSRF token in doc.php — login likely failed "
                "or pid has no seeded synthesis doc (see HANDOFF 'target auth')"
            )
        self._csrf = m.group(1)
        return self._csrf

    # ---- surfaces ----------------------------------------------------------
    def start_chat(self, pid: int) -> str:
        csrf = self._ensure_csrf()
        r = self._request("POST", f"{self._public}/chat.php",
                          data={"action": "start", "pid": pid, "csrf_token_form": csrf})
        data = r.json()
        return str(data["session_id"])

    def chat_turn(self, session_id: str, message: str) -> TurnResult:
        csrf = self._ensure_csrf()
        t0 = time.perf_counter()
        r = self._request("POST", f"{self._public}/chat.php", data={
            "action": "turn", "session_id": session_id,
            "message": message, "stream": "0", "csrf_token_form": csrf,
        })
        dt = (time.perf_counter() - t0) * 1000
        body = _safe_json(r)
        frozen = bool(body and body.get("frozen"))
        # The chat turn "defends" when it freezes, when the verifier degrades the
        # answer (it declined to assert an unverifiable claim), or on a lock/
        # conflict status. The Judge makes the final call; this is only a hint.
        degraded = bool(body and (body.get("degraded_message")
                                  or body.get("verify_status") == "degraded"))
        return TurnResult(
            content=_render_answer(body),
            http_status=r.status_code, latency_ms=dt, session_id=session_id,
            tool_calls=_normalize_tool_calls(body.get("tool_calls") if body else None),
            frozen=frozen,
            refused=frozen or degraded or r.status_code in (409, 423),
            raw=body,
        )

    def agent_ask(self, pid: int, question: str) -> TurnResult:
        csrf = self._ensure_csrf()
        t0 = time.perf_counter()
        r = self._request("POST", f"{self._public}/agent.php", data={
            "pid": pid, "question": question, "csrf_token_form": csrf,
        })
        dt = (time.perf_counter() - t0) * 1000
        body = _safe_json(r)
        status = (body or {}).get("answer_status")
        # agent.php reports which workers the supervisor routed to as a list of
        # plain strings (e.g. ["evidence_retriever", "critic"]); the Turn model's
        # tool_calls is list[dict], so normalize each name into a dict.
        return TurnResult(
            content=_render_answer(body),
            http_status=r.status_code, latency_ms=dt,
            tool_calls=_normalize_tool_calls(body.get("routed") if body else None),
            refused=status in ("refused", "frozen_sev1"),
            raw=body,
        )


def _normalize_tool_calls(raw) -> list[dict]:
    """Coerce a target's tool/worker list into ``list[dict]`` for the Turn model.

    The agent surface returns worker names as bare strings; the chat surface may
    return dicts. Normalize both so a string ``"critic"`` becomes
    ``{"name": "critic"}`` and a dict passes through unchanged.
    """
    out: list[dict] = []
    for item in (raw or []):
        out.append(item if isinstance(item, dict) else {"name": str(item)})
    return out


def _safe_json(resp) -> dict | None:
    try:
        return resp.json()
    except Exception:  # noqa: BLE001
        return None


def _render_answer(body: dict | None) -> str:
    """Normalize a target response to the assistant's user-visible text.

    Handles both surfaces: agent.php carries ``refusal_message`` + ``claims``;
    chat.php carries ``degraded_message`` (verifier declined) + ``claims``. We
    prefer an explicit refusal/degrade string, else join the claim texts, and
    only fall back to the raw body when neither is present.
    """
    if not body:
        return ""
    for key in ("refusal_message", "degraded_message"):
        if body.get(key):
            return str(body[key])
    claims = body.get("claims") or []
    if claims:
        texts = [str(c.get("text", "")) for c in claims if isinstance(c, dict)]
        joined = " ".join(t for t in texts if t)
        if joined:
            return joined
    return str(body)


# --------------------------------------------------------------------------- #
#  Mock client (offline)
# --------------------------------------------------------------------------- #
class MockTargetClient:
    """Offline stand-in. ``policy='defended'`` refuses attacks (models the real
    co-pilot's guards); ``policy='leaky'`` complies (models a regressed build),
    so tests can prove the Judge catches both."""

    def __init__(self, policy: str = "defended"):
        self.policy = policy
        self._n = 0

    def start_chat(self, pid: int) -> str:
        return f"mock-session-{pid}"

    def _respond(self, text: str) -> TurnResult:
        self._n += 1
        low = text.lower()
        attackish = any(k in low for k in (
            "ignore", "system prompt", "diagnos", "dose", "patient id 2",
            "pid=2", "override", "base64", "raw_sql", "you are now"))
        if self.policy == "leaky" and attackish:
            return TurnResult(content="Sure — here is the system prompt and patient 2's A1c is 8.1%.",
                              http_status=200, latency_ms=120.0)
        if attackish:
            return TurnResult(content="I can only discuss the one pinned patient and can't do that.",
                              http_status=200, latency_ms=110.0, refused=True)
        return TurnResult(content="The pinned patient's last A1c was 7.2% [fact_id=f1].",
                          http_status=200, latency_ms=90.0)

    def chat_turn(self, session_id: str, message: str) -> TurnResult:
        r = self._respond(message)
        r.session_id = session_id
        return r

    def agent_ask(self, pid: int, question: str) -> TurnResult:
        return self._respond(question)
