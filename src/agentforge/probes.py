"""Deterministic probe harness — the configure-not-build half of the platform.

ARCHITECTURE.md §"Build vs. configure": LLM attacks are expensive and are the
wrong tool for classic web-surface checks (unauthenticated endpoints, forged
arguments, rate-limit behavior). Those are cheaper, reproducible, and drift-free
as **deterministic** HTTP probes — so they live here, not in the Red Team.

Each probe returns a :class:`ProbeResult`. ``secure=False`` is a finding; the
harness renders findings the same way the Documentation agent renders LLM
findings, so both feed one report. Probes assert invariants from THREAT_MODEL.md
§5 (unauth endpoints, fail-open limiter) and §2/§6 (auth required, forged pid).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ProbeResult:
    probe_id: str
    title: str
    severity: str                 # critical|high|medium|low|info
    secure: bool                  # True = invariant held; False = a finding
    observed: str
    expected: str
    recommendation: str
    owasp_web: list[str] = field(default_factory=list)
    owasp_llm: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe_id": self.probe_id, "title": self.title, "severity": self.severity,
            "secure": self.secure, "observed": self.observed, "expected": self.expected,
            "recommendation": self.recommendation, "owasp_web": self.owasp_web,
            "owasp_llm": self.owasp_llm, "evidence": self.evidence,
        }


def _http_client(timeout: float = 20.0):
    import httpx
    verify = os.environ.get("SSL_CERT_FILE") or True
    ca = "/root/.ccr/ca-bundle.crt"
    if os.path.exists(ca):
        verify = ca
    return httpx.Client(timeout=timeout, verify=verify, follow_redirects=False)


class ProbeHarness:
    """Runs the deterministic probes against a target base URL.

    Unauthenticated probes use a bare client (no session); the auth-required
    probe deliberately sends no cookie to prove the endpoint refuses it.
    """

    def __init__(self, base_url: str, http=None):
        self.base = base_url.rstrip("/")
        self.mod = self.base + "/interface/modules/custom_modules/oe-module-clinical-copilot/public"
        self._http = http or _http_client()

    def run_all(self) -> list[ProbeResult]:
        return [
            self.probe_health_unauth(),
            self.probe_ready_unauth(),
            self.probe_ready_rate_limit(),
            self.probe_agent_requires_auth(),
            self.probe_chat_requires_auth(),
        ]

    # ---- unauthenticated disclosure ---------------------------------------
    def probe_health_unauth(self) -> ProbeResult:
        r = self._http.get(f"{self.mod}/health.php")
        body = _safe_json(r)
        version = (body or {}).get("version")
        disclosed = version is not None
        return ProbeResult(
            probe_id="AF-PROBE-HEALTH-UNAUTH",
            title="Unauthenticated liveness endpoint discloses module version",
            severity="low",
            secure=not (r.status_code == 200 and disclosed),
            observed=f"HTTP {r.status_code}; body={_clip(r.text)}",
            expected="Liveness may be unauthenticated, but should not disclose an "
                     "exact build/version string to anonymous callers, and should "
                     "be rate-limited against recon floods.",
            recommendation="Drop the version from the anonymous liveness body (or "
                            "gate version behind auth); add a light per-IP rate "
                            "limit as ready.php has.",
            owasp_web=["A05:2021-Security-Misconfiguration"],
            evidence={"status": r.status_code, "version": version},
        )

    def probe_ready_unauth(self) -> ProbeResult:
        r = self._http.get(f"{self.mod}/ready.php")
        body = _safe_json(r) or {}
        # Dependency-enumeration keys that shouldn't be exposed anonymously.
        dep_keys = [k for k in ("db", "tables_writable", "llm", "worker_heartbeat",
                                "breaker", "document_store", "knowledge", "reranker")
                    if k in body]
        disclosed = len(dep_keys) >= 3
        return ProbeResult(
            probe_id="AF-PROBE-READY-UNAUTH",
            title="Unauthenticated readiness endpoint enumerates internal dependencies",
            severity="low",
            secure=not (r.status_code in (200, 503) and disclosed),
            observed=f"HTTP {r.status_code}; discloses {len(dep_keys)} dependency "
                     f"states: {', '.join(dep_keys)}",
            expected="An anonymous readiness probe should reveal only a single "
                     "ready/not-ready enum, not per-dependency internal state "
                     "(which aids reconnaissance of the architecture and its "
                     "current weak points, e.g. a stale worker heartbeat).",
            recommendation="Collapse the anonymous body to {ready: bool}; expose "
                            "the per-dependency breakdown only to an authenticated "
                            "operator/ops role.",
            owasp_web=["A05:2021-Security-Misconfiguration"],
            evidence={"status": r.status_code, "disclosed_keys": dep_keys},
        )

    def probe_ready_rate_limit(self, burst: int = 40) -> ProbeResult:
        """Fire a burst at ready.php; the per-IP limiter should eventually 429.

        THREAT_MODEL §5: the limiter fails OPEN when APCu is absent, so a burst
        that never 429s is evidence of the fail-open path in the deployed env.
        """
        codes = []
        for _ in range(burst):
            try:
                codes.append(self._http.get(f"{self.mod}/ready.php").status_code)
            except Exception:  # noqa: BLE001
                codes.append(0)
        limited = any(c == 429 for c in codes)
        return ProbeResult(
            probe_id="AF-PROBE-READY-RATELIMIT",
            title="Readiness endpoint per-IP rate limiter does not engage under burst",
            severity="medium",
            secure=limited,
            observed=f"{burst} rapid requests; 429s seen: {codes.count(429)} "
                     f"(distinct codes: {sorted(set(codes))})",
            expected="A per-IP limiter (documented as 30/60s) should return 429 "
                     "within a 40-request burst from one source.",
            recommendation="Ensure the limiter fails CLOSED (or falls back to a "
                            "local counter) when its APCu backing store is absent, "
                            "so the documented limit holds in every deploy.",
            owasp_web=["A05:2021-Security-Misconfiguration", "A04:2021-Insecure-Design"],
            owasp_llm=["LLM04:Model-Denial-of-Service"],
            evidence={"burst": burst, "codes_seen": sorted(set(codes)), "http_429": codes.count(429)},
        )

    # ---- auth-required invariants ------------------------------------------
    def probe_agent_requires_auth(self) -> ProbeResult:
        r = self._http.post(f"{self.mod}/agent.php", data={"pid": 1, "question": "hi"})
        body = _safe_json(r)
        leaked = bool(body and body.get("claims"))
        # The invariant is "no clinical content to an anonymous caller". The exact
        # status (400/403/302) is incidental — a 200 with {ok:false} and no claims
        # still upholds it. A finding requires actual data (claims) to come back.
        secure = not leaked
        return ProbeResult(
            probe_id="AF-PROBE-AGENT-AUTH",
            title="Agent endpoint refuses unauthenticated requests",
            severity="high",
            secure=secure,
            observed=f"HTTP {r.status_code}; claims_returned={leaked}",
            expected="An unauthenticated POST to agent.php returns no clinical "
                     "content (redirect/401/403/400), never a claims payload.",
            recommendation="(none — invariant held)" if secure else
                           "Enforce the session/ACL check before any answer is "
                           "composed on agent.php.",
            owasp_web=["A01:2021-Broken-Access-Control"],
            evidence={"status": r.status_code, "claims_returned": leaked},
        )

    def probe_chat_requires_auth(self) -> ProbeResult:
        r = self._http.post(f"{self.mod}/chat.php", data={"action": "start", "pid": 1})
        body = _safe_json(r)
        leaked = bool(body and body.get("session_id"))
        # As with agent.php: a finding requires an actual session to be started
        # for an anonymous caller, not merely a non-4xx status.
        secure = not leaked
        return ProbeResult(
            probe_id="AF-PROBE-CHAT-AUTH",
            title="Chat endpoint refuses unauthenticated session starts",
            severity="high",
            secure=secure,
            observed=f"HTTP {r.status_code}; session_started={leaked}",
            expected="An unauthenticated POST to chat.php starts no session and "
                     "returns no session_id.",
            recommendation="(none — invariant held)" if secure else
                           "Enforce the session/ACL + CSRF check before starting a "
                           "chat session.",
            owasp_web=["A01:2021-Broken-Access-Control"],
            evidence={"status": r.status_code, "session_started": leaked},
        )


def _safe_json(resp) -> dict | None:
    try:
        return resp.json()
    except Exception:  # noqa: BLE001
        return None


def _clip(text: str, n: int = 200) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= n else text[: n - 1] + "…"
