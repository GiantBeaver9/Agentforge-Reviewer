"""Fix validation — reproduce a finding, apply the recommended fix, re-test.

The three live findings are against a third-party target we cannot redeploy, so
"validate the fix" is demonstrated the way a senior engineer would gate it in
review: pin the *detector* (the deterministic probe / the invariant regression)
against a fixture of the current (vulnerable) response so it fires, then apply
the documented remediation to the fixture and prove the same detector goes green.
A fix that does not flip the detector is not a fix.

Referenced from docs/VULNERABILITY_REPORTS.md §"Fix validation".
"""
import glob
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentforge.agents.redteam import SeedCase
from agentforge.probes import ProbeHarness
from agentforge.regression import RegressionHarness
from agentforge.target.client import MockTargetClient


# --------------------------------------------------------------------------- #
#  A minimal fake HTTP layer so a probe can run against a canned response.
# --------------------------------------------------------------------------- #
class _Resp:
    def __init__(self, status_code=200, body=None, text=""):
        self.status_code = status_code
        self._body = body
        self.text = text if text else (json.dumps(body) if body is not None else "")

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


class _FakeClient:
    """Returns a fixed response for every GET/POST — the 'deployed' behavior."""

    def __init__(self, resp: _Resp):
        self._resp = resp

    def get(self, url, *a, **k):
        return self._resp

    def post(self, url, *a, **k):
        return self._resp


# --------------------------------------------------------------------------- #
#  AF-PROBE-HEALTH-UNAUTH — version disclosure (+ supply-chain AF-SUP-001)
# --------------------------------------------------------------------------- #
def test_health_version_disclosure_reproduces_then_fix_clears():
    # 1) Reproduce: the current deploy returns the exact build string.
    vulnerable = _FakeClient(_Resp(
        200, {"status": "ok", "module": "oe-module-clinical-copilot", "version": "1"}))
    finding = ProbeHarness("https://target", http=vulnerable).probe_health_unauth()
    assert finding.secure is False  # the finding fires

    # 2) Apply the recommended fix: drop the version from the anonymous body.
    fixed = _FakeClient(_Resp(200, {"status": "ok"}))
    revalidated = ProbeHarness("https://target", http=fixed).probe_health_unauth()
    assert revalidated.secure is True  # same detector, now green


# --------------------------------------------------------------------------- #
#  AF-PROBE-READY-RATELIMIT — limiter fails open under burst
# --------------------------------------------------------------------------- #
class _BurstClient:
    """Serves N 200s then starts 429ing — a limiter that engages after `after`."""

    def __init__(self, after: int | None):
        self.after = after
        self.n = 0

    def get(self, url, *a, **k):
        self.n += 1
        if self.after is not None and self.n > self.after:
            return _Resp(429, {"error": "rate_limited"})
        return _Resp(200, {"ready": True})


def test_ready_rate_limit_reproduces_then_fix_clears():
    # 1) Reproduce: limiter never engages (fails open) -> finding.
    finding = ProbeHarness("https://t", http=_BurstClient(after=None)).probe_ready_rate_limit(burst=40)
    assert finding.secure is False
    # 2) Fix: limiter fails closed and 429s within the burst -> green.
    fixed = ProbeHarness("https://t", http=_BurstClient(after=30)).probe_ready_rate_limit(burst=40)
    assert fixed.secure is True


# --------------------------------------------------------------------------- #
#  Invariant fix-validation via the regression harness (clinical invariant)
# --------------------------------------------------------------------------- #
def _seed(category="data_exfiltration"):
    for d in json.loads((ROOT / f"evals/cases/{category}.json").read_text()):
        if d["target_surface"] in ("chat", "agent"):
            return SeedCase.from_eval(d)
    raise AssertionError("no chat/agent seed")


def test_cross_patient_invariant_fix_validation():
    # A regressed build that leaks cross-patient PHI fails the invariant replay...
    leaked = RegressionHarness(MockTargetClient("leaky")).replay([_seed()])
    assert not leaked.passed and leaked.summary()["regressed"] >= 1
    # ...and the fixed (defended) build passes it — validated by invariant, not
    # by a string match on the old leak.
    fixed = RegressionHarness(MockTargetClient("defended")).replay([_seed()])
    assert fixed.passed and fixed.summary()["regressed"] == 0
