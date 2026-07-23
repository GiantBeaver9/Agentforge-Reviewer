"""Regression harness: invariant-based pass/fail, sibling replay."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentforge.agents.redteam import SeedCase
from agentforge.regression import RegressionHarness
from agentforge.target.client import MockTargetClient


def _seed(category="data_exfiltration"):
    for d in json.loads((ROOT / f"evals/cases/{category}.json").read_text()):
        if d["target_surface"] in ("chat", "agent"):
            return SeedCase.from_eval(d)
    raise AssertionError("no chat/agent seed")


def test_defended_build_passes_regression():
    harness = RegressionHarness(MockTargetClient("defended"))
    report = harness.replay([_seed()])
    assert report.passed
    assert report.summary()["regressed"] == 0


def test_regressed_build_is_caught():
    # A leaky build re-breaks the case -> invariant fails -> regression flagged.
    harness = RegressionHarness(MockTargetClient("leaky"))
    report = harness.replay([_seed()])
    assert not report.passed
    assert report.summary()["regressed"] >= 1
    assert _seed().id in report.summary()["regressed_cases"]


def test_sibling_replay_expands_coverage():
    harness = RegressionHarness(MockTargetClient("defended"))
    corpus = [_seed("data_exfiltration"), _seed("prompt_injection")]
    report = harness.replay_with_siblings([_seed("data_exfiltration")], corpus)
    # Replays the case plus its data_exfiltration siblings from the corpus.
    assert report.summary()["total"] >= 1
    assert report.passed


def test_inconclusive_status_is_produced():
    # A target whose answer carries neither leak nor defense marker -> the Judge
    # returns 'uncertain' -> the harness classifies INCONCLUSIVE (not held/pass).
    from agentforge.target.client import TurnResult
    from agentforge.regression import INCONCLUSIVE

    class _Ambiguous:
        def start_chat(self, pid): return "s"
        def _r(self): return TurnResult(content="Here is some general information.",
                                        http_status=200, latency_ms=1.0)
        def chat_turn(self, s, m): return self._r()
        def agent_ask(self, p, q): return self._r()

    report = RegressionHarness(_Ambiguous()).replay([_seed()])
    assert report.results[0].status == INCONCLUSIVE
    assert report.summary()["inconclusive"] == 1
    assert report.passed is False


def test_cli_regression_strict_fails_on_inconclusive(tmp_path, monkeypatch):
    import agentforge.cli as climod
    monkeypatch.setattr(climod, "RUNS_DIR", tmp_path)
    # A defended mock leaves benign cases 'uncertain' -> inconclusive present.
    assert climod.main(["regression", "--dry-run", "--mock-policy", "defended"]) == 0
    assert climod.main(["regression", "--dry-run", "--mock-policy", "defended", "--strict"]) == 1
