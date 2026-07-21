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
