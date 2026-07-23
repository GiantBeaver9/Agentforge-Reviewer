"""Reproducible, non-circular eval scoring.

Directly answers the review: eval results are written from a run (not
hand-authored) and are deterministic against the mock; and the invariant check is
independent of the Judge's blocklist — proven by the ``subtle`` leak the Judge
misses but the invariant still catches.
"""
import glob
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentforge.agents.judge import JudgeAgent
from agentforge.agents.redteam import RedTeamAgent, SeedCase
from agentforge.evalrunner import invariant_violated, run_eval_suite, suite_report
from agentforge.target.client import MockTargetClient


def _all_cases():
    cases = []
    for f in sorted(glob.glob(str(ROOT / "evals/cases/*.json"))):
        cases += json.loads(Path(f).read_text())
    return cases


def test_eval_run_is_deterministic_and_matches_committed_baseline():
    cases = _all_cases()
    r1 = suite_report(run_eval_suite(MockTargetClient("defended"), cases))
    r2 = suite_report(run_eval_suite(MockTargetClient("defended"), cases))
    assert r1 == r2                                   # reproducible byte-for-byte
    baseline = json.loads((ROOT / "evals/OFFLINE_BASELINE.json").read_text())
    got = {c["case_id"]: c["result"] for c in r1["cases"]}
    want = {c["case_id"]: c["result"] for c in baseline["cases"]}
    assert got == want                                # committed baseline reproduces


def test_leaky_build_fails_the_invariant():
    cases = _all_cases()
    report = suite_report(run_eval_suite(MockTargetClient("leaky"), cases))
    assert report["by_result"].get("fail", 0) > 0     # the check is not vacuous


def test_invariant_is_not_the_judge_blocklist_subtle_leak():
    # The `subtle` mock leaks cross-patient PHI paraphrased AWAY from every Judge
    # token. The deterministic Judge must MISS it (proving the two are different),
    # while the independent invariant still CATCHES it.
    exfil = next(c for c in _all_cases()
                 if c["id"] == "AF-EXF-001" and c["target_surface"] == "chat")
    rt = RedTeamAgent(MockTargetClient("subtle"))
    directive = {"directive_id": "d", "campaign_id": "c", "correlation_id": "c",
                 "budget": {"max_attempts": 2, "max_usd": 1.0}, "max_turns": 4}
    attempt = rt.run_directive(directive, [SeedCase.from_eval(exfil)])[0]
    output = next(t["content"] for t in reversed(attempt["turns"]) if t["role"] == "target")

    # Judge (substring blocklist) does NOT flag it as a success...
    assert JudgeAgent().judge(attempt).verdict != "success"
    # ...but the independent invariant DOES catch the disclosure.
    violated, reason = invariant_violated(exfil, output)
    assert violated and "cross-patient" in reason


def test_defended_output_does_not_trip_the_invariant():
    exfil = next(c for c in _all_cases() if c["id"] == "AF-EXF-001")
    violated, _ = invariant_violated(
        exfil, "I can only provide information for the patient pinned to this conversation.")
    assert not violated
    # The pinned patient's own value is fine (no other-individual reference).
    v2, _ = invariant_violated(exfil, "The pinned patient's last A1c was 7.2%.")
    assert not v2
