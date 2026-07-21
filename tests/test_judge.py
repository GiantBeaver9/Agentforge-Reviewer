"""Judge: contract-valid verdicts, correct success/failure calls, drift check."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from jsonschema import Draft202012Validator
from agentforge.agents.judge import JudgeAgent, RUBRIC_VERSION
from agentforge.agents.redteam import RedTeamAgent, SeedCase
from agentforge.target.client import MockTargetClient

VSCHEMA = Draft202012Validator(
    json.loads((ROOT / "contracts/v1/judge_to_documentation.schema.json").read_text()))


def _attempts(policy):
    d = json.loads((ROOT / "evals/cases/data_exfiltration.json").read_text())[0]
    directive = {"directive_id": "dir", "campaign_id": "c", "correlation_id": "c",
                 "attack_category": "data_exfiltration", "target_surface": "chat",
                 "rationale": "coverage_gap", "priority": 5, "max_turns": 4,
                 "budget": {"max_attempts": 6, "max_usd": 1.0}}
    return RedTeamAgent(MockTargetClient(policy)).run_directive(directive, [SeedCase.from_eval(d)])


def test_verdicts_are_contract_valid():
    judge = JudgeAgent()
    for a in _attempts("defended"):
        VSCHEMA.validate(judge.judge(a).to_wire())


def test_defended_target_judged_failure():
    judge = JudgeAgent()
    verdicts = [judge.judge(a).verdict for a in _attempts("defended")]
    assert all(v == "failure" for v in verdicts)


def test_leaky_target_judged_success_and_critical():
    judge = JudgeAgent()
    results = [judge.judge(a) for a in _attempts("leaky")]
    wins = [v for v in results if v.verdict == "success"]
    assert wins, "leaky target should produce at least one success verdict"
    # data_exfiltration success is critical and must escalate to a human.
    assert all(v.severity.value == "critical" for v in wins)
    assert all(v.escalate_to_human for v in wins)
    assert all(v.add_to_regression for v in wins)


def test_ground_truth_drift_check_passes():
    labeled = json.loads((ROOT / "evals/ground_truth.json").read_text())
    report = JudgeAgent().check_ground_truth(labeled)
    assert report["passed"], report["mismatches"]
    assert report["rubric_version"] == RUBRIC_VERSION
    assert report["agreements"] == report["total"] == len(labeled)
