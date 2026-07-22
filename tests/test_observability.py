"""Observability store: append-only, and rollups join verdicts to attempts."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentforge.agents.judge import JudgeAgent
from agentforge.agents.redteam import RedTeamAgent, SeedCase
from agentforge.observability.store import ObservabilityStore
from agentforge.target.client import MockTargetClient
import json


def _seed():
    d = json.loads((ROOT / "evals/cases/data_exfiltration.json").read_text())[0]
    return SeedCase.from_eval(d)


def _directive(n=6):
    return {"directive_id": "dir-x", "campaign_id": "camp-x", "correlation_id": "camp-x",
            "attack_category": "data_exfiltration", "target_surface": "chat",
            "rationale": "coverage_gap", "priority": 5, "max_turns": 4,
            "budget": {"max_attempts": n, "max_usd": 1.0}}


def test_records_are_append_only(tmp_path):
    store = ObservabilityStore(tmp_path / "run.jsonl")
    store.record({"type": "orchestrator_to_redteam", "producer": "orchestrator",
                  "correlation_id": "c1"})
    store.record({"type": "redteam_to_judge", "producer": "redteam", "correlation_id": "c1",
                  "attempt_id": "a1", "attack_category": "data_exfiltration",
                  "target_surface": "chat"})
    events = store.events()
    assert len(events) == 2
    assert all("_observed_at" in e for e in events)


def test_coverage_joins_verdicts_to_attempts(tmp_path):
    store = ObservabilityStore(tmp_path / "run.jsonl")
    target = MockTargetClient("leaky")     # leaks -> Judge should call success
    attempts = RedTeamAgent(target).run_directive(_directive(), [_seed()])
    store.record_all(attempts)
    judge = JudgeAgent()
    for a in attempts:
        store.record(judge.judge(a).to_wire())

    cov = store.coverage()
    cell = cov[("data_exfiltration", "chat")]
    assert cell.attempts == len(attempts)
    assert cell.verdicts == len(attempts)
    # A leaky target should yield at least one confirmed success.
    assert cell.successes >= 1
    assert store.open_findings()               # non-empty
    assert store.summary()["open_findings"] >= 1


def test_agent_responses_carry_provenance(tmp_path):
    store = ObservabilityStore(tmp_path / "run.jsonl")
    attempts = RedTeamAgent(MockTargetClient("leaky")).run_directive(_directive(), [_seed()])
    store.record_all(attempts)
    judge = JudgeAgent()
    for a in attempts:
        store.record(judge.judge(a).to_wire())

    ar = store.agent_responses()
    assert ar["attempts"] and ar["verdicts"]
    # deterministic red team (no LLM) -> every attempt tagged deterministic
    assert {a["attack_source"] for a in ar["attempts"]} == {"deterministic"}
    # deterministic judge -> every verdict tagged deterministic
    assert {v["decision_path"] for v in ar["verdicts"]} == {"deterministic"}
    # raw text is surfaced for the tab (attacker turn + target response)
    assert any(a["attacker"] for a in ar["attempts"])


def test_summary_is_deterministic(tmp_path):
    """The rollup is code-only (no LLM, no clock in the numbers), so summarizing
    the same store twice must return byte-identical results. Guards against a
    future change sneaking non-determinism (set ordering, time, randomness) into
    the numbers the Orchestrator scores and the dashboard renders."""
    store = ObservabilityStore(tmp_path / "run.jsonl")
    target = MockTargetClient("leaky")
    attempts = RedTeamAgent(target).run_directive(_directive(), [_seed()])
    store.record_all(attempts)
    judge = JudgeAgent()
    for a in attempts:
        store.record(judge.judge(a).to_wire())

    first = store.summary()
    second = store.summary()
    assert first == second
    # serialize too — catches ordering diffs that == on nested dicts/lists hides
    assert json.dumps(first, sort_keys=False) == json.dumps(second, sort_keys=False)


def test_defended_target_has_no_open_findings(tmp_path):
    store = ObservabilityStore(tmp_path / "run.jsonl")
    attempts = RedTeamAgent(MockTargetClient("defended")).run_directive(_directive(), [_seed()])
    store.record_all(attempts)
    judge = JudgeAgent()
    for a in attempts:
        store.record(judge.judge(a).to_wire())
    assert store.open_findings() == []
    cell = store.coverage()[("data_exfiltration", "chat")]
    assert cell.pass_rate == 1.0               # every judged attempt defended
