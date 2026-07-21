"""Orchestrator scoring/halt + full pipeline wiring over the mock target."""
import glob
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from jsonschema import Draft202012Validator
from agentforge.agents.orchestrator import CampaignState, OrchestratorAgent
from agentforge.agents.redteam import SeedCase
from agentforge.observability.store import ObservabilityStore
from agentforge.pipeline import run_campaign
from agentforge.target.client import MockTargetClient

DSCHEMA = Draft202012Validator(
    json.loads((ROOT / "contracts/v1/orchestrator_to_redteam.schema.json").read_text()))


def _all_seeds():
    seeds = []
    for f in sorted(glob.glob(str(ROOT / "evals/cases/*.json"))):
        for d in json.loads(Path(f).read_text()):
            if d["target_surface"] in ("chat", "agent"):
                seeds.append(SeedCase.from_eval(d))
    return seeds


def test_directive_is_contract_valid(tmp_path):
    store = ObservabilityStore(tmp_path / "run.jsonl")
    directive = OrchestratorAgent(store).next_directive(max_attempts=5)
    DSCHEMA.validate(directive)


def test_uncovered_cell_scores_highest(tmp_path):
    store = ObservabilityStore(tmp_path / "run.jsonl")
    orch = OrchestratorAgent(store)
    scored = orch.score_cells()
    # With no coverage yet, the highest base_priority cell wins.
    assert scored[0][1]["base_priority"] == 5


def test_budget_halt(tmp_path):
    store = ObservabilityStore(tmp_path / "run.jsonl")
    orch = OrchestratorAgent(store, CampaignState(max_usd=1.0, spent_usd=1.0))
    assert orch.halt_check().halt
    assert orch.halt_check().reason == "budget_exceeded"


def test_no_signal_window_halt(tmp_path):
    store = ObservabilityStore(tmp_path / "run.jsonl")
    orch = OrchestratorAgent(store, CampaignState(halt_after_empty_windows=2))
    orch.account([], new_successes=0)
    orch.account([], new_successes=0)
    d = orch.halt_check()
    assert d.halt and d.reason == "no_findings_in_window"


def test_target_version_change_detected(tmp_path):
    store = ObservabilityStore(tmp_path / "run.jsonl")
    orch = OrchestratorAgent(store, CampaignState(last_target_version="v1"))
    assert orch.target_changed("v2") is True
    assert orch.target_changed("v2") is False   # no change second time


def test_full_pipeline_defended(tmp_path):
    store = ObservabilityStore(tmp_path / "run.jsonl")
    result = run_campaign(target=MockTargetClient("defended"), seeds=_all_seeds(),
                          store=store, max_rounds=2, max_attempts_per_round=6)
    assert result.directives
    assert result.attempts
    assert result.verdicts
    assert result.reports == []                # defended target -> no findings
    assert store.summary()["open_findings"] == 0


def test_full_pipeline_leaky_produces_reports(tmp_path):
    store = ObservabilityStore(tmp_path / "run.jsonl")
    result = run_campaign(target=MockTargetClient("leaky"), seeds=_all_seeds(),
                          store=store, max_rounds=2, max_attempts_per_round=6)
    assert result.reports, "leaky target should yield at least one vuln report"
    # Every report traces back to a recorded success verdict.
    assert store.summary()["open_findings"] >= 1
    assert all(r.status in ("draft", "pending_human_approval") for r in result.reports)
