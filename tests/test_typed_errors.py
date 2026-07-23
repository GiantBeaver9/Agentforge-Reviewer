"""Typed AgentError emission: the named failure modes are emitted on the wire
and validate against the error contract at runtime (not raw look-alike dicts)."""
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
from agentforge.target.client import MockTargetClient, TargetUnreachable

ESCHEMA = Draft202012Validator(
    json.loads((ROOT / "contracts/v1/errors.schema.json").read_text()))


def _all_seeds():
    seeds = []
    for f in sorted(glob.glob(str(ROOT / "evals/cases/*.json"))):
        for d in json.loads(Path(f).read_text()):
            if d["target_surface"] in ("chat", "agent"):
                seeds.append(SeedCase.from_eval(d))
    return seeds


def _errors(store):
    return [e for e in store.events() if e.get("type") == "error"]


def _wire(event):
    # Strip store-local annotations (``_observed_at`` etc.) that the append-only
    # log adds on receipt; the on-wire message is everything without them.
    return {k: v for k, v in event.items() if not k.startswith("_")}


def test_emitted_errors_are_contract_valid(tmp_path):
    store = ObservabilityStore(tmp_path / "run.jsonl")
    orch = OrchestratorAgent(store, CampaignState(max_usd=0.0005, max_attempts=999))
    run_campaign(target=MockTargetClient("defended"), seeds=_all_seeds(), store=store,
                 orchestrator=orch, max_rounds=5, max_attempts_per_round=6)
    errs = _errors(store)
    assert errs, "a tiny budget should emit at least one typed error"
    for e in errs:                       # every emitted error validates on the wire
        ESCHEMA.validate(_wire(e))


def test_budget_exceeded_is_emitted_typed(tmp_path):
    store = ObservabilityStore(tmp_path / "run.jsonl")
    orch = OrchestratorAgent(store, CampaignState(max_usd=0.0005, max_attempts=999))
    run_campaign(target=MockTargetClient("defended"), seeds=_all_seeds(), store=store,
                 orchestrator=orch, max_rounds=5, max_attempts_per_round=6)
    codes = {e["error_code"] for e in _errors(store)}
    assert "budget_exceeded" in codes


class _DeadTarget:
    def start_chat(self, pid):
        raise TargetUnreachable("connect refused")

    def chat_turn(self, session_id, message):
        raise TargetUnreachable("connect refused")

    def agent_ask(self, pid, question):
        raise TargetUnreachable("connect refused")


def test_target_unreachable_is_emitted_typed(tmp_path):
    store = ObservabilityStore(tmp_path / "run.jsonl")
    run_campaign(target=_DeadTarget(), seeds=_all_seeds(), store=store,
                 max_rounds=1, max_attempts_per_round=4)
    errs = _errors(store)
    assert any(e["error_code"] == "target_unreachable" for e in errs)
    for e in errs:
        ESCHEMA.validate(_wire(e))
