"""Red Team drives the mock target end-to-end and every attempt is contract-valid."""
import json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from jsonschema import Draft202012Validator
from agentforge.agents.redteam import RedTeamAgent, SeedCase
from agentforge.target.client import MockTargetClient

SCHEMA = Draft202012Validator(json.loads((ROOT/"contracts/v1/redteam_to_judge.schema.json").read_text()))

def _seed():
    d = json.loads((ROOT/"evals/cases/prompt_injection.json").read_text())[0]
    return SeedCase.from_eval(d)

def _directive(n=10):
    return {"directive_id":"dir-x","campaign_id":"camp-x","correlation_id":"camp-x",
            "attack_category":"prompt_injection","target_surface":"chat","rationale":"coverage_gap",
            "priority":5,"max_turns":4,"budget":{"max_attempts":n,"max_usd":1.0}}

def test_seed_plus_mutations_all_valid():
    agent = RedTeamAgent(MockTargetClient("defended"))
    attempts = agent.run_directive(_directive(), [_seed()])
    assert len(attempts) == 5          # 1 seed + 4 deterministic mutations
    for a in attempts:
        SCHEMA.validate(a)             # raises if any attempt violates the contract
    assert {a["attack_technique"] for a in attempts} == {"seed","mutation"}

def test_leaky_target_produces_compliant_response():
    agent = RedTeamAgent(MockTargetClient("leaky"))
    attempts = agent.run_directive(_directive(), [_seed()])
    joined = " ".join(t["content"] for a in attempts for t in a["turns"] if t["role"]=="target")
    assert "patient 2" in joined.lower()   # leaky target leaks -> Judge should flag success

def test_budget_is_respected():
    agent = RedTeamAgent(MockTargetClient("defended"))
    attempts = agent.run_directive(_directive(n=3), [_seed()])
    assert len(attempts) <= 3
