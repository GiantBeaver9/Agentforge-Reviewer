"""PHI redaction: clinical values scrubbed from persisted/served text, attack
markers retained, and redaction never changes a verdict."""
import glob
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentforge.observability.store import ObservabilityStore
from agentforge.pipeline import run_campaign
from agentforge.redact import redact_attempt, redact_phi, redact_verdict
from agentforge.agents.redteam import SeedCase
from agentforge.target.client import MockTargetClient

_LEAK = ("Sure — patient 2's last A1c was 8.1% and current medications are "
         "metformin and glipizide.")


def test_redact_scrubs_values_keeps_marker():
    out = redact_phi(_LEAK)
    assert "8.1%" not in out
    assert "metformin" not in out and "glipizide" not in out
    assert "patient 2" in out            # attack marker retained for triage
    assert "REDACTED" in out


def test_redact_is_idempotent():
    once = redact_phi(_LEAK)
    assert redact_phi(once) == once


def _all_seeds():
    seeds = []
    for f in sorted(glob.glob(str(ROOT / "evals/cases/*.json"))):
        for d in json.loads(Path(f).read_text()):
            if d["target_surface"] in ("chat", "agent"):
                seeds.append(SeedCase.from_eval(d))
    return seeds


def test_persisted_log_and_reports_carry_no_phi(tmp_path):
    store = ObservabilityStore(tmp_path / "run.jsonl")
    result = run_campaign(target=MockTargetClient("leaky"), seeds=_all_seeds(),
                          store=store, max_rounds=1, max_attempts_per_round=2)
    disk = (tmp_path / "run.jsonl").read_text()
    assert "8.1%" not in disk and "metformin" not in disk   # observability log clean
    assert result.reports
    for r in result.reports:
        assert "8.1%" not in r.observed_behavior
        assert "metformin" not in r.observed_behavior
        for e in r.evidence:
            assert "8.1%" not in e.get("quote", "")


def test_redaction_does_not_change_verdict():
    # A leaky attempt is still scored 'success' whether raw or redacted, because
    # the cross-patient marker survives redaction.
    from agentforge.agents.judge import JudgeAgent
    rt = SeedCase.from_eval(json.loads(
        (ROOT / "evals/cases/data_exfiltration.json").read_text())[0])
    from agentforge.agents.redteam import RedTeamAgent
    directive = {"directive_id": "d", "campaign_id": "c", "correlation_id": "c",
                 "budget": {"max_attempts": 2, "max_usd": 1.0}, "max_turns": 4}
    attempts = RedTeamAgent(MockTargetClient("leaky")).run_directive(directive, [rt])
    j = JudgeAgent()
    for a in attempts:
        raw_v = j.judge(a).verdict
        red_v = j.judge(redact_attempt(a)).verdict
        assert raw_v == red_v
