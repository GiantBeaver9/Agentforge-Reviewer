"""AgentForge CLI — run the adversarial platform against the target.

Commands:
    redteam    run a Red Team campaign only (seed + mutations), emit attempts
    campaign   run the FULL loop: Orchestrator -> Red Team -> Judge -> Documentation
    judge      (re)judge a captured attempts file offline, emit verdicts
    regression replay the regression suite (invariant-based); non-zero on a regression
    dashboard  print the observability rollup for a run log

Examples:
    # Offline dry-run (mock target) — works anywhere:
    python -m agentforge.cli campaign --dry-run --mock-policy leaky

    # Live full campaign against the deployed target (needs egress + creds):
    python -m agentforge.cli campaign --pid 1 --max-attempts 4
"""
from __future__ import annotations

import argparse
import glob
import json
import sys
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
CASES_DIR = ROOT / "evals" / "cases"
RUNS_DIR = ROOT / "runs"

sys.path.insert(0, str(ROOT / "src"))

from agentforge import config as cfgmod                                  # noqa: E402
from agentforge.agents.judge import JudgeAgent                           # noqa: E402
from agentforge.agents.llm import build_judge_llm, build_redteam_llm    # noqa: E402
from agentforge.agents.orchestrator import CampaignState, OrchestratorAgent  # noqa: E402
from agentforge.agents.redteam import RedTeamAgent, SeedCase             # noqa: E402
from agentforge.observability.store import ObservabilityStore           # noqa: E402
from agentforge.pipeline import run_campaign                             # noqa: E402
from agentforge.target.client import MockTargetClient, OpenEmrTargetClient  # noqa: E402


def _build_judge(args, cfg) -> JudgeAgent:
    """Deterministic Judge by default; opt into the independent LLM with
    --use-llm-judge (requires JUDGE_BASE_URL + egress to it)."""
    if getattr(args, "use_llm_judge", False):
        llm = build_judge_llm(cfg)
        if llm is not None:
            print(f"[judge] LLM refinement on: {cfg.judge.model}")
            return JudgeAgent(llm=llm, model_name=cfg.judge.model)
        print("[judge] --use-llm-judge set but JUDGE_BASE_URL empty; using rubric")
    return JudgeAgent()


def _build_redteam_llm(args, cfg):
    if getattr(args, "use_llm_redteam", False):
        llm = build_redteam_llm(cfg)
        if llm is not None:
            print(f"[redteam] LLM variants on: {cfg.redteam.model}")
            return llm
        print("[redteam] --use-llm-redteam set but REDTEAM_BASE_URL empty; using operators")
    return None


def _load_seed_cases(category: str | None, regression_only: bool = False) -> list[SeedCase]:
    seeds: list[SeedCase] = []
    for f in sorted(glob.glob(str(CASES_DIR / "*.json"))):
        for d in json.loads(Path(f).read_text()):
            if category and d["attack_category"] != category:
                continue
            if regression_only and not d.get("regression"):
                continue
            # only cases on an LLM-driven surface (chat/agent) run through here
            if d["target_surface"] in ("chat", "agent"):
                seeds.append(SeedCase.from_eval(d))
    return seeds


def _load_ground_truth() -> list[dict]:
    """Labeled attempts that pin the Judge rubric (evals/ground_truth.json)."""
    gt = ROOT / "evals" / "ground_truth.json"
    return json.loads(gt.read_text()) if gt.exists() else []


def _make_target(args):
    cfg = cfgmod.load()
    if args.dry_run:
        print(f"[dry-run] mock target policy={args.mock_policy}")
        return MockTargetClient(policy=args.mock_policy)
    client = OpenEmrTargetClient(cfg.target, csrf_pid=args.pid)
    client.login()
    print(f"[live] target={cfg.target.base_url}")
    return client


def _directive(category: str | None, max_attempts: int, max_turns: int) -> dict:
    return {
        "directive_id": f"dir-{uuid4().hex[:8]}",
        "campaign_id": f"camp-{uuid4().hex[:8]}",
        "correlation_id": f"camp-{uuid4().hex[:8]}",
        "attack_category": category or "prompt_injection",
        "target_surface": "chat",
        "rationale": "coverage_gap",
        "priority": 5,
        "max_turns": max_turns,
        "budget": {"max_attempts": max_attempts, "max_usd": 1.0},
    }


def cmd_redteam(args: argparse.Namespace) -> int:
    cfg = cfgmod.load()
    target = _make_target(args)
    seeds = _load_seed_cases(args.category)
    if not seeds:
        print("no seed cases for that category on an LLM surface", file=sys.stderr)
        return 2
    agent = RedTeamAgent(target=target, pinned_pid=args.pid, llm=_build_redteam_llm(args, cfg))
    directive = _directive(args.category, args.max_attempts, cfg.budget.max_turns)
    attempts = agent.run_directive(directive, seeds)

    RUNS_DIR.mkdir(exist_ok=True)
    path = RUNS_DIR / f"{directive['campaign_id']}.attempts.jsonl"
    with path.open("w") as fh:
        for a in attempts:
            fh.write(json.dumps(a) + "\n")

    print(f"ran {len(attempts)} attempts across {len(seeds)} seeds -> {path}")
    for a in attempts[: args.show]:
        target_turn: dict = next((t for t in a["turns"] if t["role"] == "target"), {})
        print(f"  {a['attempt_id']} [{a['attack_technique']:8}] "
              f"{a['attack_category']:22} -> {target_turn.get('content', '')[:70]!r}")
    return 0


def cmd_campaign(args: argparse.Namespace) -> int:
    cfg = cfgmod.load()
    target = _make_target(args)
    seeds = _load_seed_cases(args.category)
    if not seeds:
        print("no seed cases for that category on an LLM surface", file=sys.stderr)
        return 2

    RUNS_DIR.mkdir(exist_ok=True)
    run_id = f"camp-{uuid4().hex[:8]}"
    store = ObservabilityStore(RUNS_DIR / f"{run_id}.observability.jsonl")
    orch = OrchestratorAgent(store, CampaignState(
        max_attempts=args.max_attempts * args.rounds, max_usd=args.max_usd))

    result = run_campaign(
        target=target, seeds=seeds, store=store, orchestrator=orch,
        judge=_build_judge(args, cfg), redteam_llm=_build_redteam_llm(args, cfg),
        pinned_pid=args.pid, max_rounds=args.rounds,
        max_attempts_per_round=args.max_attempts,
        ground_truth=_load_ground_truth(),
    )
    if result.drift is not None:
        gate = "PASS" if result.drift["passed"] else "FAIL"
        print(f"  judge-drift gate [{gate}] "
              f"{result.drift['agreements']}/{result.drift['total']} labeled cases agree "
              f"(rubric {result.drift['rubric_version']})")
    if result.regression is not None:
        rs = result.regression.summary()
        print(f"  regression (target changed): {rs['passed']}/{rs['total']} held, "
              f"{rs['regressed']} regressed {rs['regressed_cases'] or ''}")

    # Persist reports for the Documentation deliverable.
    reports_path = RUNS_DIR / f"{run_id}.reports.json"
    reports_path.write_text(json.dumps([r.to_dict() for r in result.reports], indent=2))

    summary = store.summary()
    # Record a cross-run history snapshot (fail-soft — never break a campaign
    # over a history write). Uses Postgres if DATABASE_URL is set, else SQLite.
    try:
        from agentforge.observability.history import HistoryStore
        hist = HistoryStore(sqlite_path=RUNS_DIR / "history.db")
        hist.record_snapshot(run_id, summary, mode="dry-run" if args.dry_run else "live")
        print(f"  history -> {hist.backend} snapshot for {run_id}")
    except Exception as exc:  # noqa: BLE001
        print(f"  history -> skipped ({type(exc).__name__}: {exc})")
    print(f"\ncampaign {run_id} -> {store.path.name}")
    print(f"  directives={len(result.directives)} attempts={summary['attempts']} "
          f"verdicts={summary['verdicts']} findings={summary['open_findings']} "
          f"halt={result.halt.reason if result.halt else None}")
    for r in result.reports[: args.show]:
        print(f"  FINDING {r.finding_id} [{r.severity:8}] {r.title}  ({r.status})")
    print(f"  reports -> {reports_path}")
    _print_coverage(summary)
    return 0


def cmd_judge(args: argparse.Namespace) -> int:
    attempts = [json.loads(line) for line in Path(args.attempts).read_text().splitlines() if line.strip()]
    judge = _build_judge(args, cfgmod.load())
    out = Path(args.attempts).with_suffix(".verdicts.jsonl")
    findings = 0
    with out.open("w") as fh:
        for a in attempts:
            v = judge.judge(a).to_wire()
            fh.write(json.dumps(v) + "\n")
            if v["verdict"] == "success":
                findings += 1
    print(f"judged {len(attempts)} attempts -> {out} ({findings} confirmed findings)")
    return 0


def cmd_regression(args: argparse.Namespace) -> int:
    """Replay the regression suite against the target's current build.

    Each case passes only when its *invariant* holds (the target defends), not by
    a string match — so a reworded-but-still-broken response still fails. Exits
    non-zero if any confirmed-then-fixed case has regressed, so it can gate a
    deploy on a target-version change.
    """
    from agentforge.regression import RegressionHarness
    cfg = cfgmod.load()
    target = _make_target(args)
    cases = _load_seed_cases(args.category, regression_only=True)
    if not cases:
        print("no regression-flagged seed cases on an LLM surface", file=sys.stderr)
        return 2

    harness = RegressionHarness(target=target, judge=_build_judge(args, cfg),
                                pinned_pid=args.pid)
    report = (harness.replay_with_siblings(cases, cases, cross_category=True)
              if args.cross_category else harness.replay(cases))
    summary = report.summary()

    RUNS_DIR.mkdir(exist_ok=True)
    out = RUNS_DIR / f"regression-{uuid4().hex[:8]}.json"
    out.write_text(json.dumps({"summary": summary,
                               "results": [r.__dict__ for r in report.results]}, indent=2))

    print(f"replayed {summary['total']} case(s): {summary['passed']} held, "
          f"{summary['regressed']} regressed, {summary['unreachable']} unreachable")
    for r in report.results:
        flag = "PASS " if r.passed else ("SKIP " if r.unreachable else "REGRESS")
        print(f"  [{flag}] {r.case_id:14} {r.attack_category:26} verdict={r.verdict}")
    if summary["regressed_cases"]:
        print(f"  REGRESSED: {summary['regressed_cases']}")
    print(f"  -> {out}")
    # Non-zero on a real regression so CI/deploy gating can block on it.
    return 1 if summary["regressed"] > 0 else 0


def cmd_loadtest(args: argparse.Namespace) -> int:
    from agentforge.loadtest import sweep
    cfg = cfgmod.load()
    print(f"[loadtest] {args.n} req/level against {cfg.target.base_url} (health.php)")
    results = sweep(cfg.target.base_url, n=args.n)
    RUNS_DIR.mkdir(exist_ok=True)
    out = RUNS_DIR / f"loadtest-{uuid4().hex[:8]}.json"
    out.write_text(json.dumps([s.summary() for s in results], indent=2))
    print(f"  {'conc':>4} {'rps':>8} {'p50':>7} {'p95':>7} {'p99':>7} {'errs':>5}")
    for s in results:
        m = s.summary()["latency_ms"]
        print(f"  {s.concurrency:>4} {s.throughput_rps:>8} {m['p50']:>7} "
              f"{m['p95']:>7} {m['p99']:>7} {s.errors:>5}")
    print(f"  -> {out}")
    return 0


def cmd_web(args: argparse.Namespace) -> int:
    from agentforge.web import main as web_main
    web_main(args.host, args.port)
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    from agentforge.probes import ProbeHarness
    cfg = cfgmod.load()
    print(f"[probe] deterministic probes against {cfg.target.base_url}")
    results = ProbeHarness(cfg.target.base_url).run_all()
    findings = [r for r in results if not r.secure]

    RUNS_DIR.mkdir(exist_ok=True)
    out = RUNS_DIR / f"probes-{uuid4().hex[:8]}.json"
    out.write_text(json.dumps([r.to_dict() for r in results], indent=2))

    for r in results:
        flag = "FINDING" if not r.secure else "ok     "
        print(f"  [{flag}] {r.severity:8} {r.probe_id:26} {r.title}")
        if not r.secure:
            print(f"            observed: {r.observed}")
    print(f"\n{len(findings)} finding(s) / {len(results)} probes -> {out}")
    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    store = ObservabilityStore(args.run)
    summary = store.summary()
    print(f"run: {args.run}")
    print(f"attempts={summary['attempts']} verdicts={summary['verdicts']} "
          f"open_findings={summary['open_findings']} cost_usd={summary['cost_usd']}")
    _print_coverage(summary)
    for f in store.open_findings()[: args.show]:
        print(f"  OPEN [{f['severity']:8}] attempt={f['attempt_id']} conf={f['confidence']}")
    return 0


def _print_coverage(summary: dict) -> None:
    print("  coverage (category / surface: attempts, verdicts, success, pass_rate):")
    for c in summary["coverage"]:
        pr = "n/a" if c["pass_rate"] is None else f"{c['pass_rate']:.2f}"
        print(f"    {c['attack_category']:26} {c['target_surface']:6} "
              f"att={c['attempts']:<3} ver={c['verdicts']:<3} succ={c['successes']:<3} pass={pr}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="agentforge")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_target_opts(sp):
        sp.add_argument("--category", default=None, help="attack_category to focus on")
        sp.add_argument("--dry-run", action="store_true", help="use the offline mock target")
        sp.add_argument("--mock-policy", default="defended", choices=["defended", "leaky"])
        sp.add_argument("--pid", type=int, default=1, help="pinned patient id")
        sp.add_argument("--show", type=int, default=10)

    rt = sub.add_parser("redteam", help="run a Red Team campaign only")
    add_target_opts(rt)
    rt.add_argument("--max-attempts", type=int, default=25)
    rt.add_argument("--use-llm-redteam", action="store_true",
                    help="generate mutation variants with the REDTEAM_* model")
    rt.set_defaults(func=cmd_redteam)

    cp = sub.add_parser("campaign", help="run the full multi-agent loop")
    add_target_opts(cp)
    cp.add_argument("--rounds", type=int, default=3, help="orchestrator rounds")
    cp.add_argument("--max-attempts", type=int, default=6, help="max attempts per round")
    cp.add_argument("--max-usd", type=float, default=2.0)
    cp.add_argument("--use-llm-judge", action="store_true",
                    help="refine uncertain/partial verdicts with the JUDGE_* model")
    cp.add_argument("--use-llm-redteam", action="store_true",
                    help="generate mutation variants with the REDTEAM_* model")
    cp.set_defaults(func=cmd_campaign)

    ju = sub.add_parser("judge", help="(re)judge a captured attempts file offline")
    ju.add_argument("attempts", help="path to a runs/*.attempts.jsonl file")
    ju.add_argument("--use-llm-judge", action="store_true",
                    help="refine uncertain/partial verdicts with the JUDGE_* model")
    ju.set_defaults(func=cmd_judge)

    pb = sub.add_parser("probe", help="run deterministic HTTP probes (unauth surface)")
    pb.set_defaults(func=cmd_probe)

    rg = sub.add_parser("regression", help="replay the regression suite (invariant-based)")
    add_target_opts(rg)
    rg.add_argument("--cross-category", action="store_true",
                    help="also replay a bounded sample of other categories (catch cross-category regressions)")
    rg.add_argument("--use-llm-judge", action="store_true",
                    help="refine uncertain/partial verdicts with the JUDGE_* model")
    rg.set_defaults(func=cmd_regression)

    wb = sub.add_parser("web", help="launch the local web dashboard (GUI)")
    wb.add_argument("--host", default="127.0.0.1")
    wb.add_argument("--port", type=int, default=8800)
    wb.set_defaults(func=cmd_web)

    lt = sub.add_parser("loadtest", help="baseline load test of the cheap unauth surface")
    lt.add_argument("--n", type=int, default=100, help="requests per concurrency level")
    lt.set_defaults(func=cmd_loadtest)

    db = sub.add_parser("dashboard", help="print the observability rollup for a run")
    db.add_argument("run", help="path to a runs/*.observability.jsonl file")
    db.add_argument("--show", type=int, default=10)
    db.set_defaults(func=cmd_dashboard)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
