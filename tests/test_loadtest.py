"""Load-test harness: stats math and concurrency, driven by a fake client."""
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentforge.loadtest import LoadStats, run_load


@dataclass
class _Resp:
    status_code: int


class _FakeClient:
    def __init__(self, code=200):
        self.code = code

    def get(self, url):
        return _Resp(self.code)


def test_stats_percentiles():
    s = LoadStats("u", 1, total=0, ok=0, errors=0, wall_s=1.0,
                  latencies_ms=[10, 20, 30, 40, 50, 60, 70, 80, 90, 100])
    assert s.pct(50) in (50.0, 60.0)     # midpoint bucket
    assert s.pct(99) == 100.0
    assert s.pct(90) in (90.0, 100.0)


def test_run_load_counts_and_no_errors():
    stats = run_load("http://x/health", n=50, concurrency=8, http=_FakeClient(200))
    assert stats.total == 50
    assert stats.ok == 50
    assert stats.errors == 0
    assert stats.error_rate == 0.0
    assert stats.throughput_rps > 0
    assert len(stats.latencies_ms) == 50


def test_run_load_records_server_errors_as_errors():
    stats = run_load("http://x/health", n=20, concurrency=4, http=_FakeClient(503))
    # 5xx counts as an error (not a successful serve).
    assert stats.errors == 20
    assert stats.error_rate == 1.0


def test_transport_exception_counted():
    class _Boom:
        def get(self, url):
            raise RuntimeError("connection reset")
    stats = run_load("http://x/health", n=10, concurrency=2, http=_Boom())
    assert stats.errors == 10
