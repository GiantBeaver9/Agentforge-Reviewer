"""Load-test harness — baseline throughput/latency of the target's cheap surface.

A 100-request load test that is **safe to run against the live deploy**: it hits
the unauthenticated liveness/readiness endpoints (``health.php`` / ``ready.php``),
which perform no LLM work and spend none of the co-pilot's token budget. That
keeps the perf baseline honest and repeatable without the destructive cost of
hammering ``agent.php``/``chat.php`` (whose per-request cost and latency are
characterized analytically from real single-shot measurements — see
docs/LOAD_TEST.md).

Deterministic and dependency-free (stdlib threads + the shared httpx client), so
it can run in CI as a smoke/perf gate.
"""
from __future__ import annotations

import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class LoadStats:
    endpoint: str
    concurrency: int
    total: int
    ok: int
    errors: int
    wall_s: float
    latencies_ms: list[float] = field(default_factory=list)

    @property
    def throughput_rps(self) -> float:
        return round(self.total / self.wall_s, 2) if self.wall_s > 0 else 0.0

    @property
    def error_rate(self) -> float:
        return round(self.errors / self.total, 4) if self.total else 0.0

    def pct(self, p: float) -> float:
        if not self.latencies_ms:
            return 0.0
        xs = sorted(self.latencies_ms)
        k = min(len(xs) - 1, max(0, int(round((p / 100.0) * (len(xs) - 1)))))
        return round(xs[k], 1)

    def summary(self) -> dict:
        return {
            "endpoint": self.endpoint,
            "concurrency": self.concurrency,
            "requests": self.total,
            "ok": self.ok,
            "errors": self.errors,
            "error_rate": self.error_rate,
            "wall_s": round(self.wall_s, 3),
            "throughput_rps": self.throughput_rps,
            "latency_ms": {
                "min": round(min(self.latencies_ms), 1) if self.latencies_ms else 0.0,
                "p50": self.pct(50), "p90": self.pct(90),
                "p95": self.pct(95), "p99": self.pct(99),
                "max": round(max(self.latencies_ms), 1) if self.latencies_ms else 0.0,
                "mean": round(statistics.fmean(self.latencies_ms), 1) if self.latencies_ms else 0.0,
            },
        }


def resource_snapshot() -> dict:
    """Platform-side (load-generator) CPU/memory, from the stdlib — no psutil.

    The target's CPU/mem isn't visible over HTTP, so this profiles *our* side: the
    peak RSS and CPU seconds this process spent generating the load, plus the host
    1-minute load average. Captured before/after a sweep, the deltas show how much
    the harness itself costs to drive a given concurrency.
    """
    import os
    import resource
    ru = resource.getrusage(resource.RUSAGE_SELF)
    # ru_maxrss is KiB on Linux (bytes on macOS); we run on Linux (KiB).
    snap = {
        "maxrss_mb": round(ru.ru_maxrss / 1024, 1),
        "cpu_user_s": round(ru.ru_utime, 3),
        "cpu_sys_s": round(ru.ru_stime, 3),
    }
    try:
        snap["load_avg_1m"] = round(os.getloadavg()[0], 2)
    except (OSError, AttributeError):  # not available on some platforms
        snap["load_avg_1m"] = None
    return snap


def _http_client(timeout: float = 30.0):
    import os
    import httpx
    verify = os.environ.get("SSL_CERT_FILE") or True
    ca = "/root/.ccr/ca-bundle.crt"
    if os.path.exists(ca):
        verify = ca
    return httpx.Client(timeout=timeout, verify=verify)


def run_load(url: str, n: int = 100, concurrency: int = 10, http=None,
             request: Callable | None = None) -> LoadStats:
    """Fire ``n`` GETs at ``url`` with ``concurrency`` workers; collect latencies.

    ``request`` overrides the per-call function (for tests/other verbs); it must
    return an object with ``.status_code`` or raise.
    """
    client = http or _http_client()
    latencies: list[float] = []
    ok = 0
    errors = 0

    def one() -> tuple[bool, float]:
        t0 = time.perf_counter()
        try:
            r = client.get(url) if request is None else request(client, url)
            dt = (time.perf_counter() - t0) * 1000
            return (200 <= r.status_code < 500, dt)
        except Exception:  # noqa: BLE001 — a transport error is a load error
            return (False, (time.perf_counter() - t0) * 1000)

    wall0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(one) for _ in range(n)]
        for f in as_completed(futures):
            success, dt = f.result()
            latencies.append(dt)
            if success:
                ok += 1
            else:
                errors += 1
    wall = time.perf_counter() - wall0

    return LoadStats(endpoint=url, concurrency=concurrency, total=n, ok=ok,
                     errors=errors, wall_s=wall, latencies_ms=latencies)


def sweep(base_url: str, path: str = "/interface/modules/custom_modules/"
          "oe-module-clinical-copilot/public/health.php",
          n: int = 100, concurrencies=(1, 5, 10, 20)) -> list[LoadStats]:
    """Run the 100-request test at several concurrency levels to find the knee."""
    url = base_url.rstrip("/") + path
    client = _http_client()
    return [run_load(url, n=n, concurrency=c, http=client) for c in concurrencies]
