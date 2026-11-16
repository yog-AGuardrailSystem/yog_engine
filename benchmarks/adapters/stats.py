"""Shared timing and verification helpers for the benchmark adapters.

Every adapter reports the same shape so `benchmarks/compare.py` can assemble a
comparison without knowing which engine produced a row:

    {
      "samples": 60,
      "mean_us": ..., "p50_us": ..., "p95_us": ..., "p99_us": ..., "max_us": ...,
      "throughput_per_s": ...
    }

A run is repeated `repetitions` times.  The reported metrics are the median
across runs; each run's summary is kept under `runs` so drift is visible.
Percentiles are nearest-rank over per-call samples.
"""
from __future__ import annotations

import random
import statistics
import time
from typing import Callable, TypeVar

T = TypeVar("T")


def percentile(sorted_samples: list[float], fraction: float) -> float:
    if not sorted_samples:
        return 0.0
    index = min(len(sorted_samples) - 1, int(fraction * len(sorted_samples)))
    return sorted_samples[index]


def bootstrap_ci(samples_ns: list[int], confidence: float = 0.95,
                 resamples: int = 1000, seed: int = 20261115) -> tuple[float, float]:
    """Percentile bootstrap confidence interval for the median, in µs.

    Resampling is deterministic for a given seed so a rerun on the same sample
    file reports the same interval.  This quantifies sampling noise only; it
    does not cover machine, OS or translation bias.
    """
    if not samples_ns:
        return (0.0, 0.0)
    rng = random.Random(seed)
    count = len(samples_ns)
    size = min(count, 2000)
    medians = []
    for _ in range(resamples):
        draw = [samples_ns[rng.randrange(count)] for _ in range(size)]
        draw.sort()
        medians.append(draw[size // 2])
    medians.sort()
    low_index = max(0, int((1.0 - confidence) / 2.0 * resamples))
    high_index = min(resamples - 1, int((1.0 + confidence) / 2.0 * resamples) - 1)
    return medians[low_index] / 1000.0, medians[high_index] / 1000.0


def summarize(samples_ns: list[int]) -> dict:
    ordered = sorted(samples_ns)
    total = sum(samples_ns)
    count = len(samples_ns)
    return {
        "samples": count,
        "mean_us": (total / count / 1000.0) if count else 0.0,
        "p50_us": percentile(ordered, 0.50) / 1000.0,
        "p95_us": percentile(ordered, 0.95) / 1000.0,
        "p99_us": percentile(ordered, 0.99) / 1000.0,
        "max_us": (ordered[-1] / 1000.0) if ordered else 0.0,
        "throughput_per_s": (count / (total / 1e9)) if total else 0.0,
    }


def measure_once(fn: Callable[[], T], iterations: int,
                 warmup: int = 1) -> tuple[list[int], T]:
    """Call `fn` `warmup` times untimed, then `iterations` times timed."""
    value: T | None = None
    for _ in range(max(0, warmup)):
        value = fn()
    samples: list[int] = []
    for _ in range(iterations):
        before = time.perf_counter_ns()
        value = fn()
        after = time.perf_counter_ns()
        samples.append(after - before)
    if value is None:
        raise ValueError("iterations and warmup were both zero")
    return samples, value


def sample_runs(fn: Callable[[], T], iterations: int, warmup: int,
                runs: int) -> list[list[int]]:
    """Return raw per-call nanosecond samples for each independent run.

    Keeping raw samples lets the caller bootstrap over run medians, which
    captures drift between runs instead of pretending every call is i.i.d.
    """
    if iterations < 1 or runs < 1:
        raise ValueError("iterations and runs must be positive")
    out: list[list[int]] = []
    for _ in range(runs):
        samples, _ = measure_once(fn, iterations, warmup)
        out.append(samples)
    return out


def summarize_with_ci(samples_ns: list[int], confidence: float = 0.95) -> dict:
    """Summarise one in-process run, with a within-run bootstrap CI."""
    if not samples_ns:
        return {}
    summary = summarize(samples_ns)
    low, high = bootstrap_ci(samples_ns, confidence)
    summary.update({"runs": 1, "ci_low_us": low, "ci_high_us": high})
    return summary


def summarize_runs(runs_ns: list[list[int]], confidence: float = 0.95) -> dict:
    """Summarise independent runs.

    ``p50_us`` is the median of the per-run medians; the confidence interval
    is a percentile bootstrap over those run medians.  Pooled statistics
    (p95/p99) describe the calls but their CIs are not reported because calls
    within a run are not independent.
    """
    if not runs_ns or not any(runs_ns):
        return {}
    medians = [statistics.median(run) for run in runs_ns if run]
    pooled = [sample for run in runs_ns for sample in run]
    summary = summarize(pooled)
    low, high = bootstrap_ci([int(value) for value in medians], confidence)
    summary.update({
        "runs": len(medians),
        "run_p50_us": [round(value / 1000.0, 3) for value in medians],
        "ci_low_us": low,
        "ci_high_us": high,
        "p50_us": statistics.median(medians) / 1000.0,
    })
    return summary


def measure(fn: Callable[[], T], iterations: int, warmup: int = 1,
            repetitions: int = 1) -> tuple[dict, T]:
    """Repeat a measurement and return median metrics plus the last value."""
    if iterations < 1:
        raise ValueError("iterations must be positive")
    if repetitions < 1:
        raise ValueError("repetitions must be positive")
    runs: list[dict] = []
    value: T | None = None
    for _ in range(repetitions):
        samples, value = measure_once(fn, iterations, warmup)
        runs.append(summarize(samples))
    assert value is not None
    keys = [key for key in runs[0] if key != "samples"]
    median = {key: statistics.median(run[key] for run in runs) for key in keys}
    median["samples"] = runs[0]["samples"]
    return {
        "iterations": iterations,
        "warmup": warmup,
        "repetitions": repetitions,
        "median": median,
        "runs": runs,
    }, value


def require_decision(label: str, expected: str, actual: str) -> None:
    """Fail loudly instead of reporting a timing for the wrong decision."""
    if actual != expected:
        raise SystemExit(
            f"decision mismatch for {label!r}: expected {expected}, got {actual}"
        )
