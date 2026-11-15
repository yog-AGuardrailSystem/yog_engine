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

import statistics
import time
from typing import Callable, TypeVar

T = TypeVar("T")


def percentile(sorted_samples: list[float], fraction: float) -> float:
    if not sorted_samples:
        return 0.0
    index = min(len(sorted_samples) - 1, int(fraction * len(sorted_samples)))
    return sorted_samples[index]


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
