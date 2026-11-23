"""Latency histogram and an OpenTelemetry (OTLP/HTTP JSON) metrics exporter, with no third-party dependency.

The exporter is off unless an endpoint is configured.  Exporting is best effort: any failure (collector down,
slow, or answering with an error) is swallowed and counted, and can never delay or change a decision, because
export runs on its own thread and the decision path only does a locked counter update.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.request
from typing import Callable, Optional

# seconds: 100 microseconds to 10 seconds
DEFAULT_BUCKETS = (0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 10.0)


class Histogram:
    def __init__(self, bounds=DEFAULT_BUCKETS):
        self.bounds = tuple(bounds)
        self._lock = threading.Lock()
        self.buckets = [0] * (len(self.bounds) + 1)           # the last bucket is "+Inf"
        self.count = 0
        self.total = 0.0

    def observe(self, seconds: float) -> None:
        index = len(self.bounds)
        for i, bound in enumerate(self.bounds):
            if seconds <= bound:
                index = i
                break
        with self._lock:
            self.buckets[index] += 1
            self.count += 1
            self.total += seconds

    def snapshot(self) -> tuple:
        with self._lock:
            return list(self.buckets), self.count, self.total

    def prometheus(self, name: str) -> str:
        buckets, count, total = self.snapshot()
        lines, running = [], 0
        for bound, n in zip(self.bounds, buckets):
            running += n
            lines.append(f'{name}_bucket{{le="{bound}"}} {running}')
        lines.append(f'{name}_bucket{{le="+Inf"}} {count}')
        lines.append(f"{name}_sum {total:.9f}")
        lines.append(f"{name}_count {count}")
        return "\n".join(lines)


def _attr(key: str, value) -> dict:
    return {"key": key, "value": {"stringValue": str(value)}}


def otlp_metrics_payload(counts: dict, histogram: Histogram, *, service: str = "yog-sidecar", version: str = "",
                         started_ns: int, now_ns: Optional[int] = None) -> dict:
    """An OTLP/HTTP JSON ``ExportMetricsServiceRequest``: one cumulative counter per decision outcome (plus the
    other counters) and one histogram of decision latency."""
    now_ns = now_ns if now_ns is not None else time.time_ns()
    points = []
    for name, value in sorted(counts.items()):
        if name.startswith("decisions_"):
            points.append({"attributes": [_attr("decision", name[len("decisions_"):].upper())], "startTimeUnixNano": str(started_ns),
                           "timeUnixNano": str(now_ns), "asInt": str(value)})
    metrics = [{"name": "yog.decisions", "description": "Decisions by outcome", "unit": "{decision}",
                "sum": {"dataPoints": points, "aggregationTemporality": 2, "isMonotonic": True}}]
    others = [(n, v) for n, v in sorted(counts.items()) if not n.startswith("decisions_")]
    metrics.append({"name": "yog.events", "description": "Sidecar events (requests, cache hits, errors, ...)", "unit": "{event}",
                    "sum": {"dataPoints": [{"attributes": [_attr("event", n)], "startTimeUnixNano": str(started_ns),
                                            "timeUnixNano": str(now_ns), "asInt": str(v)} for n, v in others],
                            "aggregationTemporality": 2, "isMonotonic": True}})
    buckets, count, total = histogram.snapshot()
    metrics.append({"name": "yog.decision.duration", "description": "Time to decide one request", "unit": "s",
                    "histogram": {"dataPoints": [{"startTimeUnixNano": str(started_ns), "timeUnixNano": str(now_ns),
                                                  "count": str(count), "sum": total,
                                                  "bucketCounts": [str(b) for b in buckets],
                                                  "explicitBounds": list(histogram.bounds)}],
                                  "aggregationTemporality": 2}})
    return {"resourceMetrics": [{"resource": {"attributes": [_attr("service.name", service), _attr("service.version", version)]},
                                 "scopeMetrics": [{"scope": {"name": "yog_platform"}, "metrics": metrics}]}]}


class OtlpExporter:
    """Posts metrics to ``<endpoint>/v1/metrics`` every ``interval`` seconds on a background thread."""

    def __init__(self, endpoint: str, snapshot: Callable[[], tuple], *, interval: float = 30.0, timeout: float = 2.0,
                 service: str = "yog-sidecar", version: str = ""):
        self._url = endpoint.rstrip("/") + "/v1/metrics"
        self._snapshot = snapshot                          # () -> (counts dict, Histogram)
        self._interval, self._timeout = interval, timeout
        self._service, self._version = service, version
        self._started_ns = time.time_ns()
        self._stop = threading.Event()
        self.failures = 0
        self.exports = 0

    def export_once(self) -> bool:
        try:
            counts, histogram = self._snapshot()
            body = json.dumps(otlp_metrics_payload(counts, histogram, service=self._service, version=self._version,
                                                   started_ns=self._started_ns)).encode()
            request = urllib.request.Request(self._url, data=body, headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                response.read()
            self.exports += 1
            return True
        except Exception:                                  # best effort: never raise into the caller
            self.failures += 1
            return False

    def start(self) -> threading.Thread:
        def loop():
            while not self._stop.wait(self._interval):
                self.export_once()
        thread = threading.Thread(target=loop, daemon=True, name="yog-otlp")
        thread.start()
        return thread

    def stop(self) -> None:
        self._stop.set()
