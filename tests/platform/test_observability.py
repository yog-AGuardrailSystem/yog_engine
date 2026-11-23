"""Decision logs (OPA shape), latency histogram and the OTLP exporter."""
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from test_sidecar_policy_faults import REQ, make_sidecar, post  # noqa: E402

from yog_platform.decision_log import DecisionLog, redact_values  # noqa: E402
from yog_platform.telemetry import Histogram, OtlpExporter, otlp_metrics_payload  # noqa: E402


def lines(path):
    return [json.loads(x) for x in Path(path).read_text(encoding="utf-8").splitlines() if x.strip()]


def test_decision_log_has_the_opa_shape_and_no_input_by_default(tmp_path):
    log = DecisionLog(str(tmp_path / "d.log"))
    car, _m, _a = make_sidecar(tmp_path, decision_log=log)
    post(car, REQ)
    post(car, dict(REQ, resource="nope"))
    first, second = lines(tmp_path / "d.log")
    assert set(first) >= {"decision_id", "timestamp", "path", "input_hash", "result", "bundles", "metrics", "labels"}
    assert first["path"] == "yog/run_tool" and first["result"]["decision"] == "ALLOW" and second["result"]["decision"] == "DENY"
    assert "input" not in first and "hunter2" not in (tmp_path / "d.log").read_text()
    assert first["decision_id"] != second["decision_id"] and first["metrics"]["timer_decision_ns"] >= 0
    assert first["bundles"]["policy"]["revision"] and first["labels"]["policy_version"] == 1


def test_input_logging_is_opt_in_and_redactable(tmp_path):
    raw = DecisionLog(str(tmp_path / "raw.log"), include_input=True)
    masked = DecisionLog(str(tmp_path / "masked.log"), include_input=True, redact=redact_values)
    for name, log in (("raw", raw), ("masked", masked)):
        car, _m, _a = make_sidecar(tmp_path, decision_log=log)
        post(car, REQ)
    assert lines(tmp_path / "raw.log")[0]["input"]["args"]["secret"] == "hunter2"
    text = (tmp_path / "masked.log").read_text()
    assert "hunter2" not in text and lines(tmp_path / "masked.log")[0]["input"]["args"]["secret"] == "<redacted>"
    assert lines(tmp_path / "masked.log")[0]["input"]["actor"] == "bot"


def test_a_broken_decision_log_does_not_change_the_decision(tmp_path):
    car, _m, _a = make_sidecar(tmp_path, decision_log=DecisionLog(str(tmp_path / "no" / "such" / "dir" / "d.log")))
    status, body = post(car, REQ)
    assert status == 200 and body["decision"] == "ALLOW"
    assert car.metrics.counts["decision_log_failures"] == 1


def test_histogram_buckets_and_prometheus_output(tmp_path):
    h = Histogram((0.001, 0.01))
    for v in (0.0005, 0.005, 0.5):
        h.observe(v)
    assert h.snapshot() == ([1, 1, 1], 3, 0.5055)
    text = h.prometheus("lat")
    assert 'lat_bucket{le="0.001"} 1' in text and 'lat_bucket{le="0.01"} 2' in text and 'lat_bucket{le="+Inf"} 3' in text
    assert "lat_count 3" in text
    car, _m, _a = make_sidecar(tmp_path)
    post(car, REQ)
    assert "yog_decision_seconds_count 1" in car.metrics_text()


def test_otlp_payload_shape():
    h = Histogram((0.001,))
    h.observe(0.0002)
    payload = otlp_metrics_payload({"decisions_allow": 3, "decisions_deny": 1, "requests": 4}, h, started_ns=1, now_ns=2, version="x")
    metrics = {m["name"]: m for m in payload["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]}
    points = metrics["yog.decisions"]["sum"]["dataPoints"]
    assert {(p["attributes"][0]["value"]["stringValue"], p["asInt"]) for p in points} == {("ALLOW", "3"), ("DENY", "1")}
    assert metrics["yog.events"]["sum"]["dataPoints"][0]["asInt"] == "4"
    hist = metrics["yog.decision.duration"]["histogram"]["dataPoints"][0]
    assert hist["count"] == "1" and hist["bucketCounts"] == ["1", "0"] and hist["explicitBounds"] == [0.001]
    json.dumps(payload)


def test_exporter_posts_to_a_collector_and_survives_failures(tmp_path):
    received = []

    class Collector(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append((self.path, json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *a):
            pass
    server = HTTPServer(("127.0.0.1", 0), Collector)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    car, _m, _a = make_sidecar(tmp_path)
    post(car, REQ)
    exporter = OtlpExporter(f"http://127.0.0.1:{server.server_address[1]}", car.metrics_snapshot)
    assert exporter.export_once() is True
    server.shutdown()
    path, body = received[0]
    assert path == "/v1/metrics" and body["resourceMetrics"]
    dead = OtlpExporter("http://127.0.0.1:9", car.metrics_snapshot, timeout=0.3)
    assert dead.export_once() is False and dead.failures == 1          # never raises
    assert post(car, REQ)[1]["decision"] == "ALLOW"
