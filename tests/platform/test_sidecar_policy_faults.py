"""Engine process handling, policy loading, the sidecar, registry sync and fault injection.

Everything here uses a scripted fake `yogc` (tests/platform/fake_yogc.py) or an in-memory fake engine, so
the tests exercise the platform logic itself and run anywhere.  Integration with the real yogc is in
test_real_engine.py.
"""
import json
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from yog_platform import audit as audit_mod
from yog_platform import bundle, cache, ed25519, policy, sidecar
from yog_platform.engine import EngineError, YogcEngine

HERE = Path(__file__).parent
FAKE = [sys.executable, str(HERE / "fake_yogc.py")]
SECRET = bytes(range(32))
KEYS = {"k1": ed25519.public_key(SECRET)}
NOT_AFTER = "2099-01-01T00:00:00Z"


def doc(version=1, text="fact a(b)\n", self_tests=None, **kw):
    return bundle.build_bundle({"main.yog": text}, policy_version=version, key_id="k1", secret=SECRET,
                               created="2026-01-01T00:00:00Z", not_after=kw.pop("not_after", NOT_AFTER),
                               self_tests=self_tests, **kw)


# ------------------------------------------------------------ a fake in-memory engine

class FakeEngine:
    instances = []

    def __init__(self, text):
        self.text, self.closed, self.calls = text, False, 0
        self.fail = None
        FakeEngine.instances.append(self)

    def check(self, request):
        self.calls += 1
        if self.fail:
            raise self.fail
        if (request.get("args") or {}).get("bad"):
            return {"error": {"message": "bad request", "line": 0, "column": 0}}
        resource = request.get("resource", "")
        decision = "ALLOW" if resource.startswith("ok") else ("REQUIRE_APPROVAL" if resource == "deploy" else "DENY")
        return {"decision": decision, "reason": "fake", "matched_line": 1, "policy_version": 2,
                "obligations": [{"name": "audit", "args": [resource]}] if decision == "ALLOW" else []}

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def _reset_fakes():
    FakeEngine.instances.clear()


def make_manager(**kw):
    return policy.PolicyManager(FakeEngine, KEYS, **kw)


def make_sidecar(tmp_path, **kw):
    manager = make_manager()
    manager.load_bundle(doc(1))
    log = audit_mod.AuditLog(str(tmp_path / "audit.log"))
    car = sidecar.Sidecar(manager, audit=log, cache=cache.DecisionCache(), trusted_bundle_dir=str(tmp_path), **kw)
    return car, manager, log


def post(car, request):
    body = request if isinstance(request, bytes) else json.dumps(request).encode()
    return car.handle_check(body)


REQ = {"actor": "bot", "action": "run_tool", "resource": "ok_tool", "args": {"secret": "hunter2"}}


# --------------------------------------------------------------------- YogcEngine

def test_engine_round_trip_and_request_errors():
    engine = YogcEngine(FAKE + ["ok"], "policy.yog")
    try:
        assert engine.check(REQ)["decision"] == "ALLOW"
        assert engine.check(dict(REQ, resource="deploy"))["decision"] == "REQUIRE_APPROVAL"
        assert "error" in engine.check(dict(REQ, args={"bad": 1}))      # a request error is not a crash
        assert engine.check(REQ)["decision"] == "ALLOW"                  # and the process is still usable
    finally:
        engine.close()
    with pytest.raises(EngineError, match="closed"):
        engine.check(REQ)


def test_engine_refuses_a_policy_that_does_not_compile():
    with pytest.raises(EngineError, match="does not compile"):
        YogcEngine(FAKE + ["bad_compile"], "policy.yog")


def test_engine_crash_raises_and_recovers_on_the_next_call():
    engine = YogcEngine(FAKE + ["crash_after_one"], "policy.yog", timeout=3)
    try:
        assert engine.check(REQ)["decision"] == "ALLOW"
        with pytest.raises(EngineError):
            engine.check(REQ)                                            # the process died mid-request
        assert engine.check(REQ)["decision"] == "ALLOW"                  # a fresh process answers
    finally:
        engine.close()


def test_engine_hang_times_out_and_never_returns_an_answer():
    engine = YogcEngine(FAKE + ["hang"], "policy.yog", timeout=0.5)
    try:
        with pytest.raises(EngineError, match="did not answer"):
            engine.check(REQ)
    finally:
        engine.close()


def test_engine_garbage_output_is_an_error():
    engine = YogcEngine(FAKE + ["garbage"], "policy.yog", timeout=3)
    try:
        with pytest.raises(EngineError, match="malformed"):
            engine.check(REQ)
    finally:
        engine.close()


# ------------------------------------------------------------------ PolicyManager

def test_manager_loads_swaps_and_closes_the_old_engine():
    manager = make_manager()
    first = manager.load_bundle(doc(1, "fact a(1)\n"))
    second = manager.load_bundle(doc(2, "fact a(2)\n"))
    assert manager.current is second and first.policy_hash != second.policy_hash
    assert first.engine.closed and not second.engine.closed


@pytest.mark.parametrize("bad,message", [
    (lambda: dict(doc(2), signature="A" * 86 + "=="), "does not verify"),
    (lambda: doc(2, not_after="2020-01-01T00:00:00Z"), "expired"),
    (lambda: doc(1), "downgrade"),                 # same-or-older than the policy in force is not newer... see below
])
def test_manager_refuses_bad_bundles_and_keeps_the_old_policy(bad, message):
    manager = make_manager()
    good = manager.load_bundle(doc(5))
    candidate = bad()
    if message == "downgrade":
        candidate = doc(4)
    with pytest.raises(policy.PolicyError, match=message):
        manager.load_bundle(candidate)
    assert manager.current is good and not good.engine.closed
    assert manager.last_error


def test_manager_runs_self_tests_before_swapping():
    manager = make_manager()
    good = manager.load_bundle(doc(1))
    tests = [{"request": {"actor": "a", "action": "x", "resource": "ok1"}, "expect": "ALLOW"}]
    passing = manager.load_bundle(doc(2, self_tests=tests))
    assert manager.current is passing
    failing = [{"request": {"actor": "a", "action": "x", "resource": "nope"}, "expect": "ALLOW"}]
    with pytest.raises(policy.PolicyError, match="self-test 1 failed"):
        manager.load_bundle(doc(3, self_tests=failing))
    assert manager.current is passing
    assert FakeEngine.instances[-1].closed                       # the staged engine is released
    assert not good.engine.closed or good is not manager.current


def test_manager_rolls_back_when_the_engine_cannot_start():
    def factory(text):
        raise EngineError("does not compile")
    manager = policy.PolicyManager(factory, KEYS)
    with pytest.raises(policy.PolicyError, match="does not compile"):
        manager.load_bundle(doc(1))
    assert manager.current is None


# ------------------------------------------------------------------------ sidecar

def test_check_allow_deny_and_audit_has_no_raw_arguments(tmp_path):
    car, manager, log = make_sidecar(tmp_path)
    status, body = post(car, dict(REQ, request_id="r-1"))
    assert status == 200 and body["decision"] == "ALLOW" and body["request_id"] == "r-1"
    assert body["policy_hash"] == manager.current.policy_hash and body["cached"] is False
    assert post(car, dict(REQ, resource="nope"))[1]["decision"] == "DENY"
    lines = Path(log.path).read_text().splitlines()
    assert len(lines) == 2 and audit_mod.verify(log.path)[0] == 2
    assert "hunter2" not in Path(log.path).read_text()           # hashes only, never the arguments
    record = json.loads(lines[0])
    assert record["decision"] == "ALLOW" and len(record["request_hash"]) == 64


@pytest.mark.parametrize("raw,status", [
    (b"not json", 400), (b"[1,2]", 400), (b"\xff\xfe", 400), (b"x" * ((1 << 20) + 1), 413),
])
def test_malformed_requests_get_a_deny_shaped_reply(tmp_path, raw, status):
    car, _, _ = make_sidecar(tmp_path)
    got, body = car.handle_check(raw)
    assert got == status and body["decision"] == "DENY" and "error" in body


def test_request_level_errors_are_denies(tmp_path):
    car, _, log = make_sidecar(tmp_path)
    status, body = post(car, dict(REQ, args={"bad": 1}))
    assert status == 400 and body["decision"] == "DENY" and body["error"]["message"] == "bad request"
    assert json.loads(Path(log.path).read_text().splitlines()[0])["error"] is True


def test_no_policy_loaded_is_a_deny(tmp_path):
    car = sidecar.Sidecar(make_manager())
    status, body = post(car, REQ)
    assert status == 503 and body["decision"] == "DENY"
    assert car.policy_info()[0] == 503


@pytest.mark.parametrize("exc,status", [(EngineError("boom"), 503), (RuntimeError("bug"), 500)])
def test_engine_faults_never_become_an_allow(tmp_path, exc, status):
    car, manager, _ = make_sidecar(tmp_path)
    manager.current.engine.fail = exc
    got, body = post(car, REQ)
    assert got == status and body["decision"] == "DENY" and "error" in body
    manager.current.engine.fail = None
    assert post(car, REQ)[1]["decision"] == "ALLOW"               # and it recovers


def test_unwritable_audit_log_denies(tmp_path):
    car, _, log = make_sidecar(tmp_path)
    log.path = str(tmp_path / "missing-dir" / "audit.log")
    status, body = post(car, REQ)
    assert status == 503 and body["decision"] == "DENY" and "audit" in body["reason"]


def test_cache_hits_then_clears_on_reload(tmp_path):
    car, manager, _ = make_sidecar(tmp_path)
    engine = manager.current.engine
    assert post(car, REQ)[1]["cached"] is False
    assert post(car, REQ)[1]["cached"] is True and engine.calls == 1
    status, info = car.reload(json.dumps({"bundle": doc(2)}).encode())
    assert status == 200 and info["policy_version"] == 2
    again = post(car, REQ)[1]
    assert again["cached"] is False and again["policy_hash"] == info["policy_hash"]    # never a stale answer
    assert post(car, dict(REQ, resource="deploy"))[1]["decision"] == "REQUIRE_APPROVAL"
    assert post(car, dict(REQ, resource="deploy"))[1]["cached"] is False                # approvals are not cached


def test_reload_failures_keep_the_current_policy(tmp_path):
    car, manager, _ = make_sidecar(tmp_path)
    before = manager.current.policy_hash
    tampered = doc(9)
    tampered["files"]["main.yog"] = "fact evil(1)\n"
    # version 0 is older than the version in force (1), so it is refused as a downgrade
    for payload in ({"bundle": tampered}, {"bundle": doc(0)}, {"bundle": 5}, {"nope": 1}):
        status, body = car.reload(json.dumps(payload).encode())
        assert status in (400, 422) and "error" in body
    assert manager.current.policy_hash == before
    assert post(car, REQ)[1]["decision"] == "ALLOW"


def test_reload_by_path_is_confined_to_the_bundle_directory(tmp_path):
    car, manager, _ = make_sidecar(tmp_path)
    (tmp_path / "next.json").write_text(json.dumps(doc(3)))
    assert car.reload(json.dumps({"bundle": "next.json"}).encode())[0] == 200
    outside = tmp_path.parent / "outside.json"
    outside.write_text(json.dumps(doc(4)))
    status, body = car.reload(json.dumps({"bundle": "../outside.json"}).encode())
    assert status == 400 and "outside" in body["error"]["message"]
    assert manager.current.policy_version == 3


def test_metrics_and_policy_info(tmp_path):
    car, manager, _ = make_sidecar(tmp_path)
    post(car, REQ)
    post(car, b"junk")
    text = car.metrics_text()
    assert "yog_requests_total 2" in text and "yog_policy_loaded 1" in text and "yog_decisions_allow_total 1" in text
    status, info = car.policy_info()
    assert status == 200 and info["policy_hash"] == manager.current.policy_hash


# ------------------------------------------------------------------- over HTTP

def test_http_endpoints_end_to_end(tmp_path):
    car, manager, _ = make_sidecar(tmp_path)
    server = sidecar.make_server(car)
    sidecar.run_in_thread(server)
    base = f"http://127.0.0.1:{server.server_address[1]}"

    def call(path, data=None, headers=None):
        req = urllib.request.Request(base + path, data=data, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    try:
        status, text = call("/v1/check", json.dumps(REQ).encode(), {"Content-Type": "application/json"})
        assert status == 200 and json.loads(text)["decision"] == "ALLOW"
        assert call("/healthz")[0] == 200
        assert json.loads(call("/v1/policy")[1])["policy_version"] == 1
        assert "yog_requests_total" in call("/metrics")[1]
        assert call("/nope")[0] == 404
        status, text = call("/v1/check", b"{bad")
        assert status == 400 and json.loads(text)["decision"] == "DENY"
        # a lying Content-Length larger than the limit is refused without reading the body
        status, text = call("/v1/check", b"{}", {"Content-Length": str((1 << 20) + 5)})
        assert status in (400, 413) or status == 0
    finally:
        server.shutdown()
        server.server_close()


def test_concurrent_checks_and_reloads_are_safe(tmp_path):
    car, manager, _ = make_sidecar(tmp_path)
    errors, stop = [], threading.Event()

    def worker():
        while not stop.is_set():
            status, body = post(car, REQ)
            if body["decision"] != "ALLOW" or status != 200:
                errors.append((status, body))

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for version in range(2, 12):
        assert car.reload(json.dumps({"bundle": doc(version)}).encode())[0] == 200
    stop.set()
    for t in threads:
        t.join()
    assert not errors, errors[:3]


# -------------------------------------------------- registry sync (distribution)

def publish(root: Path, version, **kw):
    bundles = root / "bundles"
    bundles.mkdir(exist_ok=True)
    (bundles / f"{version}.json").write_text(json.dumps(doc(version, **kw)))
    (root / "index.json").write_text(json.dumps(
        {"channels": {"stable": {"bundle": f"bundles/{version}.json", "policy_version": version}}}))


def test_syncer_loads_newer_bundles_and_ignores_unchanged_ones(tmp_path):
    manager = make_manager()
    syncer = policy.Syncer(manager, str(tmp_path))
    publish(tmp_path, 1)
    assert syncer.sync_once().policy_version == 1
    assert syncer.sync_once() is None                              # nothing new
    publish(tmp_path, 2)
    assert syncer.sync_once().policy_version == 2 and manager.current.policy_version == 2
    assert not syncer.errors


def test_syncer_keeps_serving_when_the_registry_is_down_or_corrupt(tmp_path):
    manager = make_manager()
    syncer = policy.Syncer(manager, str(tmp_path))
    publish(tmp_path, 1)
    syncer.sync_once()
    good = manager.current
    (tmp_path / "index.json").unlink()                               # a partition: the registry is unreachable
    assert syncer.sync_once() is None and manager.current is good
    (tmp_path / "index.json").write_text("{corrupt")
    assert syncer.sync_once() is None and manager.current is good
    publish(tmp_path, 2)
    tampered = json.loads((tmp_path / "bundles" / "2.json").read_text())
    tampered["files"]["main.yog"] = "fact evil(1)\n"
    (tmp_path / "bundles" / "2.json").write_text(json.dumps(tampered))
    assert syncer.sync_once() is None and manager.current is good     # a corrupt/tampered bundle is refused
    assert len(syncer.errors) == 3
    publish(tmp_path, 3)                                             # and recovery works once it is fixed
    assert syncer.sync_once().policy_version == 3


def test_syncer_refuses_a_rollback_to_an_older_policy(tmp_path):
    manager = make_manager()
    syncer = policy.Syncer(manager, str(tmp_path))
    publish(tmp_path, 5)
    syncer.sync_once()
    publish(tmp_path, 4)                                             # an attacker re-publishes an old bundle
    assert syncer.sync_once() is None and manager.current.policy_version == 5
    (tmp_path / "index.json").write_text(json.dumps(
        {"channels": {"stable": {"bundle": "bundles/4.json", "policy_version": 99}}}))   # lying index
    assert syncer.sync_once() is None and manager.current.policy_version == 5
    assert any("downgrade" in e for e in syncer.errors)


def test_stale_policy_is_reported_by_the_audit_trail(tmp_path):
    """Every decision records the policy hash that made it, so a stale replica is visible."""
    car, manager, log = make_sidecar(tmp_path)
    post(car, REQ)
    old_hash = manager.current.policy_hash
    car.reload(json.dumps({"bundle": doc(2)}).encode())
    post(car, REQ)
    records = [json.loads(line) for line in Path(log.path).read_text().splitlines()]
    assert records[0]["policy_hash"] == old_hash and records[1]["policy_hash"] == manager.current.policy_hash
    assert records[0]["policy_hash"] != records[1]["policy_hash"]
