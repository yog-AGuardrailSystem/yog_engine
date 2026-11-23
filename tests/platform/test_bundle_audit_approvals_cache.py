"""Bundles, imports, the audit chain, approval tokens and the decision cache."""
import copy
import datetime as dt
import json

import pytest

from yog_platform import approvals, audit, bundle, cache, ed25519
from yog_platform.imports import ImportError_, expand_imports

SECRET = bytes(range(32))
PUBLIC = ed25519.public_key(SECRET)
KEYS = {"release-1": PUBLIC}
NOW = dt.datetime(2026, 11, 23, tzinfo=dt.timezone.utc)
FILES = {"main.yog": 'version 2\nimport "rules/a.yog"\nfact x(a)\n', "rules/a.yog": "fact y(b)\n"}


def make(files=FILES, **overrides):
    args = dict(policy_version=5, key_id="release-1", secret=SECRET, created="2026-11-01T00:00:00Z",
                not_after="2027-11-01T00:00:00Z")
    args.update(overrides)
    return bundle.build_bundle(files, **args)


# ------------------------------------------------------------------- bundles

def test_good_bundle_verifies_and_expands_imports():
    verified = bundle.verify_bundle(make(), KEYS, now=NOW)
    assert verified.policy_version == 5
    assert verified.policy_text == "version 2\nfact y(b)\nfact x(a)\n"
    assert len(verified.policy_hash) == 64
    assert verified.source_map[1] == ("rules/a.yog", 1)          # errors map back to the right file


def test_policy_hash_is_stable_and_changes_with_content():
    a = bundle.verify_bundle(make(), KEYS, now=NOW).policy_hash
    assert a == bundle.verify_bundle(make(), KEYS, now=NOW).policy_hash
    changed = make({"main.yog": "fact z(c)\n"})
    assert bundle.verify_bundle(changed, KEYS, now=NOW).policy_hash != a


@pytest.mark.parametrize("mutate,message", [
    (lambda d: d.update(format="other"), "unknown bundle format"),
    (lambda d: d["manifest"].update(policy_version=99), "signature does not verify"),
    (lambda d: d["manifest"].update(key_id="evil"), "unknown key"),
    (lambda d: d.update(signature="!!!"), "base64"),
    (lambda d: d.update(signature="A" * 86 + "=="), "does not verify"),
    (lambda d: d["files"].update({"main.yog": "fact evil(1)\n"}), "does not match its manifest hash"),
    (lambda d: d["files"].update({"extra.yog": "fact e(1)\n"}), "do not match the manifest"),
    (lambda d: d.pop("manifest"), "malformed"),
])
def test_tampered_bundles_are_rejected(mutate, message):
    doc = make()
    mutate(doc)
    with pytest.raises(bundle.BundleError, match=message):
        bundle.verify_bundle(doc, KEYS, now=NOW)


def test_wrong_key_expiry_downgrade_and_language_version():
    other = ed25519.public_key(bytes(reversed(range(32))))
    with pytest.raises(bundle.BundleError, match="does not verify"):
        bundle.verify_bundle(make(), {"release-1": other}, now=NOW)
    with pytest.raises(bundle.BundleError, match="expired"):
        bundle.verify_bundle(make(not_after="2026-01-01T00:00:00Z"), KEYS, now=NOW)
    with pytest.raises(bundle.BundleError, match="downgrade refused"):
        bundle.verify_bundle(make(policy_version=4), KEYS, now=NOW, min_policy_version=5)
    bundle.verify_bundle(make(policy_version=5), KEYS, now=NOW, min_policy_version=5)     # same is fine
    with pytest.raises(bundle.BundleError, match="language version 3"):
        bundle.verify_bundle(make(language_version=3), KEYS, now=NOW)
    with pytest.raises(bundle.BundleError, match="bad timestamp"):
        bundle.verify_bundle(make(not_after="tomorrow"), KEYS, now=NOW)
    with pytest.raises(bundle.BundleError, match="entry file"):
        make({"other.yog": "fact a(b)\n"})


# ------------------------------------------------------------------- imports

@pytest.mark.parametrize("files,message", [
    ({"main.yog": 'import "../outside.yog"\n'}, "leaves the policy directory"),
    ({"main.yog": 'import "/etc/passwd"\n'}, "bad import path"),
    ({"main.yog": 'import "a\\\\b.yog"\n'}, "bad import path"),
    ({"main.yog": 'import "missing.yog"\n'}, "not in the bundle"),
    ({"main.yog": 'import "a.yog"\n', "a.yog": 'import "main.yog"\n'}, "import cycle"),
])
def test_unsafe_imports_are_rejected(files, message):
    with pytest.raises(ImportError_, match=message):
        expand_imports(files, "main.yog")


def test_each_file_is_included_once():
    files = {"main.yog": 'import "a.yog"\nimport "b.yog"\n', "a.yog": 'import "c.yog"\nfact a(1)\n',
             "b.yog": 'import "c.yog"\nfact b(1)\n', "c.yog": "fact c(1)\n"}
    text, _ = expand_imports(files, "main.yog")
    assert text.count("fact c(1)") == 1


# --------------------------------------------------------------------- audit

def test_audit_chain_detects_every_kind_of_tampering(tmp_path):
    path = str(tmp_path / "audit.log")
    log = audit.AuditLog(path, clock=lambda: 1700000000)
    for i in range(4):
        log.append({"decision": "ALLOW", "request_hash": f"h{i}"})
    assert audit.verify(path) == (4, log.last_hash)
    lines = open(path, encoding="utf-8").read().splitlines()

    def broken(new_lines, match):
        bad = tmp_path / "bad.log"
        bad.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
        with pytest.raises(audit.AuditError, match=match):
            audit.verify(str(bad))

    edited = json.loads(lines[1]); edited["decision"] = "DENY"
    broken([lines[0], json.dumps(edited), *lines[2:]], "modified")
    broken([lines[0], *lines[2:]], "sequence")                  # deleted record
    broken([lines[1], lines[0], *lines[2:]], "sequence")        # reordered
    broken([lines[0], "not json"], "not valid JSON")
    # cutting the tail leaves a valid chain: it is only caught against a recorded anchor
    tail_cut = tmp_path / "cut.log"
    tail_cut.write_text("\n".join(lines[:3]) + "\n", encoding="utf-8")
    assert audit.verify(str(tail_cut))[0] == 3
    with pytest.raises(audit.AuditError, match="truncated"):
        audit.verify(str(tail_cut), expected_count=4)
    with pytest.raises(audit.AuditError, match="recorded hash"):
        audit.verify(str(tail_cut), expected_last_hash=log.last_hash)


def test_audit_log_resumes_and_refuses_a_damaged_log(tmp_path):
    path = str(tmp_path / "audit.log")
    first = audit.AuditLog(path)
    first.append({"n": 1})
    again = audit.AuditLog(path)
    assert again.append({"n": 2})["seq"] == 2
    assert audit.verify(path)[0] == 2
    text = open(path, encoding="utf-8").read().replace('"n": 1', '"n": 9')
    open(path, "w", encoding="utf-8").write(text)
    with pytest.raises(audit.AuditError):
        audit.AuditLog(path)


# ----------------------------------------------------------------- approvals

REQUEST = {"actor": "bot", "action": "run_tool", "resource": "deploy", "args": {"target": "prod"},
           "env": {"stage": "prod"}, "now": 100, "request_id": "r1"}


class Clock:
    def __init__(self): self.t = 1000.0
    def __call__(self): return self.t


def manager(**kw):
    clock = Clock()
    return approvals.ApprovalManager(b"s" * 32, ttl=60, clock=clock, **kw), clock


def test_approval_happy_path_is_single_use():
    m, _ = manager()
    a = m.create(REQUEST, "ph1")
    token = m.issue_token(a.approval_id, "alice")
    # now / request_id may change between attempts without invalidating the approval
    retry = dict(REQUEST, now=999, request_id="r2")
    assert m.consume(token, retry, "ph1") == "alice"
    with pytest.raises(approvals.ApprovalError, match="already used"):
        m.consume(token, retry, "ph1")


@pytest.mark.parametrize("change", [
    {"args": {"target": "prod", "force": True}}, {"resource": "other"}, {"actor": "evil"},
    {"action": "x"}, {"env": {"stage": "dev"}},
])
def test_approval_is_bound_to_the_exact_call(change):
    m, _ = manager()
    token = m.issue_token(m.create(REQUEST, "ph1").approval_id, "alice")
    with pytest.raises(approvals.ApprovalError, match="differs"):
        m.consume(token, dict(REQUEST, **change), "ph1")


def test_approval_expiry_policy_binding_and_forgery():
    m, clock = manager()
    a = m.create(REQUEST, "ph1")
    token = m.issue_token(a.approval_id, "alice")
    with pytest.raises(approvals.ApprovalError, match="policy changed"):
        m.consume(token, REQUEST, "ph2")
    clock.t += 61
    with pytest.raises(approvals.ApprovalError, match="expired"):
        m.consume(token, REQUEST, "ph1")

    m, _ = manager()
    a = m.create(REQUEST, "ph1")
    good = m.issue_token(a.approval_id, "alice")
    for bad in ("", "garbage", good[:-3] + "AAA"):
        with pytest.raises(approvals.ApprovalError):
            m.consume(bad, REQUEST, "ph1")
    # a token for a different approver name does not verify
    import base64
    payload = json.loads(base64.urlsafe_b64decode(good + "=" * (-len(good) % 4)))
    payload["approver"] = "mallory"
    forged = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    with pytest.raises(approvals.ApprovalError, match="does not verify"):
        m.consume(forged, REQUEST, "ph1")


def test_only_listed_approvers_can_approve():
    m, _ = manager(approvers=["alice"])
    a = m.create(REQUEST, "ph1")
    with pytest.raises(approvals.ApprovalError, match="not an authorised"):
        m.issue_token(a.approval_id, "mallory")
    m.issue_token(a.approval_id, "alice")
    with pytest.raises(approvals.ApprovalError, match="unknown"):
        m.issue_token("nope", "alice")
    with pytest.raises(ValueError):
        approvals.ApprovalManager(b"short")


# --------------------------------------------------------------------- cache

def test_cache_hits_only_for_identical_requests_and_policy():
    c = cache.DecisionCache(clock=Clock())
    result = {"decision": "ALLOW", "obligations": []}
    assert c.put(REQUEST, "ph1", result)
    assert c.get(dict(REQUEST, request_id="other"), "ph1") == result      # request_id is ignored
    assert c.get(REQUEST, "ph2") is None                                   # policy changed
    assert c.get(dict(REQUEST, args={"target": "x"}), "ph1") is None       # args changed
    stale = dict(REQUEST, state={"version": 2, "values": {}})
    c.put(stale, "ph1", result)
    assert c.get(dict(stale, state={"version": 3, "values": {}}), "ph1") is None   # state bump


def test_cache_never_stores_errors_approvals_or_traced_requests_and_expires():
    clock = Clock()
    c = cache.DecisionCache(ttl=10, clock=clock)
    assert not c.put(REQUEST, "p", {"error": {"message": "x"}})
    assert not c.put(REQUEST, "p", {"decision": "REQUIRE_APPROVAL"})
    assert not c.put(REQUEST, "p", {"decision": "ALLOW"}, traced=True)
    assert c.put(REQUEST, "p", {"decision": "DENY"})
    clock.t += 11
    assert c.get(REQUEST, "p") is None
    c.put(REQUEST, "p", {"decision": "DENY"})
    c.clear()
    assert c.get(REQUEST, "p") is None


def test_cache_returns_copies_and_is_bounded():
    c = cache.DecisionCache(max_entries=2, clock=Clock())
    c.put(REQUEST, "p", {"decision": "ALLOW", "obligations": [1]})
    got = c.get(REQUEST, "p")
    got["obligations"].append(2)
    assert c.get(REQUEST, "p")["obligations"] == [1]
    for i in range(5):
        c.put(dict(REQUEST, resource=f"r{i}"), "p", {"decision": "DENY"})
    assert len(c._items) == 2
