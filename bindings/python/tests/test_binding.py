"""Behavioural tests for the Python ctypes binding.

These tests exercise the binding against the compiled shared library.  They are
skipped (not silently passed) when the library has not been built.
"""
from __future__ import annotations

import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import yog  # noqa: E402

pytestmark = pytest.mark.skipif(
    not Path(yog.library_path()).is_file(),
    reason="YOG shared library not built (cmake --target yog_shared)",
)

POLICY = """\
fact role(alice, admin)
fact member(bob, core)
fact team_resource(core, db)
fact clearance(alice, 5)
fact classification(db, 3)

allow can_access(User, Resource):
    role(User, admin)

allow can_access(User, Resource):
    member(User, Team)
    team_resource(Team, Resource)

allow can_access(User, Resource):
    clearance(User, Level)
    classification(Resource, Needed)
    Level >= Needed
"""


def test_allow_and_reason() -> None:
    policy = yog.Yog(POLICY)
    assert policy.check("alice", "can_access", "db") == yog.ALLOW
    assert policy.check("bob", "can_access", "db") == yog.ALLOW  # team join
    decision, reason = policy.evaluate("carol", "can_access", "db")
    assert decision == yog.DENY
    assert "no allow clause" in reason


def test_default_deny_for_unknown_subject() -> None:
    policy = yog.Yog(POLICY)
    assert policy.check("nobody", "can_access", "db") == yog.DENY


def test_compile_error_reports_position() -> None:
    with pytest.raises(yog.YogCompileError) as caught:
        yog.Yog("allow broken(:\n")
    assert caught.value.line > 0
    assert caught.value.message


def test_context_facts_are_isolated_between_checks() -> None:
    policy = yog.Yog(
        "fact role(carol, guest)\n"
        "allow can_access(User, Resource):\n"
        "    role(User, admin)\n"
    )
    context = "fact role(carol, admin)"
    assert policy.check("carol", "can_access", "db", context) == yog.ALLOW
    # The fact must not leak into the next request.
    assert policy.check("carol", "can_access", "db") == yog.DENY


def test_limits_round_trip_and_are_enforced() -> None:
    policy = yog.Yog(POLICY)
    policy.limits = (1000000, 8)
    assert policy.limits == (1000000, 8)
    policy.limits = (1, 8)
    with pytest.raises(yog.YogEvaluationError):
        policy.check("carol", "can_access", "db")


def test_resource_limits_round_trip_and_keep_unset_fields() -> None:
    policy = yog.Yog(POLICY)
    defaults = policy.resource_limits
    assert defaults["max_solutions"] == 100000
    assert defaults["max_millis"] == 10000
    assert defaults["max_memory"] == 64 * 1024 * 1024
    policy.resource_limits = {"max_memory": 1}
    assert policy.resource_limits["max_memory"] == 1
    assert policy.resource_limits["max_steps"] == defaults["max_steps"]
    with pytest.raises(yog.YogEvaluationError):
        policy.check("bob", "can_access", "db")
    # Setting the old (steps, depth) pair must not reset the other budgets.
    policy.limits = (1000000, 8)
    assert policy.resource_limits["max_memory"] == 1
    policy.resource_limits = {"max_memory": 0}
    assert policy.resource_limits["max_memory"] == defaults["max_memory"]
    with pytest.raises(ValueError):
        policy.resource_limits = {"max_bananas": 1}


def test_shared_policy_is_thread_safe() -> None:
    policy = yog.Yog(POLICY)
    requests = [("alice", "db")] * 200 + [("bob", "db")] * 200 + [("nobody", "db")] * 200

    def decide(request):
        return policy.check(request[0], "can_access", request[1])

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(decide, requests))

    assert results.count(yog.ALLOW) == 400
    assert results.count(yog.DENY) == 200


def test_closed_policy_cannot_be_checked() -> None:
    policy = yog.Yog(POLICY)
    policy.close()
    with pytest.raises(ValueError):
        policy.check("alice", "can_access", "db")


def test_library_version_matches_package_version() -> None:
    # The wheel uses the PEP 440 spelling (0.2.0a1); the C library reports the
    # SemVer spelling (0.2.0-alpha.1).  Both must describe the same release.
    assert yog.library_version() == "0.2.0-alpha.1"
    assert yog.__version__ == "0.2.0a1"


V2_POLICY = """version 2
input arg(text, any)
input env(text, any)
input now(int)
deny act(U, R):
    arg("sql", Q)
    matches(Q, "(?i)drop table")
require_approval act(U, R):
    env("stage", "prod")
    obligation audit("prod", R)
allow act(U, R):
    arg("n", N)
    N > 3
    obligation audit("allowed", R)
    obligation limit(U, N, true)
"""


def test_decide_returns_obligations_with_types() -> None:
    policy = yog.Yog(V2_POLICY)
    assert policy.policy_version == 2
    outcome = policy.check_json({"actor": "bot", "action": "act", "resource": "db", "args": {"n": 7}})
    assert outcome.decision == yog.ALLOW and outcome.allowed
    assert outcome.matched_line > 0
    assert outcome.obligations == (
        yog.Obligation("audit", ("allowed", "db")),
        yog.Obligation("limit", ("bot", 7, True)),
    )


def test_require_approval_and_deny_outcomes() -> None:
    policy = yog.Yog(V2_POLICY)
    base = {"actor": "bot", "action": "act", "resource": "db"}
    approval = policy.check_json({**base, "env": {"stage": "prod"}})
    assert approval.decision == yog.REQUIRE_APPROVAL and not approval.allowed
    assert approval.obligations == (yog.Obligation("audit", ("prod", "db")),)
    denied = policy.check_json({**base, "args": {"sql": "Please DROP TABLE x", "n": 9}})
    assert denied.decision == yog.DENY and denied.obligations == ()
    assert policy.check("bot", "act", "db") == yog.DENY      # no facts: default deny


def test_check_json_rejects_malformed_and_forged_requests() -> None:
    policy = yog.Yog(V2_POLICY)
    for bad in ("not json", {"actor": "bot"}, {"actor": "a", "action": "act", "resource": "r", "bogus": 1},
                {"actor": "a", "action": "act", "resource": "r", "args": {"x": 1.5}}):
        with pytest.raises(yog.YogEvaluationError):
            policy.check_json(bad)
    # request values are data: a value that looks like policy text cannot forge a fact
    forged = policy.check_json({"actor": "a", "action": "act", "resource": "r",
                                "args": {"sql": 'x"); fact env("stage", "prod'}})
    assert forged.decision == yog.DENY


def test_typed_context_is_enforced_on_the_text_path() -> None:
    policy = yog.Yog(V2_POLICY)
    with pytest.raises(yog.YogEvaluationError):
        policy.decide("bot", "act", "db", 'fact now("later")')


def test_trace_is_returned_on_request() -> None:
    policy = yog.Yog(V2_POLICY)
    outcome = policy.check_json({"actor": "bot", "action": "act", "resource": "db", "args": {"n": 7}}, trace=True)
    assert outcome.trace and "allow" in outcome.trace.lower()
