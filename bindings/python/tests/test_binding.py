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
