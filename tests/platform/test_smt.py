"""Symbolic comparison (needs z3-solver; skipped without it) and its agreement with the bounded search."""
import pytest

z3 = pytest.importorskip("z3")

from yog_platform.compare import compare_policies  # noqa: E402
from yog_platform.smt import Unsupported, compare_smt  # noqa: E402

OLD = """version 2
input arg(text, any)
input env(text, any)
fact role(alice, admin)
fact role(bob, reader)
deny act(U, R):
    arg("sql", Q)
    contains(Q, "drop")
allow act(U, R):
    role(U, admin)
allow act(U, R):
    role(U, reader)
    arg("n", N)
    N < 5
"""
WIDER = OLD + 'allow act(U, R):\n    role(U, reader)\n    arg("n", N)\n    N < 9\n'
NARROWER = OLD + "deny act(U, R):\n    role(U, reader)\n"
APPROVAL = OLD.replace("allow act(U, R):\n    role(U, admin)", "require_approval act(U, R):\n    role(U, admin)")
NOT_EDGE = OLD.replace("contains(Q, \"drop\")", "starts_with(Q, \"drop\")")

CORPUS = [(OLD, OLD), (OLD, WIDER), (OLD, NARROWER), (OLD, APPROVAL), (OLD, NOT_EDGE), (WIDER, OLD)]


def test_identical_policies_are_proved_not_wider():
    assert compare_smt(OLD, OLD)["verdict"] == "yes"


def test_a_wider_policy_gets_a_replayed_counterexample():
    result = compare_smt(OLD, WIDER)
    assert result["verdict"] == "no"
    request = result["counterexample"]
    assert request["actor"] == "bob" and 5 <= request["args"]["n"] < 9


def test_narrowing_is_proved_safe():
    assert compare_smt(OLD, NARROWER)["verdict"] == "yes"


@pytest.mark.parametrize("old,new", CORPUS)
def test_symbolic_and_bounded_answers_agree(old, new):
    symbolic = compare_smt(old, new)["verdict"]
    bounded = compare_policies(old, new)
    assert symbolic in ("yes", "no")
    assert (symbolic == "no") == (bounded["new_permits_more_count"] > 0)


def test_unsupported_constructs_are_refused_not_guessed():
    rule = "version 2\nfact foo(a)\nrule reachable(X):\n    foo(X)\nallow act(U, R):\n    reachable(U)\n"
    with pytest.raises(Unsupported):
        compare_smt(rule, rule)
    regex = 'version 2\ninput arg(text, any)\nallow act(U, R):\n    arg("p", P)\n    matches(P, "a+")\n'
    with pytest.raises(Unsupported):
        compare_smt(regex, regex)
