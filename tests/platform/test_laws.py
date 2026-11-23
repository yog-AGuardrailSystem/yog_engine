"""Algebraic laws of the decision core, checked over closed, generated spaces (reference interpreter).

These are the properties the spec promises (docs/SPEC.md, "Decision semantics"); the exhaustive C-versus-reference
comparison in yog/tests/differential/diff_small_models.py then ties the C engine to the same behaviour.
"""
import itertools
import random
import time

import pytest

from yog_platform.engine import EngineError
from yog_platform.format import format_source, same_meaning
from yog_platform.pdp import ReferencePDP

HEADER = "version 2\ninput flag(text)\ninput level(int)\nfact vip(u1)\n\n"
BODIES = [
    ["true == true"], ['flag("x")'], ['not flag("x")'], ["vip(U)"], ["not vip(U)"],
    ["level(N)", "N > 1"], ["level(N)", "N < 1"], ['flag("x")', "vip(U)"],
]
OBLIGATION = {"allow": "from_allow", "require_approval": "from_approval"}
RANK = {"DENY": 0, "REQUIRE_APPROVAL": 1, "ALLOW": 2}


def clause(kind, body, with_obligation=False):
    lines = [f"{kind} act(U, R):"] + ["    " + g for g in body]
    if with_obligation and kind in OBLIGATION:
        lines.append(f"    obligation {OBLIGATION[kind]}(R)")
    return "\n".join(lines) + "\n"


def requests():
    for actor, flag, level in itertools.product(("u1", "u2"), (None, "x", "y"), (None, 0, 1, 2)):
        request = {"actor": actor, "action": "act", "resource": "r1"}
        facts = []
        if flag is not None:
            facts.append({"predicate": "flag", "args": [flag]})
        if level is not None:
            facts.append({"predicate": "level", "args": [level]})
        if facts:
            request["facts"] = facts
        yield request


REQUESTS = list(requests())


def results(clauses):
    pdp = ReferencePDP(HEADER + "\n".join(clauses))
    return [pdp.check(r) for r in REQUESTS]


def random_clauses(rng, low=0, high=5):
    return [clause(rng.choice(["allow", "allow", "deny", "require_approval"]), rng.choice(BODIES), rng.random() < 0.6)
            for _ in range(rng.randint(low, high))]


def decisions(clauses):
    return [r["decision"] for r in results(clauses)]


@pytest.mark.parametrize("seed", range(60))
def test_evaluation_is_deterministic(seed):
    clauses = random_clauses(random.Random(seed))
    assert results(clauses) == results(clauses)


@pytest.mark.parametrize("seed", range(60))
def test_clause_order_never_changes_the_decision_or_the_obligation_set(seed):
    rng = random.Random(seed)
    clauses = random_clauses(rng, 2, 5)
    base = results(clauses)
    shuffled = clauses[:]
    rng.shuffle(shuffled)
    other = results(shuffled)
    for a, b in zip(base, other):
        assert a["decision"] == b["decision"]
        assert sorted(map(repr, a["obligations"])) == sorted(map(repr, b["obligations"]))


@pytest.mark.parametrize("seed", range(80))
def test_adding_a_deny_clause_never_makes_a_decision_more_permissive(seed):
    rng = random.Random(seed)
    clauses = random_clauses(rng)
    extra = clause("deny", rng.choice(BODIES))
    for before, after in zip(decisions(clauses), decisions(clauses + [extra])):
        assert RANK[after] <= RANK[before]
        if before == "DENY":
            assert after == "DENY"


@pytest.mark.parametrize("seed", range(80))
def test_adding_an_allow_clause_never_makes_a_decision_less_permissive(seed):
    rng = random.Random(seed)
    clauses = random_clauses(rng)
    extra = clause("allow", rng.choice(BODIES), rng.random() < 0.5)
    for before, after in zip(decisions(clauses), decisions(clauses + [extra])):
        assert RANK[after] >= RANK[before]


@pytest.mark.parametrize("seed", range(80))
def test_require_approval_never_beats_a_matching_deny_and_always_beats_allow(seed):
    rng = random.Random(seed)
    clauses = random_clauses(rng)
    extra = clause("require_approval", rng.choice(BODIES))
    for before, after in zip(results(clauses), results(clauses + [extra])):
        if before["reason"].startswith("deny clause at line"):                              # an explicit deny matched: it still wins
            assert after["decision"] == "DENY"
        if before["decision"] == "ALLOW":
            assert after["decision"] in ("ALLOW", "REQUIRE_APPROVAL")      # approval wins where the new clause holds
        if before["decision"] == "REQUIRE_APPROVAL":
            assert after["decision"] == "REQUIRE_APPROVAL"


@pytest.mark.parametrize("seed", range(80))
def test_obligations_come_only_from_clauses_of_the_winning_kind(seed):
    clauses = random_clauses(random.Random(seed))
    for result in results(clauses):
        names = {o["name"] for o in result["obligations"]}
        if result["decision"] == "DENY":
            assert names == set()
        elif result["decision"] == "ALLOW":
            assert names <= {"from_allow"}
        else:
            assert names <= {"from_approval"}
        assert len(result["obligations"]) == len({repr(o) for o in result["obligations"]})      # deduplicated


@pytest.mark.parametrize("seed", range(40))
def test_the_formatter_is_idempotent_and_keeps_the_meaning(seed):
    source = HEADER + "\n".join(random_clauses(random.Random(seed), 1, 5))
    once = format_source(source)
    assert format_source(once) == once
    assert same_meaning(source, once)
    assert decisions_of(source) == decisions_of(once)


def decisions_of(source):
    pdp = ReferencePDP(source)
    return [pdp.check(r)["decision"] for r in REQUESTS]


# ------------------------------------------------------------------ normalisation never misbehaves

ODD_PATHS = ["", "/", "//", "/a/b", "/a/../b", "/a/./b/", "..", "../..", "a//b", "/a/b/../../..", "\u00e9/\u4e2d", "/a b/c",
             "/" + "a/" * 200, "x" * 3000, "/a/b\\c", "C:\\a\\b", "%2e%2e/etc", "/a/b/\u202e/c", "~", "/a/\n/b"]


def test_path_normalisation_never_raises_and_never_escapes_the_base():
    pdp = ReferencePDP('version 2\ninput arg(text, any)\nallow act(U, R):\n    arg("p", P)\n    under(P, "/a/b")\n')
    for path in ODD_PATHS:
        result = pdp.check({"actor": "u", "action": "act", "resource": "r", "args": {"p": path}})
        assert "decision" in result or "error" in result, path
        if result.get("decision") == "ALLOW":
            parts, resolved = path.split("/"), []
            for part in parts:                                           # an independent resolution
                if part in ("", "."):
                    continue
                if part == "..":
                    if resolved:
                        resolved.pop()
                else:
                    resolved.append(part)
            assert path.startswith("/") and resolved[:2] == ["a", "b"], path


@pytest.mark.parametrize("seed", range(60))
def test_random_regular_expressions_compile_or_are_refused_and_always_finish_quickly(seed):
    rng = random.Random(seed)
    alphabet = list("ab()|*+?.[]^$\\{}") + ["(?i)", "a*", "(a|b)*", "[a-c]", "\\d"]
    pattern = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 14)))
    if '"' in pattern or "\n" in pattern:
        return
    source = f'version 2\ninput arg(text, any)\nallow act(U, R):\n    arg("t", T)\n    matches(T, "{pattern}")\n'
    try:
        pdp = ReferencePDP(source)
    except EngineError:
        return                                                          # refused at compile time: fine
    started = time.perf_counter()
    for text in ["", "a", "ab", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!", "b" * 200, "AbAb", "a" * 2000]:
        result = pdp.check({"actor": "u", "action": "act", "resource": "r", "args": {"t": text}})
        assert "decision" in result or "error" in result, (pattern, text)
    assert time.perf_counter() - started < 5, pattern


def test_the_classic_catastrophic_pattern_is_linear():
    pdp = ReferencePDP('version 2\ninput arg(text, any)\nallow act(U, R):\n    arg("t", T)\n    matches(T, "(a*)*b")\n')
    started = time.perf_counter()
    result = pdp.check({"actor": "u", "action": "act", "resource": "r", "args": {"t": "a" * 600 + "!"}})
    assert result.get("decision") == "DENY" or "error" in result
    assert time.perf_counter() - started < 5
