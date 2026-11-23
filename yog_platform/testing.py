"""Policy tests (`.yogtest` files), clause coverage and decision diffs.

A ``.yogtest`` file is JSON::

    {"policy": "relative/or/absolute/policy.yog",
     "tests": [{"name": "drop is denied",
                "request": {"actor": "a", "action": "run_tool", "resource": "sql_exec", "args": {...}},
                "expect": {"decision": "DENY", "reason_contains": "deny clause", "obligations": ["audit"]}}]}

``expect.decision`` is required; ``reason_contains`` and ``obligations`` (names, in order) are optional.
Coverage reports decision clauses that no test made the deciding clause.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class TestResult:
    name: str
    passed: bool
    message: str = ""


@dataclass
class Report:
    results: list = field(default_factory=list)
    uncovered: list = field(default_factory=list)       # [(line, kind)]

    @property
    def passed(self) -> bool:
        return all(r.passed for r in self.results)


def _decision_clauses(source: str):
    from .analysis import _ref
    ref = _ref()
    program = ref.Parser(ref.tokenize(source)).parse()
    return [(c.line, c.kind) for c in program.clauses if c.kind != "rule"]


def run_tests(test_file: str, engine_factory: Callable[[str], object]) -> Report:
    with open(test_file, encoding="utf-8") as handle:
        spec = json.load(handle)
    policy_path = spec["policy"]
    if not os.path.isabs(policy_path):
        policy_path = os.path.join(os.path.dirname(os.path.abspath(test_file)), policy_path)
    with open(policy_path, encoding="utf-8") as handle:
        source = handle.read()
    engine = engine_factory(source)
    report, hit = Report(), set()
    try:
        for number, test in enumerate(spec["tests"], 1):
            name = test.get("name", f"test {number}")
            expect = test["expect"]
            result = engine.check(test["request"])
            problems = []
            got = result.get("decision", "ERROR" if "error" in result else None)
            if got != expect["decision"]:
                problems.append(f"expected {expect['decision']}, got {got}"
                                + (f" ({result['error'].get('message')})" if "error" in result else ""))
            if "reason_contains" in expect and expect["reason_contains"] not in result.get("reason", ""):
                problems.append(f"reason {result.get('reason')!r} does not contain {expect['reason_contains']!r}")
            if "obligations" in expect:
                names = [o["name"] for o in result.get("obligations", [])]
                if names != expect["obligations"]:
                    problems.append(f"obligations {names} != {expect['obligations']}")
            if result.get("matched_line"):
                hit.add(result["matched_line"])
            report.results.append(TestResult(name, not problems, "; ".join(problems)))
    finally:
        engine.close()
    report.uncovered = [(line, kind) for line, kind in _decision_clauses(source) if line not in hit]
    return report


def diff_policies(old_source: str, new_source: str, requests: list, engine_factory: Callable[[str], object]) -> list:
    """Returns the requests whose decision or obligations differ between two policies."""
    old, new = engine_factory(old_source), engine_factory(new_source)
    changes = []
    try:
        for request in requests:
            a, b = old.check(request), new.check(request)
            key = lambda r: (r.get("decision", "ERROR"), [o["name"] for o in r.get("obligations", [])])
            if key(a) != key(b):
                changes.append({"request": request, "old": {"decision": key(a)[0], "obligations": key(a)[1]},
                                "new": {"decision": key(b)[0], "obligations": key(b)[1]}})
    finally:
        old.close()
        new.close()
    return changes
