#!/usr/bin/env python3
"""Differential check: the C compiler vs the Python behavioural reference.

Two independent comparisons over the conformance corpus:

  1. query evaluation -- every `query` in the policy, including bindings;
  2. authorization       -- the same requests through `check()`, including
                            the DENY/ALLOW precedence and the exact reason.

Usage:
    python yog/tests/differential/diff_vs_python.py [--yogc PATH] [POLICY...]

Exit status 0 means the two implementations agreed on every case.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
ROOT = HERE.parents[3]
DEFAULT_POLICY = ROOT / "all_examples.yog"
DEFAULT_YOGC = ROOT / "yog" / "build" / ("yogc.exe" if os.name == "nt" else "yogc")


def load_reference():
    path = ROOT / "yog.py"
    spec = importlib.util.spec_from_file_location("yog_reference", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def python_queries(reference, source: str):
    program = reference.Parser(reference.tokenize(source)).parse()
    engine = reference.Engine(program)
    results = []
    for query in engine.queries:
        ok, solutions, _trace = engine.ask(query)
        bindings = []
        for solution in solutions:
            binding = {
                name: repr(value)
                for name, value in solution.items()
                if "#" not in name and not name.startswith("_G")
            }
            if binding:
                bindings.append(binding)
        results.append((repr(query), ok, bindings))
    return engine, results


def c_queries(yogc: Path, policy: Path):
    completed = subprocess.run(
        [str(yogc), "run", str(policy)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode != 0:
        raise SystemExit(f"yogc run failed ({completed.returncode}):\n{completed.stderr}")

    results = []
    current = None
    for raw in completed.stdout.splitlines():
        line = raw.rstrip("\n")
        if line.startswith("query "):
            current = {"query": line[len("query "):].strip(), "decision": None, "bindings": []}
        elif current is not None and line.startswith("  -> "):
            current["decision"] = line.strip().endswith("TRUE")
        elif current is not None and line.startswith("     ") and "=" in line:
            binding = {}
            for part in line.strip().split(", "):
                if "=" in part:
                    name, value = part.split("=", 1)
                    binding[name] = value
            current["bindings"].append(binding)
        elif current is not None and not line.strip():
            results.append((current["query"], current["decision"], current["bindings"]))
            current = None
    if current is not None:
        results.append((current["query"], current["decision"], current["bindings"]))
    return results


def check_requests(reference, engine, source: str):
    """Ground arity-2 queries are also run through check() on both sides."""
    requests = []
    for query in engine.queries:
        if len(query.args) != 2:
            continue
        if not all(isinstance(arg, reference.Const) for arg in query.args):
            continue
        actor, resource = (str(arg.val) for arg in query.args)
        expected = engine.check(actor, query.pred, resource)
        requests.append((actor, query.pred, resource, expected["decision"], expected["reason"]))
    return requests


def c_check(yogc: Path, policy: Path, actor: str, action: str, resource: str):
    completed = subprocess.run(
        [str(yogc), "check", str(policy), actor, action, resource],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode not in (0, 3):
        raise SystemExit(
            f"yogc check {' '.join((actor, action, resource))} failed "
            f"({completed.returncode}):\n{completed.stderr}"
        )
    header = completed.stdout.splitlines()[0] if completed.stdout else ""
    decision, _, reason = header.partition("|")
    return decision.strip(), reason.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--yogc", type=Path, default=DEFAULT_YOGC)
    parser.add_argument("policies", nargs="*", type=Path, default=[DEFAULT_POLICY])
    args = parser.parse_args()

    if not args.yogc.exists():
        raise SystemExit(f"yogc not found: {args.yogc} (build it, or pass --yogc)")

    reference = load_reference()
    failures = 0

    for policy in args.policies:
        source = policy.read_text(encoding="utf-8", errors="replace")
        engine, expected_queries = python_queries(reference, source)
        actual_queries = c_queries(args.yogc, policy)

        if actual_queries != expected_queries:
            failures += 1
            print(f"FAIL {policy}: query results differ")
            for expected, actual in zip(expected_queries, actual_queries):
                if expected != actual:
                    print(f"  expected: {expected}")
                    print(f"  actual:   {actual}")
            if len(expected_queries) != len(actual_queries):
                print(f"  expected {len(expected_queries)} queries, got {len(actual_queries)}")
        else:
            print(f"ok   {policy}: {len(expected_queries)} queries match")

        for actor, action, resource, decision, reason in check_requests(reference, engine, source):
            actual_decision, actual_reason = c_check(args.yogc, policy, actor, action, resource)
            if (actual_decision, actual_reason) != (decision, reason):
                failures += 1
                print(f"FAIL check {action}({actor}, {resource})")
                print(f"  expected: {decision} | {reason}")
                print(f"  actual:   {actual_decision} | {actual_reason}")

    if failures:
        print(f"\n{failures} differential case(s) failed")
        return 1
    print("\nall differential checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
