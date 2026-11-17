#!/usr/bin/env python3
"""Data-driven conformance suite for the YOG compiler.

The expectations in `cases.json` are stated independently of `yog.py` and of
the C implementation: each request names the decision the authorization
contract must produce, and each compile case names the diagnostic it must
report.  This is the suite that catches a bug shared by both implementations.

Usage:
    python yog/tests/conformance/run_conformance.py [--yogc PATH] [--policy PATH]

Exit status 0 means every expectation held.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve()
ROOT = HERE.parents[3]
DEFAULT_POLICY = ROOT / "all_examples.yog"
DEFAULT_YOGC = ROOT / "yog" / "build" / ("yogc.exe" if os.name == "nt" else "yogc")
CASES = HERE.parent / "cases.json"

# (name, source, expected substring in stderr).  These pin the diagnostics that
# docs/COMPILER.md promises.  Message text is part of the contract.
COMPILE_CASES = [
    ("zero-arity atom", "fact a()\n", "Expected a term"),
    ("no rule body", "fact p(a)\nrule q(X):\n", "Expected an indented body"),
    ("identifier-left comparison", "fact p(a)\nrule q(X):\n    p(X)\n    a == X\n",
     "Expected '(', found EQ"),
    ("non-ground fact", "fact p(X)\n", "facts must be ground"),
    ("role conflict", "fact p(a)\nallow p(X):\n    p(X)\n", "pick one role"),
    ("unbound rule head", "fact p(a)\nrule q(Y):\n    p(X)\n",
     "never bound by the body"),
    ("unbound before not", "fact p(a)\nfact r(b)\nrule q(X):\n    p(X)\n    not r(Y)\n",
     "not bound before `not`"),
    ("unbound before comparison", "fact p(a)\nrule q(X):\n    p(X)\n    Y < 3\n",
     "not bound before a comparison"),
    ("undefined predicate", "fact p(a)\nallow q(X, Y):\n    p(X)\n    missing(Y)\n",
     "is not defined by any fact or rule"),
    ("rule cycle", "fact p(a)\nrule r(X):\n    s(X)\nrule s(X):\n    r(X)\n",
     "rule cycle:"),
]


def run(yogc: Path, args: list[str], stdin: str | None = None):
    return subprocess.run(
        [str(yogc), *args],
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def run_batch(yogc: Path, policy: Path, cases: list[dict]) -> list[str]:
    lines = []
    for case in cases:
        line = f"{case['actor']} {case['action']} {case['resource']}"
        if case.get("context"):
            line += f" | {case['context']}"
        lines.append(line)
    completed = run(yogc, ["batch", str(policy)], "\n".join(lines) + "\n")
    if completed.returncode != 0:
        raise SystemExit(f"yogc batch failed ({completed.returncode}):\n{completed.stderr}")
    blocks = [block.strip() for block in completed.stdout.split("--") if block.strip()]
    if len(blocks) != len(cases):
        raise SystemExit(
            f"expected {len(cases)} batch results, got {len(blocks)}:\n{completed.stdout}"
        )
    return blocks


def parse_queries(stdout: str) -> dict[str, bool]:
    results: dict[str, bool] = {}
    current = None
    for raw in stdout.splitlines():
        line = raw.strip()
        if line.startswith("query "):
            current = line[len("query "):].strip()
        elif current is not None and line.startswith("-> "):
            results[current] = line.endswith("TRUE")
            current = None
    return results


def check_compile_cases(yogc: Path) -> int:
    failures = 0
    with tempfile.TemporaryDirectory(prefix="yog-conformance-") as tmp:
        for index, (name, source, expected) in enumerate(COMPILE_CASES):
            path = Path(tmp) / f"case_{index}.yog"
            path.write_text(source, encoding="utf-8")
            completed = run(yogc, ["validate", str(path)])
            output = completed.stderr + completed.stdout
            if completed.returncode != 1:
                failures += 1
                print(f"FAIL compile [{name}]: expected exit 1, got {completed.returncode}")
            elif expected not in output:
                failures += 1
                print(f"FAIL compile [{name}]: missing {expected!r}")
                print(f"  output: {output.strip()}")
            else:
                print(f"ok   compile [{name}]")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--yogc", type=Path, default=DEFAULT_YOGC)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    args = parser.parse_args()

    if not args.yogc.exists():
        raise SystemExit(f"yogc not found: {args.yogc} (build it, or pass --yogc)")

    spec = json.loads(CASES.read_text(encoding="utf-8"))
    policy = args.policy
    if not policy.is_absolute():
        policy = ROOT / policy
    cases = spec["cases"]
    failures = 0

    blocks = run_batch(args.yogc, policy, cases)
    for case, block in zip(cases, blocks):
        header = block.splitlines()[0] if block else ""
        decision, _, reason = header.partition("|")
        decision = decision.strip()
        reason = reason.strip()
        if header.startswith("ERROR|"):
            failures += 1
            print(f"FAIL check [{case['name']}]: {header}")
        elif decision != case["decision"]:
            failures += 1
            print(f"FAIL check [{case['name']}]: expected {case['decision']}, got {decision}")
            print(f"  reason: {reason}")
        elif case["reason_contains"] not in reason:
            failures += 1
            print(f"FAIL check [{case['name']}]: reason {reason!r} lacks "
                  f"{case['reason_contains']!r}")
        else:
            print(f"ok   check [{case['name']}]")

    completed = run(args.yogc, ["run", str(policy)])
    if completed.returncode != 0:
        raise SystemExit(f"yogc run failed ({completed.returncode}):\n{completed.stderr}")
    actual = parse_queries(completed.stdout)
    for case in spec.get("query_cases", []):
        if case["query"] not in actual:
            failures += 1
            print(f"FAIL query [{case['name']}]: {case['query']!r} not found")
        elif actual[case["query"]] != case["result"]:
            failures += 1
            print(f"FAIL query [{case['name']}]: expected {case['result']}, "
                  f"got {actual[case['query']]}")
        else:
            print(f"ok   query [{case['name']}]")

    failures += check_compile_cases(args.yogc)

    if failures:
        print(f"\n{failures} conformance case(s) failed")
        return 1
    print(f"\nall {len(cases)} authorization, {len(spec.get('query_cases', []))} query "
          f"and {len(COMPILE_CASES)} compile cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
