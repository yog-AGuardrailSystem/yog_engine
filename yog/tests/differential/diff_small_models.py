#!/usr/bin/env python3
"""Exhaustive small-model differential test: C engine versus the Python reference.

Random testing samples a huge space; this script instead covers a tiny space completely.  It enumerates *every*
policy made of zero, one or two clauses drawn from a fixed menu of clauses (all three decision kinds, with and
without an obligation, over a handful of body shapes), and runs every one of them against *every* request in a
small request universe.  For each (policy, request) the decision, the reason (which clause won) and the ordered
obligations must be identical in both implementations, or both must report an evaluation error.

Because the space is closed, passing means: for policies of this size over this vocabulary there is no input on
which the two engines disagree.  It does not say anything about larger policies; that is what the random
differential test (diff_v2.py) and the fuzzers are for.

Usage:
    python yog/tests/differential/diff_small_models.py [--yogc PATH] [--limit N]
"""
from __future__ import annotations

import argparse
import itertools
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import diff_v2  # noqa: E402  (reuses its plumbing: run_yogc, run_reference, compare)

HEADER = "version 2\ninput flag(text)\ninput level(int)\nfact vip(u1)\n\n"

# Body shapes, each a list of goal lines.  Together they exercise facts, negation, comparisons, both integer
# directions, input presence/absence, and an always-true body.
BODIES = [
    ["true == true"],
    ['flag("x")'],
    ['not flag("x")'],
    ["vip(U)"],
    ["not vip(U)"],
    ["level(N)", "N > 1"],
    ["level(N)", "N < 1"],
    ['flag("x")', "vip(U)"],
]


def clause(kind: str, body: list, obligation: bool) -> str:
    lines = [f"{kind} act(U, R):"] + ["    " + g for g in body]
    if obligation:
        lines.append("    obligation audit(R)")
    return "\n".join(lines) + "\n"


def menu() -> list:
    out = []
    for kind in ("allow", "deny", "require_approval"):
        for body in BODIES:
            out.append(clause(kind, body, False))
            if kind != "deny":
                out.append(clause(kind, body, True))
    return out


def policies() -> list:
    clauses = menu()
    yield HEADER
    for one in clauses:
        yield HEADER + one
    for a, b in itertools.product(clauses, repeat=2):
        yield HEADER + a + "\n" + b


def requests() -> list:
    out = []
    for actor in ("u1", "u2"):
        for flag in (None, "x", "y"):
            for level in (None, 0, 1, 2):
                facts = []
                if flag is not None:
                    facts.append(("flag", [flag]))
                if level is not None:
                    facts.append(("level", [level]))
                out.append((actor, "act", "r1", facts))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--yogc", type=Path, default=diff_v2.DEFAULT_YOGC)
    parser.add_argument("--limit", type=int, default=0, help="stop after this many policies (0 = all)")
    args = parser.parse_args()
    if not args.yogc.exists():
        print(f"yogc not found at {args.yogc}; pass --yogc", file=sys.stderr)
        return 2
    universe = requests()
    failures: list = []
    compared = count = 0
    for policy in policies():
        count += 1
        compared += diff_v2.compare(f"[small #{count}]\n{policy}", policy, universe, args.yogc, failures)
        if len(failures) > 10 or (args.limit and count >= args.limit):
            break
    for message in failures[:10]:
        print("MISMATCH", message)
    if failures:
        print(f"{len(failures)} mismatch(es) in {compared} comparisons over {count} policies")
        return 1
    print(f"all {compared} comparisons agree: {count} policies x {len(universe)} requests, exhaustive for this vocabulary")
    return 0


if __name__ == "__main__":
    sys.exit(main())
