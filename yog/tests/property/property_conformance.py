#!/usr/bin/env python3
"""Property-based conformance test with an independent oracle.

The oracle does not use the YOG parser, unifier or solver.  It evaluates the
same generated facts with plain Python lookups, so a bug shared by the C and
Python reference engines is still caught.

Each generated policy mixes positive goals, joins on a shared `Team` variable,
and integer comparisons.  For every actor/resource pair the oracle computes the
authorization contract (deny > allow > default deny) directly.

Usage:
    python yog/tests/property/property_conformance.py [--yogc PATH] [--iterations N]

Exit status 0 means every generated policy matched the oracle.
"""
from __future__ import annotations

import argparse
import os
import random
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve()
ROOT = HERE.parents[3]
DEFAULT_YOGC = ROOT / "yog" / "build" / ("yogc.exe" if os.name == "nt" else "yogc")

ACTORS = ["alice", "bob", "carol", "dave", "erin"]
RESOURCES = ["db1", "db2", "file1", "file2"]
ROLES = ["admin", "dev", "analyst"]
TEAMS = ["red", "blue", "green"]
ENVS = ["prod", "staging"]


# --------------------------------------------------------------- oracle ----
# A clause is a tuple of literal patterns.  Each pattern is evaluated with
# direct dictionary/set lookups; there is no unification here on purpose.


def holds(pattern, actor, resource, facts) -> bool:
    kind = pattern[0]
    if kind == "role":
        return facts["role"].get(actor) == pattern[1]
    if kind == "env":
        return facts["env"].get(resource) == pattern[1]
    if kind == "member_role":
        return any(facts["team_role"].get(team) == pattern[1]
                   for team in facts["member"].get(actor, ()))
    if kind == "owner_member":
        owner = facts["owner"].get(resource)
        return owner is not None and owner in facts["member"].get(actor, ())
    if kind == "level_ge":
        level = facts["level"].get(actor)
        required = facts["required"].get(resource)
        return level is not None and required is not None and level >= required
    if kind == "and":
        return all(holds(part, actor, resource, facts) for part in pattern[1])
    raise AssertionError(f"unknown pattern {pattern!r}")


def expected_decision(allow, deny, actor, resource, facts) -> str:
    if any(all(holds(p, actor, resource, facts) for p in clause) for clause in deny):
        return "DENY"
    if any(all(holds(p, actor, resource, facts) for p in clause) for clause in allow):
        return "ALLOW"
    return "DENY"


# ------------------------------------------------------------ generation ----


def random_facts(rng: random.Random) -> dict:
    role = {actor: rng.choice(ROLES) for actor in ACTORS if rng.random() < 0.8}
    if not role:
        role[ACTORS[0]] = ROLES[0]
    env = {resource: rng.choice(ENVS) for resource in RESOURCES if rng.random() < 0.8}
    if not env:
        env[RESOURCES[0]] = ENVS[0]

    member: dict[str, set[str]] = {}
    for actor in ACTORS:
        if rng.random() < 0.7:
            member[actor] = set(rng.sample(TEAMS, rng.randint(1, 2)))
    if not member:
        member[ACTORS[0]] = {TEAMS[0]}

    team_role = {team: rng.choice(ROLES) for team in TEAMS}

    # Only teams that actually appear in `member` need a role fact, but keeping
    # all of them is simpler and still exercises joins.
    owner = {resource: rng.choice(TEAMS) for resource in RESOURCES if rng.random() < 0.7}
    if not owner:
        owner[RESOURCES[0]] = TEAMS[0]

    level = {actor: rng.randint(1, 5) for actor in ACTORS if rng.random() < 0.8}
    if not level:
        level[ACTORS[0]] = 3
    required = {resource: rng.randint(1, 5) for resource in RESOURCES if rng.random() < 0.8}
    if not required:
        required[RESOURCES[0]] = 3

    return {
        "role": role,
        "env": env,
        "member": member,
        "team_role": team_role,
        "owner": owner,
        "level": level,
        "required": required,
    }


def random_pattern(rng: random.Random) -> tuple:
    kind = rng.choice(["role", "env", "member_role", "owner_member", "level_ge", "and"])
    if kind == "role":
        return ("role", rng.choice(ROLES))
    if kind == "env":
        return ("env", rng.choice(ENVS))
    if kind == "member_role":
        return ("member_role", rng.choice(ROLES))
    if kind == "owner_member":
        return ("owner_member",)
    if kind == "level_ge":
        return ("level_ge",)
    # Keep conjunctions free of two Team-using patterns: the oracle evaluates
    # each pattern independently, while YOG would join them on the shared
    # `Team` variable.  Team joins are covered by the standalone patterns.
    simple = [("role", rng.choice(ROLES)),
              ("env", rng.choice(ENVS)),
              ("level_ge",)]
    return ("and", (rng.choice(simple), rng.choice(simple)))


def uses_team(pattern) -> bool:
    if pattern[0] in ("member_role", "owner_member"):
        return True
    if pattern[0] == "and":
        return any(uses_team(part) for part in pattern[1])
    return False


def random_clause(rng: random.Random) -> list[tuple]:
    first = random_pattern(rng)
    if rng.random() < 0.5:
        return [first]
    second = random_pattern(rng)
    # Two Team-using patterns would be joined on the same `Team` variable in
    # YOG; the oracle keeps those independent, so do not generate that shape.
    while uses_team(first) and uses_team(second):
        second = random_pattern(rng)
    return [first, second]


def render_pattern(pattern) -> list[str]:
    kind = pattern[0]
    if kind == "role":
        return [f"    role(User, {pattern[1]})"]
    if kind == "env":
        return [f"    env(Resource, {pattern[1]})"]
    if kind == "member_role":
        return ["    member(User, Team)", f"    team_role(Team, {pattern[1]})"]
    if kind == "owner_member":
        return ["    owner(Resource, Team)", "    member(User, Team)"]
    if kind == "level_ge":
        return ["    level(User, Level)", "    required(Resource, Needed)",
                "    Level >= Needed"]
    if kind == "and":
        lines: list[str] = []
        for part in pattern[1]:
            lines.extend(render_pattern(part))
        return lines
    raise AssertionError(pattern)


def render_policy(facts: dict, allow: list, deny: list) -> str:
    lines: list[str] = []
    for actor, value in sorted(facts["role"].items()):
        lines.append(f"fact role({actor}, {value})")
    for resource, value in sorted(facts["env"].items()):
        lines.append(f"fact env({resource}, {value})")
    for actor, teams in sorted(facts["member"].items()):
        for team in sorted(teams):
            lines.append(f"fact member({actor}, {team})")
    for team, value in sorted(facts["team_role"].items()):
        lines.append(f"fact team_role({team}, {value})")
    for resource, team in sorted(facts["owner"].items()):
        lines.append(f"fact owner({resource}, {team})")
    for actor, value in sorted(facts["level"].items()):
        lines.append(f"fact level({actor}, {value})")
    for resource, value in sorted(facts["required"].items()):
        lines.append(f"fact required({resource}, {value})")

    # Interleave decide clauses: deny precedence must not depend on order.
    clauses = [("allow", c) for c in allow] + [("deny", c) for c in deny]
    random.shuffle(clauses)
    for kind, clause in clauses:
        lines.append(f"{kind} can_act(User, Resource):")
        for pattern in clause:
            lines.extend(render_pattern(pattern))
        lines.append("")
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------ main ----


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--yogc", type=Path, default=DEFAULT_YOGC)
    parser.add_argument("--iterations", type=int, default=80)
    parser.add_argument("--seed", type=int, default=20261112)
    args = parser.parse_args()

    if not args.yogc.exists():
        raise SystemExit(f"yogc not found: {args.yogc} (build it, or pass --yogc)")

    rng = random.Random(args.seed)
    checked = 0
    failures = 0

    with tempfile.TemporaryDirectory(prefix="yog-property-") as tmp:
        for iteration in range(args.iterations):
            facts = random_facts(rng)
            allow = [random_clause(rng) for _ in range(rng.randint(1, 3))]
            deny = [random_clause(rng) for _ in range(rng.randint(0, 2))]
            source = render_policy(facts, allow, deny)
            path = Path(tmp) / f"policy_{iteration}.yog"
            path.write_text(source, encoding="utf-8")

            requests = [(actor, resource) for actor in ACTORS for resource in RESOURCES]
            stdin = "".join(f"{actor} can_act {resource}\n" for actor, resource in requests)
            completed = subprocess.run(
                [str(args.yogc), "batch", str(path)],
                input=stdin,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            if completed.returncode != 0:
                failures += 1
                print(f"FAIL iteration {iteration}: yogc batch failed")
                print(completed.stderr)
                continue

            blocks = [b.strip() for b in completed.stdout.split("--") if b.strip()]
            if len(blocks) != len(requests):
                failures += 1
                print(f"FAIL iteration {iteration}: expected {len(requests)} results, "
                      f"got {len(blocks)}")
                continue

            for (actor, resource), block in zip(requests, blocks):
                actual = block.split("|", 1)[0].strip()
                expected = expected_decision(allow, deny, actor, resource, facts)
                checked += 1
                if actual != expected:
                    failures += 1
                    print(f"FAIL iteration {iteration} {actor}/{resource}: "
                          f"expected {expected}, got {actual}")
                    print("--- policy ---")
                    print(source)
                    if failures > 5:
                        print("too many failures; stopping")
                        return 1

    if failures:
        print(f"\n{failures} property failure(s)")
        return 1
    print(f"all {checked} generated authorization decisions matched the oracle "
          f"({args.iterations} policies, seed {args.seed})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
