#!/usr/bin/env python3
"""Generate the shared benchmark corpus.

The same facts and rules are emitted at three sizes.  Generated policies are
written to `benchmarks/generated/` (not committed) so the repository stays
small while every run uses an identical, deterministic workload.

Fact shape:
    role(user, role)
    member(user, team)
    team_resource(team, resource)
    public(resource)
    clearance(user, 1..5)
    classification(resource, 1..5)

Rule shape (one decision predicate, four allow clauses):
    admin OR (member -> team_resource) OR (manager + public)
          OR (clearance >= classification)

Usage:
    python benchmarks/gen_corpus.py [--out DIR]
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_OUT = HERE / "generated"

SIZES = {
    "small": {"users": 20, "teams": 5, "resources": 30},
    "medium": {"users": 200, "teams": 20, "resources": 200},
    "large": {"users": 2000, "teams": 100, "resources": 1000},
}

ROLES = ["engineer", "engineer", "engineer", "manager", "auditor", "guest"]


class Lcg:
    def __init__(self, seed: int) -> None:
        self.state = seed & 0xFFFFFFFFFFFFFFFF

    def next(self) -> int:
        self.state = (self.state * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        return (self.state >> 33) & 0xFFFFFFFF

    def choice(self, values):
        return values[self.next() % len(values)]


def generate(size: str, spec: dict) -> str:
    rng = Lcg(0xC0FFEE ^ sum(ord(c) for c in size))
    users = [f"u{i:04d}" for i in range(spec["users"])]
    teams = [f"t{i:03d}" for i in range(spec["teams"])]
    resources = [f"r{i:04d}" for i in range(spec["resources"])]

    lines: list[str] = []
    roles: dict[str, str] = {}
    members: dict[str, str] = {}
    clearance: dict[str, int] = {}

    for index, user in enumerate(users):
        if index == 0:
            role = "admin"
        elif index == 1:
            role = "guest"
        elif index == 2:
            role = "engineer"
        else:
            role = rng.choice(ROLES)
        roles[user] = role
        lines.append(f"fact role({user}, {role})")
        # The guest and low-clearance users deliberately have no team, so the
        # denied benchmark requests cannot fall through to the member clause.
        if index not in (1, 2):
            team = teams[index % len(teams)]
            members[user] = team
            lines.append(f"fact member({user}, {team})")
        clearance[user] = 1 if index == 2 else 1 + rng.next() % 5

    for user in users:
        lines.append(f"fact clearance({user}, {clearance[user]})")

    owned: dict[str, str] = {}
    for index, resource in enumerate(resources):
        team = teams[index % len(teams)]
        owned[resource] = team
        lines.append(f"fact team_resource({team}, {resource})")
        public = rng.next() % 4 == 0
        if public:
            lines.append(f"fact public({resource})")

    # Two sentinel resources for the denied cases: no team owns them, they are
    # not public, and their classification is above the benchmark user's
    # clearance.
    for sentinel, level in (("r_denied", 5), ("r_secret", 5)):
        lines.append(f"fact classification({sentinel}, {level})")
    for resource in resources:
        lines.append(f"fact classification({resource}, {1 + rng.next() % 5})")

    lines.extend([
        "",
        "allow can_access(User, Resource):",
        "    role(User, admin)",
        "",
        "allow can_access(User, Resource):",
        "    member(User, Team)",
        "    team_resource(Team, Resource)",
        "",
        "allow can_access(User, Resource):",
        "    role(User, manager)",
        "    public(Resource)",
        "",
        "allow can_access(User, Resource):",
        "    clearance(User, Level)",
        "    classification(Resource, Needed)",
        "    Level >= Needed",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    by_size = {}
    for size, spec in SIZES.items():
        policy = args.out / f"{size}.yog"
        policy.write_text(generate(size, spec), encoding="utf-8")
        print(f"wrote {policy} ({spec['users']} users, {spec['resources']} resources)")

        # r0000 is owned by t000, and user index `teams` is a member of t000.
        # Index 0 is admin and indices 1/2 are the reserved deny users.
        member_user = f"u{spec['teams']:04d}"
        by_size[size] = [
            {"label": "admin allow", "actor": "u0000", "action": "can_access",
             "resource": "r0000", "expected": "ALLOW"},
            {"label": "team join allow", "actor": member_user, "action": "can_access",
             "resource": "r0000", "expected": "ALLOW"},
            {"label": "guest default deny", "actor": "u0001", "action": "can_access",
             "resource": "r_denied", "expected": "DENY"},
            {"label": "low clearance deny", "actor": "u0002", "action": "can_access",
             "resource": "r_secret", "expected": "DENY"},
        ]

    (args.out / "requests.json").write_text(
        json.dumps({"by_size": by_size}, indent=2) + "\n", encoding="utf-8"
    )
    print(f"wrote {args.out / 'requests.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
