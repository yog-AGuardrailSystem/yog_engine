#!/usr/bin/env python3
"""Generate the shared benchmark corpus.

Two profiles are emitted so that feature gaps are visible instead of hidden:

* ``full`` -- the YOG benchmark policy, including the numeric
  ``clearance >= classification`` clause.  Casbin's standard model cannot
  express that clause, so it is *not* feature-matched.
* ``common`` -- only the subset every engine (YOG, OPA, Cedar, Casbin) can
  express directly: role, group membership, resource ownership and a public
  flag.  This is the corpus used for the fair cross-engine comparison.

Fact shape (profile ``common``):
    role(user, role)
    member(user, team)
    team_resource(team, resource)
    public(resource)

Profile ``full`` additionally emits:
    clearance(user, 1..5)
    classification(resource, 1..5)

Rule shape (one decision predicate):
    common: admin OR (member -> team_resource) OR (manager + public)
    full:   common OR (clearance >= classification)

Usage:
    python benchmarks/gen_corpus.py [--out DIR] [--profile full|common|both]
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
PROFILES = ("full", "common")


class Lcg:
    def __init__(self, seed: int) -> None:
        self.state = seed & 0xFFFFFFFFFFFFFFFF

    def next(self) -> int:
        self.state = (self.state * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        return (self.state >> 33) & 0xFFFFFFFF

    def choice(self, values):
        return values[self.next() % len(values)]


def corpus_name(profile: str, size: str) -> str:
    return f"{size}.yog" if profile == "full" else f"common-{size}.yog"


def requests_name(profile: str) -> str:
    return "requests.json" if profile == "full" else "common-requests.json"


def generate(size: str, spec: dict, profile: str = "full") -> str:
    if profile not in PROFILES:
        raise ValueError(f"unknown profile: {profile}")
    rng = Lcg(0xC0FFEE ^ sum(ord(c) for c in size) ^ (0x5EED if profile == "common" else 0))
    users = [f"u{i:04d}" for i in range(spec["users"])]
    teams = [f"t{i:03d}" for i in range(spec["teams"])]
    resources = [f"r{i:04d}" for i in range(spec["resources"])]

    lines: list[str] = []
    roles: dict[str, str] = {}
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
            lines.append(f"fact member({user}, {team})")
        clearance[user] = 1 if index == 2 else 1 + rng.next() % 5

    for index, resource in enumerate(resources):
        team = teams[index % len(teams)]
        lines.append(f"fact team_resource({team}, {resource})")
        if rng.next() % 4 == 0:
            lines.append(f"fact public({resource})")

    # Sentinel resources for the denied cases: no team owns them, they are not
    # public, and their classification is above the low-clearance user.
    for sentinel, level in (("r_denied", 5), ("r_secret", 5)):
        if profile == "full":
            lines.append(f"fact classification({sentinel}, {level})")

    if profile == "full":
        for user in users:
            lines.append(f"fact clearance({user}, {clearance[user]})")
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
    ])
    if profile == "full":
        lines.extend([
            "allow can_access(User, Resource):",
            "    clearance(User, Level)",
            "    classification(Resource, Needed)",
            "    Level >= Needed",
            "",
        ])
    return "\n".join(lines)


def benchmark_requests(spec: dict, profile: str) -> list[dict]:
    member_user = f"u{spec['teams']:04d}"
    deny_label = "low clearance deny" if profile == "full" else "unmapped deny"
    deny_resource = "r_secret" if profile == "full" else "r_denied"
    return [
        {"label": "admin allow", "actor": "u0000", "action": "can_access",
         "resource": "r0000", "expected": "ALLOW"},
        {"label": "team join allow", "actor": member_user, "action": "can_access",
         "resource": "r0000", "expected": "ALLOW"},
        {"label": "guest default deny", "actor": "u0001", "action": "can_access",
         "resource": "r_denied", "expected": "DENY"},
        {"label": deny_label, "actor": "u0002", "action": "can_access",
         "resource": deny_resource, "expected": "DENY"},
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--profile", choices=(*PROFILES, "both"), default="both")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    profiles = PROFILES if args.profile == "both" else (args.profile,)
    for profile in profiles:
        by_size = {}
        for size, spec in SIZES.items():
            policy_path = args.out / corpus_name(profile, size)
            policy_path.write_text(generate(size, spec, profile), encoding="utf-8")
            clauses = 4 if profile == "full" else 3
            print(f"wrote {policy_path} ({spec['users']} users, "
                  f"{spec['resources']} resources, {clauses} allow clauses)")
            by_size[size] = benchmark_requests(spec, profile)

        requests_path = args.out / requests_name(profile)
        requests_path.write_text(
            json.dumps({"profile": profile, "by_size": by_size}, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"wrote {requests_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
