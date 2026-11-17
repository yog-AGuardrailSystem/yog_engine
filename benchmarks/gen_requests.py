#!/usr/bin/env python3
"""Generate a few hundred deterministic requests per profile and size.

The expected decision comes from ``benchmarks/oracle.py``, an independent
implementation of the corpus semantics.  Engines are compared against this
oracle, not against each other's output.

Usage:
    python benchmarks/gen_requests.py [--out DIR] [--per-size N]
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import gen_corpus
import oracle

HERE = Path(__file__).resolve().parent
DEFAULT_OUT = HERE / "generated"


class Lcg:
    def __init__(self, seed: int) -> None:
        self.state = seed & 0xFFFFFFFFFFFFFFFF

    def next(self) -> int:
        self.state = (self.state * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        return (self.state >> 33) & 0xFFFFFFFF

    def choice(self, values):
        return values[self.next() % len(values)]


def build_requests(profile: str, size: str, model: oracle.Model, per_size: int) -> list[dict]:
    spec = gen_corpus.SIZES[size]
    rng = Lcg(0xBADCAFE ^ sum(ord(c) for c in size) ^ (0x5EED if profile == "common" else 0))
    users = [f"u{i:04d}" for i in range(spec["users"])]
    resources = [f"r{i:04d}" for i in range(spec["resources"])]

    members = sorted(model.member)
    managers = [user for user, role in model.role.items() if role == "manager"]
    managers_without_team = [user for user in managers if user not in model.member]
    public = sorted(model.public)
    owned = sorted(resource for team in model.team_resource for resource in model.team_resource[team])

    buckets: list[dict] = []

    def add(label: str, actor: str, resource: str) -> None:
        buckets.append({
            "label": label,
            "actor": actor,
            "action": "can_access",
            "resource": resource,
            "expected": oracle.decide(model, profile, actor, resource),
        })

    for _ in range(per_size):
        add("admin", "u0000", rng.choice(resources))
    for _ in range(per_size):
        user = rng.choice(members)
        team = rng.choice(sorted(model.member[user]))
        team_resources = sorted(model.team_resource.get(team, ()))
        add("team join", user, rng.choice(team_resources) if team_resources else "r_denied")
    for _ in range(per_size):
        # Prefer managers without a team so the public clause is the only
        # possible allow path; fall back to any manager.
        manager = rng.choice(managers_without_team or managers or ["u0002"])
        add("manager public", manager,
            rng.choice(public) if public else rng.choice(resources))
    for _ in range(per_size):
        add("unmapped deny", rng.choice(["u0001", "u0002"]), "r_denied")
    for _ in range(per_size):
        add("clearance boundary", rng.choice(users), rng.choice(
            ["r_secret", "r_denied", "r0000", "r0001"]))
    for _ in range(per_size):
        add("random", rng.choice(users), rng.choice(resources))

    return buckets


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--per-size", type=int, default=50,
                        help="requests per bucket; six buckets per size (default 50 -> 300)")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    for profile in gen_corpus.PROFILES:
        for size in gen_corpus.SIZES:
            policy = args.out / gen_corpus.corpus_name(profile, size)
            if not policy.exists():
                raise SystemExit(f"missing {policy}; run benchmarks/gen_corpus.py first")
            model = oracle.load_model(policy)
            requests = build_requests(profile, size, model, args.per_size)
            target = args.out / f"workload-{profile}-{size}.json"
            target.write_text(json.dumps({
                "profile": profile,
                "size": size,
                "requests": requests,
            }, indent=2) + "\n", encoding="utf-8")
            allows = sum(1 for row in requests if row["expected"] == "ALLOW")
            print(f"wrote {target} ({len(requests)} requests, "
                  f"{allows} ALLOW / {len(requests) - allows} DENY)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
