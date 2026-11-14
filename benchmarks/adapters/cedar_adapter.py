#!/usr/bin/env python3
"""Translate one generated corpus to Cedar and measure it if the CLI is installed.

Users are members of Role and Team groups; resources carry an `owner` entity
reference and a `public` flag.  That makes the team join `principal in
resource.owner`, and the clearance clause a direct integer comparison.  If the
`cedar` CLI is absent, the translation is written and the adapter reports
`available: false`.

Usage:
    python benchmarks/adapters/cedar_adapter.py --size small [--iterations 5]
"""
from __future__ import annotations

import argparse
import json
import shutil
import statistics
import subprocess
import time
from pathlib import Path

from corpus import build_model, load_requests, parse_facts

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CORPUS = ROOT / "benchmarks" / "generated"

POLICY = """// Generated from the YOG benchmark corpus.
permit (
    principal,
    action == Action::"can_access",
    resource
)
when { principal in Role::"admin" };

permit (
    principal,
    action == Action::"can_access",
    resource
)
when { principal in resource.owner };

permit (
    principal,
    action == Action::"can_access",
    resource
)
when { principal in Role::"manager" && resource.public };

permit (
    principal,
    action == Action::"can_access",
    resource
)
when { principal.clearance >= resource.classification };
"""


def write_translation(model: dict, target: Path) -> tuple[Path, Path]:
    entities = [{"uid": {"type": "Action", "id": "can_access"},
                 "attrs": {}, "parents": []}]

    roles = sorted(set(model["role"].values()) | {"manager"})
    for role in roles:
        entities.append({"uid": {"type": "Role", "id": role}, "attrs": {}, "parents": []})

    for team in sorted(model["team_resource"]):
        entities.append({"uid": {"type": "Team", "id": team}, "attrs": {}, "parents": []})
    entities.append({"uid": {"type": "Team", "id": "public"}, "attrs": {}, "parents": []})

    for user, role in sorted(model["role"].items()):
        parents = [{"type": "Role", "id": role}]
        for team in sorted(model["member"].get(user, ())):
            parents.append({"type": "Team", "id": team})
        entities.append({
            "uid": {"type": "User", "id": user},
            "attrs": {"clearance": model["clearance"].get(user, 0)},
            "parents": parents,
        })

    resources = set(model["classification"]) | model["public"]
    for resource in sorted(resources):
        owner = model["owner"].get(resource)
        attrs = {
            "classification": model["classification"].get(resource, 5),
            "public": resource in model["public"],
        }
        if owner is not None:
            attrs["owner"] = {"type": "Team", "id": owner}
        else:
            # Cedar needs an entity reference for `principal in resource.owner`.
            attrs["owner"] = {"type": "Team", "id": "public"}
        entities.append({"uid": {"type": "Resource", "id": resource},
                         "attrs": attrs, "parents": []})

    policy_path = target / "policy.cedar"
    entities_path = target / "entities.json"
    policy_path.write_text(POLICY, encoding="utf-8")
    entities_path.write_text(json.dumps(entities, indent=2) + "\n", encoding="utf-8")
    return policy_path, entities_path


def parse_decision(stdout: str) -> str:
    upper = stdout.upper()
    if "ALLOW" in upper:
        return "ALLOW"
    if "DENY" in upper:
        return "DENY"
    try:
        payload = json.loads(stdout)
        decision = payload.get("decision", "")
        return "ALLOW" if str(decision).lower() == "allow" else "DENY"
    except (ValueError, AttributeError):
        return "UNKNOWN"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size", choices=["small", "medium", "large"], default="small")
    parser.add_argument("--iterations", type=int, default=5)
    args = parser.parse_args()

    corpus = CORPUS / f"{args.size}.yog"
    if not corpus.exists():
        raise SystemExit(f"missing {corpus}; run benchmarks/gen_corpus.py first")
    model = build_model(parse_facts(corpus))
    requests = load_requests(CORPUS, args.size)
    cedar = shutil.which("cedar")

    target = ROOT / "benchmarks" / "results" / "translations" / "cedar" / args.size
    target.mkdir(parents=True, exist_ok=True)
    policy_path, entities_path = write_translation(model, target)
    result = {
        "engine": "cedar",
        "size": args.size,
        "available": cedar is not None,
        "translation": {"policy": str(policy_path), "entities": str(entities_path)},
        "requests": [],
    }
    if cedar is None:
        result["note"] = "cedar CLI not on PATH; translation written but not measured"
        print(json.dumps(result, indent=2))
        return 0

    for request in requests:
        request_path = target / "request.json"
        request_path.write_text(json.dumps({
            "principal": f'User::"{request["actor"]}"',
            "action": 'Action::"can_access"',
            "resource": f'Resource::"{request["resource"]}"',
            "context": {},
        }) + "\n", encoding="utf-8")
        samples = []
        decision = None
        for _ in range(args.iterations):
            before = time.perf_counter_ns()
            completed = subprocess.run(
                [cedar, "authorize", "--policies", str(policy_path),
                 "--entities", str(entities_path), "--request-json", str(request_path)],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
            )
            after = time.perf_counter_ns()
            if completed.returncode != 0:
                raise SystemExit(f"cedar failed: {completed.stderr}")
            decision = parse_decision(completed.stdout)
            samples.append(after - before)
        result["requests"].append({
            "label": request["label"],
            "expected": request["expected"],
            "decision": decision,
            "mean_us": statistics.fmean(samples) / 1000.0,
            "p50_us": sorted(samples)[len(samples) // 2] / 1000.0,
        })

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
