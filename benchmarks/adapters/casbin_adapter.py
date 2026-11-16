#!/usr/bin/env python3
"""Translate one generated corpus to Casbin and measure it if `casbin` is installed.

Casbin's standard model has no numeric comparison, so the clearance clause is
not translated.  The four benchmark requests do not depend on that clause for
their outcome, but the adapter records `numeric_clause: false` so the coverage
limit is explicit.

Measurement is **Python library in-process** (`Enforcer.enforce`), not a
process boundary.  It is therefore reported separately from `yogc check` and
the OPA/Cedar CLIs.

Usage:
    python benchmarks/adapters/casbin_adapter.py --size small [--iterations 200]
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import importlib.util
import json
from pathlib import Path

from corpus import (build_model, corpus_file, load_requests, parse_facts,
                    PROFILES)
from stats import measure, require_decision

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CORPUS = ROOT / "benchmarks" / "generated"
BOUNDARY = "python-library"

MODEL = """[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _
g2 = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = (g(r.sub, p.sub) || r.sub == p.sub) && (p.obj == "*" || g2(r.obj, p.obj) || r.obj == p.obj) && r.act == p.act
"""


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_translation(model: dict, target: Path) -> tuple[Path, Path]:
    lines = []
    for user, role in sorted(model["role"].items()):
        lines.append(f"g, {user}, {role}")
    for user, teams in sorted(model["member"].items()):
        for team in sorted(teams):
            lines.append(f"g, {user}, {team}")
    for team, resources in sorted(model["team_resource"].items()):
        for resource in sorted(resources):
            lines.append(f"g2, {resource}, {team}")
    for resource in sorted(model["public"]):
        lines.append(f"g2, {resource}, public")

    lines.append("p, admin, *, can_access")
    for team in sorted(model["team_resource"]):
        lines.append(f"p, {team}, {team}, can_access")
    lines.append("p, manager, public, can_access")

    model_path = target / "model.conf"
    policy_path = target / "policy.csv"
    model_path.write_text(MODEL, encoding="utf-8")
    policy_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return model_path, policy_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size", choices=["small", "medium", "large"], default="small")
    parser.add_argument("--profile", choices=PROFILES, default="full")
    parser.add_argument("--iterations", type=int, default=200)
    parser.add_argument("--warmup", type=int, default=20)
    parser.add_argument("--repetitions", type=int, default=3)
    args = parser.parse_args()

    corpus = corpus_file(CORPUS, args.profile, args.size)
    if not corpus.exists():
        raise SystemExit(f"missing {corpus}; run benchmarks/gen_corpus.py first")
    model = build_model(parse_facts(corpus))
    requests = load_requests(CORPUS, args.size, args.profile)
    available = importlib.util.find_spec("casbin") is not None

    folder = args.size if args.profile == "full" else f"common-{args.size}"
    target = ROOT / "benchmarks" / "results" / "translations" / "casbin" / folder
    target.mkdir(parents=True, exist_ok=True)
    model_path, policy_path = write_translation(model, target)
    result = {
        "engine": "casbin",
        "size": args.size,
        "profile": args.profile,
        "boundary": BOUNDARY,
        "available": available,
        "numeric_clause": args.profile != "full",
        "translation": {
            "model": str(model_path),
            "policy": str(policy_path),
            "model_sha256": digest(model_path),
            "policy_sha256": digest(policy_path),
        },
        "requests": [],
    }
    if not available:
        result["note"] = "python casbin package not installed; translation written but not measured"
        print(json.dumps(result, indent=2))
        return 0

    from casbin import Enforcer  # type: ignore

    result["tool_version"] = importlib.metadata.version("casbin")
    enforcer = Enforcer(str(model_path), str(policy_path))

    for request in requests:
        def invoke() -> str:
            allowed = enforcer.enforce(request["actor"], request["resource"], "can_access")
            return "ALLOW" if allowed else "DENY"

        measurement, decision = measure(invoke, args.iterations, args.warmup,
                                        args.repetitions)
        require_decision(request["label"], request["expected"], decision)
        result["requests"].append({
            "label": request["label"],
            "expected": request["expected"],
            "decision": decision,
            **measurement["median"],
            "iterations": measurement["iterations"],
            "warmup": measurement["warmup"],
            "repetitions": measurement["repetitions"],
            "runs": measurement["runs"],
        })

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
