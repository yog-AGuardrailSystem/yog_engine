#!/usr/bin/env python3
"""Translate one generated corpus to Casbin and measure it if `casbin` is installed.

Casbin's standard model has no numeric comparison, so the clearance clause is
not translated.  The four benchmark requests do not depend on that clause for
their outcome, but the adapter records `numeric_clause: false` so the coverage
limit is explicit.  If the Python package is absent, translation files are
written and the adapter reports `available: false`.

Usage:
    python benchmarks/adapters/casbin_adapter.py --size small [--iterations 50]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import statistics
import time
from pathlib import Path

from corpus import build_model, load_requests, parse_facts

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CORPUS = ROOT / "benchmarks" / "generated"

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
    parser.add_argument("--iterations", type=int, default=50)
    args = parser.parse_args()

    corpus = CORPUS / f"{args.size}.yog"
    if not corpus.exists():
        raise SystemExit(f"missing {corpus}; run benchmarks/gen_corpus.py first")
    model = build_model(parse_facts(corpus))
    requests = load_requests(CORPUS, args.size)
    available = importlib.util.find_spec("casbin") is not None

    target = ROOT / "benchmarks" / "results" / "translations" / "casbin" / args.size
    target.mkdir(parents=True, exist_ok=True)
    model_path, policy_path = write_translation(model, target)
    result = {
        "engine": "casbin",
        "size": args.size,
        "available": available,
        "numeric_clause": False,
        "translation": {"model": str(model_path), "policy": str(policy_path)},
        "requests": [],
    }
    if not available:
        result["note"] = "python casbin package not installed; translation written but not measured"
        print(json.dumps(result, indent=2))
        return 0

    from casbin import Enforcer  # type: ignore

    enforcer = Enforcer(str(model_path), str(policy_path))
    for request in requests:
        samples = []
        decision = None
        for _ in range(args.iterations):
            before = time.perf_counter_ns()
            allowed = enforcer.enforce(request["actor"], request["resource"], "can_access")
            after = time.perf_counter_ns()
            decision = "ALLOW" if allowed else "DENY"
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
