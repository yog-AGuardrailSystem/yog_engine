#!/usr/bin/env python3
"""Translate one generated corpus to OPA/Rego and measure it if OPA is installed.

The translation is intentionally direct: the four YOG allow clauses become four
Rego set members, and the deny > allow > default-deny contract is represented
by the final `decision` rule.  If `opa` is not on PATH the adapter writes the
translation and reports `available: false`; it never invents numbers.

Usage:
    python benchmarks/adapters/opa_adapter.py --size small [--iterations 5]
"""
from __future__ import annotations

import argparse
import json
import shutil
import statistics
import subprocess
import time
from pathlib import Path

from corpus import DECISION, build_model, load_requests, parse_facts

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CORPUS = ROOT / "benchmarks" / "generated"

REGO = """package yogbench

import future.keywords.in

allowed contains true if {
    data.role[input.actor] == "admin"
}

allowed contains true if {
    some team in object.get(data.member, input.actor, [])
    input.resource in object.get(data.team_resource, team, [])
}

allowed contains true if {
    data.role[input.actor] == "manager"
    input.resource in data.public
}

allowed contains true if {
    object.get(data.clearance, input.actor, -1) >= object.get(data.classification, input.resource, 1000000)
}

decision := "ALLOW" if { count(allowed) > 0 } else := "DENY"
"""


def write_translation(model: dict, target: Path) -> tuple[Path, Path]:
    data = {
        "role": model["role"],
        "clearance": model["clearance"],
        "classification": model["classification"],
        "public": sorted(model["public"]),
        "member": {user: sorted(teams) for user, teams in model["member"].items()},
        "team_resource": {team: sorted(resources)
                          for team, resources in model["team_resource"].items()},
    }
    data_path = target / "data.json"
    policy_path = target / "policy.rego"
    data_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    policy_path.write_text(REGO, encoding="utf-8")
    return data_path, policy_path


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
    opa = shutil.which("opa")

    target = ROOT / "benchmarks" / "results" / "translations" / "opa" / args.size
    target.mkdir(parents=True, exist_ok=True)
    data_path, policy_path = write_translation(model, target)
    result = {
        "engine": "opa",
        "size": args.size,
        "available": opa is not None,
        "translation": {"data": str(data_path), "policy": str(policy_path)},
        "requests": [],
    }
    if opa is None:
        result["note"] = "opa not on PATH; translation written but not measured"
        print(json.dumps(result, indent=2))
        return 0

    for request in requests:
        input_path = target / "input.json"
        input_path.write_text(json.dumps({
            "actor": request["actor"],
            "resource": request["resource"],
        }) + "\n", encoding="utf-8")
        samples = []
        decision = None
        for _ in range(args.iterations):
            before = time.perf_counter_ns()
            completed = subprocess.run(
                [opa, "eval", "-d", str(data_path), "-d", str(policy_path),
                 "-i", str(input_path), "-f", "raw", "data.yogbench.decision"],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
            )
            after = time.perf_counter_ns()
            if completed.returncode != 0:
                raise SystemExit(f"opa failed: {completed.stderr}")
            decision = completed.stdout.strip().strip('"')
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
