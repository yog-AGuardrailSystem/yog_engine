#!/usr/bin/env python3
"""Translate one generated corpus to OPA/Rego and measure it if OPA is installed.

The translation is intentionally direct: the four YOG allow clauses become four
Rego rules, and the deny > allow > default-deny contract is represented by the
final `decision` rule.  Measurement is **CLI per request**: every sample spawns
`opa eval`, so policy load and process startup are included, exactly as they are
for `yogc check`.  If `opa` is not found the adapter writes the translation and
reports `available: false`; it never invents numbers.

Usage:
    python benchmarks/adapters/opa_adapter.py --size small [--iterations 25]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

from corpus import (build_model, corpus_file, load_requests, parse_facts,
                    PROFILES)
from stats import measure, require_decision

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CORPUS = ROOT / "benchmarks" / "generated"
BOUNDARY = "cli-process"

REGO_HEAD = """package yogbench

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
"""

REGO_CLEARANCE = """
allowed contains true if {
    object.get(data.clearance, input.actor, -1) >= object.get(data.classification, input.resource, 1000000)
}
"""

REGO_TAIL = """
decision := "ALLOW" if { count(allowed) > 0 } else := "DENY"
"""


def policy_text(profile: str) -> str:
    body = REGO_HEAD + (REGO_CLEARANCE if profile == "full" else "") + REGO_TAIL
    return body


def find_opa() -> str | None:
    found = shutil.which("opa")
    if found:
        return found
    local = ROOT / ".tools" / ("opa.exe" if os.name == "nt" else "opa")
    return str(local) if local.exists() else None


def tool_version(opa: str) -> str:
    completed = subprocess.run([opa, "version"], capture_output=True,
                               text=True, encoding="utf-8", errors="replace")
    first = (completed.stdout or completed.stderr).strip().splitlines()
    return first[0].strip() if first else "unknown"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_translation(model: dict, target: Path, profile: str) -> tuple[Path, Path]:
    data = {
        "role": model["role"],
        "public": sorted(model["public"]),
        "member": {user: sorted(teams) for user, teams in model["member"].items()},
        "team_resource": {team: sorted(resources)
                          for team, resources in model["team_resource"].items()},
    }
    if profile == "full":
        data["clearance"] = model["clearance"]
        data["classification"] = model["classification"]
    data_path = target / "data.json"
    policy_path = target / "policy.rego"
    data_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    policy_path.write_text(policy_text(profile), encoding="utf-8")
    return data_path, policy_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size", choices=["small", "medium", "large"], default="small")
    parser.add_argument("--profile", choices=PROFILES, default="full")
    parser.add_argument("--iterations", type=int, default=25)
    parser.add_argument("--warmup", type=int, default=2)
    parser.add_argument("--repetitions", type=int, default=2)
    args = parser.parse_args()

    corpus = corpus_file(CORPUS, args.profile, args.size)
    if not corpus.exists():
        raise SystemExit(f"missing {corpus}; run benchmarks/gen_corpus.py first")
    model = build_model(parse_facts(corpus))
    requests = load_requests(CORPUS, args.size, args.profile)
    opa = find_opa()

    folder = args.size if args.profile == "full" else f"common-{args.size}"
    target = ROOT / "benchmarks" / "results" / "translations" / "opa" / folder
    target.mkdir(parents=True, exist_ok=True)
    data_path, policy_path = write_translation(model, target, args.profile)
    result = {
        "engine": "opa",
        "size": args.size,
        "profile": args.profile,
        "boundary": BOUNDARY,
        "available": opa is not None,
        "executable": opa,
        "translation": {
            "data": str(data_path),
            "policy": str(policy_path),
            "data_sha256": digest(data_path),
            "policy_sha256": digest(policy_path),
        },
        "requests": [],
    }
    if opa is None:
        result["note"] = "opa not found; translation written but not measured"
        print(json.dumps(result, indent=2))
        return 0

    result["tool_version"] = tool_version(opa)

    for request in requests:
        input_path = target / "input.json"
        input_path.write_text(json.dumps({
            "actor": request["actor"],
            "resource": request["resource"],
        }) + "\n", encoding="utf-8")

        command = [opa, "eval", "-d", str(data_path), "-d", str(policy_path),
                   "-i", str(input_path), "-f", "raw", "data.yogbench.decision"]

        def invoke() -> str:
            completed = subprocess.run(command, capture_output=True, text=True,
                                       encoding="utf-8", errors="replace")
            if completed.returncode != 0:
                raise SystemExit(f"opa failed: {completed.stderr}")
            return completed.stdout.strip().strip('"')

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
