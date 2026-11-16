#!/usr/bin/env python3
"""Translate one generated corpus to Cedar and measure it if the CLI is installed.

Users are members of Role and Team groups; resources carry an `owner` entity
reference and a `public` flag.  That makes the team join `principal in
resource.owner`, and the clearance clause a direct integer comparison.
Measurement is **CLI per request**, matching `yogc check`: policy parse,
entity load and process startup are all included.

If `cedar` is not found the translation is written and the adapter reports
`available: false`.  Policy evaluation errors are surfaced, never timed as a
decision.

Usage:
    python benchmarks/adapters/cedar_adapter.py --size small [--iterations 10]
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

POLICY_HEAD = """// Generated from the YOG benchmark corpus.
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
"""

POLICY_CLEARANCE = """
permit (
    principal,
    action == Action::"can_access",
    resource
)
when { principal.clearance >= resource.classification };
"""

POLICY_ALT_HEAD = """// Independently written translation used to check that the measured
// behaviour is a property of the corpus, not of one translation style:
// a single permit whose condition is a disjunction.
permit (
    principal,
    action == Action::"can_access",
    resource
)
when {
    principal in Role::"admin" ||
    principal in resource.owner ||
    (principal in Role::"manager" && resource.public)
"""

POLICY_ALT_CLEARANCE = """    ||
    principal.clearance >= resource.classification
"""


def policy_text(profile: str) -> str:
    return POLICY_HEAD + (POLICY_CLEARANCE if profile == "full" else "")


def policy_text_alt(profile: str) -> str:
    body = POLICY_ALT_HEAD
    if profile == "full":
        body += POLICY_ALT_CLEARANCE
    return body + "};\n"


def find_cedar() -> str | None:
    found = shutil.which("cedar")
    if found:
        return found
    candidate = Path.home() / ".cargo" / "bin" / ("cedar.exe" if os.name == "nt" else "cedar")
    return str(candidate) if candidate.exists() else None


def tool_version(cedar: str) -> str:
    completed = subprocess.run([cedar, "--version"], capture_output=True,
                               text=True, encoding="utf-8", errors="replace")
    text = (completed.stdout or completed.stderr).strip().splitlines()
    return text[0].strip() if text else "unknown"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def entity_ref(entity_type: str, entity_id: str) -> dict:
    """Cedar's JSON entity format wraps entity-valued attributes in __entity."""
    return {"__entity": {"type": entity_type, "id": entity_id}}


def write_translation(model: dict, target: Path, profile: str) -> tuple[Path, Path]:
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
        attrs = {}
        if profile == "full":
            attrs["clearance"] = model["clearance"].get(user, 0)
        entities.append({
            "uid": {"type": "User", "id": user},
            "attrs": attrs,
            "parents": parents,
        })

    resources = set(model["classification"]) | model["public"] | {"r_denied", "r_secret"}
    for owned in model["team_resource"].values():
        resources |= owned
    for resource in sorted(resources):
        owner = model["owner"].get(resource, "public")
        attrs = {
            "public": resource in model["public"],
            "owner": entity_ref("Team", owner),
        }
        if profile == "full":
            attrs["classification"] = model["classification"].get(resource, 5)
        entities.append({"uid": {"type": "Resource", "id": resource},
                         "attrs": attrs, "parents": []})

    policy_path = target / "policy.cedar"
    policy_alt_path = target / "policy_alt.cedar"
    entities_path = target / "entities.json"
    policy_path.write_text(policy_text(profile), encoding="utf-8")
    policy_alt_path.write_text(policy_text_alt(profile), encoding="utf-8")
    entities_path.write_text(json.dumps(entities, indent=2) + "\n", encoding="utf-8")
    return policy_path, entities_path


def parse_decision(stdout: str) -> str:
    text = stdout.strip()
    if text.startswith("{"):
        try:
            payload = json.loads(text)
            decision = str(payload.get("decision", ""))
            if decision.lower() in ("allow", "deny"):
                return decision.upper()
        except ValueError:
            pass
    first = text.splitlines()[0].strip().upper() if text else ""
    return first if first in ("ALLOW", "DENY") else "UNKNOWN"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size", choices=["small", "medium", "large"], default="small")
    parser.add_argument("--profile", choices=PROFILES, default="full")
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--repetitions", type=int, default=2)
    args = parser.parse_args()

    corpus = corpus_file(CORPUS, args.profile, args.size)
    if not corpus.exists():
        raise SystemExit(f"missing {corpus}; run benchmarks/gen_corpus.py first")
    model = build_model(parse_facts(corpus))
    requests = load_requests(CORPUS, args.size, args.profile)
    cedar = find_cedar()

    folder = args.size if args.profile == "full" else f"common-{args.size}"
    target = ROOT / "benchmarks" / "results" / "translations" / "cedar" / folder
    target.mkdir(parents=True, exist_ok=True)
    policy_path, entities_path = write_translation(model, target, args.profile)
    result = {
        "engine": "cedar",
        "size": args.size,
        "profile": args.profile,
        "boundary": BOUNDARY,
        "available": cedar is not None,
        "executable": cedar,
        "translation": {
            "policy": str(policy_path),
            "policy_alt": str(policy_path.parent / "policy_alt.cedar"),
            "entities": str(entities_path),
            "policy_sha256": digest(policy_path),
            "policy_alt_sha256": digest(policy_path.parent / "policy_alt.cedar"),
            "entities_sha256": digest(entities_path),
        },
        "requests": [],
    }
    if cedar is None:
        result["note"] = "cedar CLI not found; translation written but not measured"
        print(json.dumps(result, indent=2))
        return 0

    result["tool_version"] = tool_version(cedar)

    for request in requests:
        request_path = target / "request.json"
        request_path.write_text(json.dumps({
            "principal": f'User::"{request["actor"]}"',
            "action": 'Action::"can_access"',
            "resource": f'Resource::"{request["resource"]}"',
            "context": {},
        }) + "\n", encoding="utf-8")

        command = [cedar, "authorize", "--policies", str(policy_path),
                   "--entities", str(entities_path), "--request-json", str(request_path)]

        def invoke() -> str:
            completed = subprocess.run(command, capture_output=True, text=True,
                                       encoding="utf-8", errors="replace")
            combined = completed.stdout + completed.stderr
            if "error while evaluating policy" in combined:
                raise SystemExit(f"cedar evaluation error: {completed.stdout}{completed.stderr}")
            decision = parse_decision(completed.stdout)
            # The Cedar CLI exits 2 for a DENY decision, so a non-zero status is
            # not an error when a decision was parsed.
            if decision == "UNKNOWN":
                raise SystemExit(
                    f"cedar produced no decision (exit {completed.returncode}): "
                    f"{completed.stdout}{completed.stderr}"
                )
            return decision

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
