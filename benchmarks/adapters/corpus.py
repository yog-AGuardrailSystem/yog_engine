"""Shared reader for the generated benchmark corpus.

The corpus is deliberately a small, regular subset of YOG (ground facts plus
one decision predicate), so each adapter can translate it without embedding a
full YOG parser.  Two profiles are supported:

* ``full``   -- includes the numeric clearance clause; not feature-matched.
* ``common`` -- only features every engine can express; used for the fair
  comparison.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

FACT_RE = re.compile(r"^fact\s+([A-Za-z_][A-Za-z0-9_]*)\(([^)]*)\)\s*$")
DECISION = "can_access"
PROFILES = ("full", "common")


def parse_value(text: str):
    text = text.strip()
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    return text


def parse_facts(policy: Path) -> dict[str, list[tuple]]:
    facts: dict[str, list[tuple]] = {}
    for line in policy.read_text(encoding="utf-8").splitlines():
        match = FACT_RE.match(line.strip())
        if not match:
            continue
        name, raw_args = match.groups()
        args = tuple(parse_value(part) for part in raw_args.split(",") if part.strip())
        facts.setdefault(name, []).append(args)
    return facts


def corpus_file(corpus_dir: Path, profile: str, size: str) -> Path:
    if profile not in PROFILES:
        raise ValueError(f"unknown profile: {profile}")
    return corpus_dir / (f"{size}.yog" if profile == "full" else f"common-{size}.yog")


def requests_file(corpus_dir: Path, profile: str) -> Path:
    if profile not in PROFILES:
        raise ValueError(f"unknown profile: {profile}")
    return corpus_dir / ("requests.json" if profile == "full" else "common-requests.json")


def load_requests(corpus_dir: Path, size: str, profile: str = "full") -> list[dict]:
    spec = json.loads(requests_file(corpus_dir, profile).read_text(encoding="utf-8"))
    return spec["by_size"][size]


def load_workload(corpus_dir: Path, profile: str, size: str) -> list[dict]:
    path = corpus_dir / f"workload-{profile}-{size}.json"
    return json.loads(path.read_text(encoding="utf-8"))["requests"]


def write_request_tsv(corpus_dir: Path, profile: str, size: str, target: Path) -> Path:
    """Write the TSV format the Rust/Go harnesses read."""
    rows = load_workload(corpus_dir, profile, size)
    lines = []
    for row in rows:
        context = row.get("context", "")
        lines.append("\t".join([
            row["label"], row["actor"], row["action"], row["resource"], context
        ]))
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return target


def build_model(facts: dict[str, list[tuple]]) -> dict:
    """Normalise the fact tables the adapters need."""
    role = {args[0]: args[1] for args in facts.get("role", [])}
    clearance = {args[0]: args[1] for args in facts.get("clearance", [])}
    classification = {args[0]: args[1] for args in facts.get("classification", [])}
    public = {args[0] for args in facts.get("public", [])}

    member: dict[str, set[str]] = {}
    for user, team in facts.get("member", []):
        member.setdefault(user, set()).add(team)

    team_resource: dict[str, set[str]] = {}
    owner: dict[str, str] = {}
    for team, resource in facts.get("team_resource", []):
        team_resource.setdefault(team, set()).add(resource)
        owner.setdefault(resource, team)

    return {
        "role": role,
        "clearance": clearance,
        "classification": classification,
        "public": public,
        "member": member,
        "team_resource": team_resource,
        "owner": owner,
    }
