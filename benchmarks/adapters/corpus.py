"""Shared reader for the generated benchmark corpus.

The corpus is deliberately a small, regular subset of YOG (ground facts plus
one decision predicate), so each adapter can translate it without embedding a
full YOG parser.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

FACT_RE = re.compile(r"^fact\s+([A-Za-z_][A-Za-z0-9_]*)\(([^)]*)\)\s*$")
DECISION = "can_access"


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


def load_requests(corpus_dir: Path, size: str) -> list[dict]:
    spec = json.loads((corpus_dir / "requests.json").read_text(encoding="utf-8"))
    return spec["by_size"][size]


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
