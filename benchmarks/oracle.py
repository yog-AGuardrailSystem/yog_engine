"""Independent reference semantics for the benchmark corpus.

This module deliberately does **not** import the YOG engine, the YOG Python
binding, or any adapter translation.  It is a second, small implementation of
the documented contract:

    any satisfied allow clause -> ALLOW
    otherwise                  -> DENY          (fail-closed default)

For the ``full`` profile the four allow clauses are evaluated in the same
order as the policy (admin, team join, manager+public, clearance).  For
``common`` only the first three exist.  There are no deny rules in this corpus,
so the deny-overrides part of the contract has no effect here; it is exercised
by the conformance suite, not by this oracle.

Agreement between this oracle, YOG, OPA, Cedar and Casbin is evidence about
these 300 requests, not a proof of language equivalence.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

FACT_RE = re.compile(r"^fact\s+([A-Za-z_][A-Za-z0-9_]*)\(([^)]*)\)\s*$")


def _value(text: str):
    text = text.strip()
    return int(text) if re.fullmatch(r"-?\d+", text) else text


@dataclass
class Model:
    role: dict[str, str] = field(default_factory=dict)
    member: dict[str, set[str]] = field(default_factory=dict)
    team_resource: dict[str, set[str]] = field(default_factory=dict)
    public: set[str] = field(default_factory=set)
    clearance: dict[str, int] = field(default_factory=dict)
    classification: dict[str, int] = field(default_factory=dict)

    def allowed(self, actor: str, resource: str, profile: str) -> bool:
        if self.role.get(actor) == "admin":
            return True
        teams = self.member.get(actor, set())
        for team in teams:
            if resource in self.team_resource.get(team, set()):
                return True
        if self.role.get(actor) == "manager" and resource in self.public:
            return True
        if profile == "full":
            level = self.clearance.get(actor)
            needed = self.classification.get(resource)
            if level is not None and needed is not None and level >= needed:
                return True
        return False


def load_model(policy: Path) -> Model:
    model = Model()
    for line in policy.read_text(encoding="utf-8").splitlines():
        match = FACT_RE.match(line.strip())
        if not match:
            continue
        name, raw = match.groups()
        args = tuple(_value(part) for part in raw.split(",") if part.strip())
        if name == "role" and len(args) == 2:
            model.role[args[0]] = args[1]
        elif name == "member" and len(args) == 2:
            model.member.setdefault(args[0], set()).add(args[1])
        elif name == "team_resource" and len(args) == 2:
            model.team_resource.setdefault(args[0], set()).add(args[1])
        elif name == "public" and len(args) == 1:
            model.public.add(args[0])
        elif name == "clearance" and len(args) == 2:
            model.clearance[args[0]] = args[1]
        elif name == "classification" and len(args) == 2:
            model.classification[args[0]] = args[1]
    return model


def decide(model: Model, profile: str, actor: str, resource: str) -> str:
    return "ALLOW" if model.allowed(actor, resource, profile) else "DENY"


def corpus_path(corpus_dir: Path, profile: str, size: str) -> Path:
    return corpus_dir / (f"{size}.yog" if profile == "full" else f"common-{size}.yog")


def source_facts(model: Model) -> dict:
    """Return the fact tables in the shape the adapters already use."""
    owner: dict[str, str] = {}
    for team, resources in model.team_resource.items():
        for resource in resources:
            owner.setdefault(resource, team)
    return {
        "role": dict(model.role),
        "clearance": dict(model.clearance),
        "classification": dict(model.classification),
        "public": set(model.public),
        "member": {user: set(teams) for user, teams in model.member.items()},
        "team_resource": {team: set(resources)
                          for team, resources in model.team_resource.items()},
        "owner": owner,
    }
