"""OpenFGA (Zanzibar-style ReBAC) adapter for the YOG benchmark corpus.

Translates the feature-matched ``common`` profile (admin role, team membership,
team-owned resources, manager + public resource) into:

* an OpenFGA authorization model (``model.fga`` + ``model.json``), and
* OpenFGA relationship tuples (``tuples.json``).

Includes:
* :class:`OpenFGAHttpClient` for measuring a live OpenFGA server
  (``OPENFGA_URL`` or ``--openfga-url``);
* :class:`OpenFGALocalEvaluator` (pure-Python Zanzibar tuple-graph evaluator)
  so translation equivalence can be verified without a Dockerized OpenFGA
  instance.
"""
from __future__ import annotations

import json
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

OPENFGA_DSL = """model
  schema 1.1

type user

type system
  relations
    define admin: [user]
    define manager: [user]

type team
  relations
    define member: [user]

type resource
  relations
    define system: [system]
    define owner: [team]
    define public_viewer: [user:*]
    define can_access: admin from system or member from owner or (public_viewer and manager from system)
"""


def write_translation(model: dict, out_dir: Path) -> None:
    """Write OpenFGA ``model.fga`` and ``tuples.json`` for ``model``."""
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "model.fga").write_text(OPENFGA_DSL, encoding="utf-8")

    tuples: List[Dict[str, str]] = []
    for user, role in sorted(model["role"].items()):
        if role == "admin":
            tuples.append({"user": f"user:{user}", "relation": "admin", "object": "system:global"})
        elif role == "manager":
            tuples.append({"user": f"user:{user}", "relation": "manager", "object": "system:global"})

    for user, teams in sorted(model["member"].items()):
        for team in sorted(teams):
            tuples.append({"user": f"user:{user}", "relation": "member", "object": f"team:{team}"})

    resources: Set[str] = set()
    for team, res_set in sorted(model["team_resource"].items()):
        for res in sorted(res_set):
            resources.add(res)
            tuples.append({"user": f"team:{team}", "relation": "owner", "object": f"resource:{res}"})

    for res in sorted(model["public"]):
        resources.add(res)
        tuples.append({"user": "user:*", "relation": "public_viewer", "object": f"resource:{res}"})

    for res in sorted(resources):
        tuples.append({"user": "system:global", "relation": "system", "object": f"resource:{res}"})

    (out_dir / "tuples.json").write_text(json.dumps({"tuples": tuples}, indent=2) + "\n", encoding="utf-8")


class OpenFGALocalEvaluator:
    """Deterministic local evaluator over OpenFGA relationship tuples."""

    def __init__(self, tuples: List[Dict[str, str]]):
        self._admins: Set[str] = set()
        self._managers: Set[str] = set()
        self._team_members: Dict[str, Set[str]] = {}
        self._resource_owners: Dict[str, Set[str]] = {}
        self._public_resources: Set[str] = set()
        self._resource_systems: Dict[str, Set[str]] = {}

        for t in tuples:
            user, rel, obj = t["user"], t["relation"], t["object"]
            if rel == "admin" and obj == "system:global" and user.startswith("user:"):
                self._admins.add(user[5:])
            elif rel == "manager" and obj == "system:global" and user.startswith("user:"):
                self._managers.add(user[5:])
            elif rel == "member" and obj.startswith("team:") and user.startswith("user:"):
                self._team_members.setdefault(obj[5:], set()).add(user[5:])
            elif rel == "owner" and obj.startswith("resource:") and user.startswith("team:"):
                self._resource_owners.setdefault(obj[9:], set()).add(user[5:])
            elif rel == "public_viewer" and obj.startswith("resource:") and user == "user:*":
                self._public_resources.add(obj[9:])
            elif rel == "system" and obj.startswith("resource:"):
                self._resource_systems.setdefault(obj[9:], set()).add(user)

    def check(self, actor: str, resource: str) -> str:
        # 1. admin from system
        if actor in self._admins:
            return "ALLOW"
        # 2. member from owner
        for team in self._resource_owners.get(resource, set()):
            if actor in self._team_members.get(team, set()):
                return "ALLOW"
        # 3. public_viewer and manager from system
        if resource in self._public_resources and actor in self._managers:
            return "ALLOW"
        return "DENY"


class OpenFGAHttpClient:
    """Minimal HTTP client for a live OpenFGA server ``/stores/{id}/check``."""

    def __init__(self, base_url: str, store_id: str, model_id: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.store_id = store_id
        self.model_id = model_id

    def check(self, actor: str, resource: str) -> str:
        payload: Dict[str, Any] = {
            "tuple_key": {
                "user": f"user:{actor}",
                "relation": "can_access",
                "object": f"resource:{resource}",
            }
        }
        if self.model_id:
            payload["authorization_model_id"] = self.model_id
        req = urllib.request.Request(
            f"{self.base_url}/stores/{self.store_id}/check",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        return "ALLOW" if body.get("allowed") else "DENY"
