"""The YOG guard used by the agent-security benchmark integrations.

The guard turns a tool call into a YOG JSON request and asks the policy decision
point.  It is deliberately small: the benchmark cares about the decision, not
about the gateway's audit/approval plumbing.  Fail-closed rules match the
production gateway:

* a request that cannot be built (unsupported argument type, too many facts) is
  a DENY, never an allow;
* an engine error is a DENY;
* ``REQUIRE_APPROVAL`` means the call did not run.  The benchmark reports it
  separately because a human could still approve it.

Arguments are sanitised before they become JSON: YOG supports strings, integers,
booleans and arrays of those, not floats or nulls.  Floats are rendered as
strings (the policy does not compare money amounts in these benchmarks) and
nulls are dropped.  Lists of objects are flattened with an index in the key, so
``attachments[0].file_id`` becomes ``input.attachments.0.file_id``.
"""
from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from yog_platform.pdp import ReferencePDP  # noqa: E402

POLICY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "policies")
_IDENT = re.compile(r"[a-z][A-Za-z0-9_]*\Z")


def policy_path(name: str) -> str:
    return os.path.join(POLICY_DIR, name if name.endswith(".yog") else name + ".yog")


def load_policy(name: str) -> str:
    with open(policy_path(name), encoding="utf-8") as handle:
        return handle.read()


def _scalar(value: Any) -> Any:
    if isinstance(value, bool) or isinstance(value, int) or isinstance(value, str):
        return value
    if isinstance(value, float):
        # YOG JSON has no floats.  Keep the value visible to the policy as text.
        return format(value, ".10g")
    if value is None:
        return None
    return str(value)


def sanitize_arguments(value: Any) -> Any:
    """Return a YOG-JSON-safe copy of a tool argument tree."""
    if isinstance(value, Mapping):
        out = {}
        for key, item in value.items():
            cleaned = sanitize_arguments(item)
            if cleaned is not None:
                out[str(key)] = cleaned
        return out
    if isinstance(value, (list, tuple)):
        items = [sanitize_arguments(item) for item in value]
        if all(not isinstance(item, (Mapping, list, tuple)) for item in items):
            return [item for item in items if item is not None]
        out = {}
        for index, item in enumerate(items):
            if item is not None:
                out[str(index)] = item
        return out
    return _scalar(value)


def facts_array(facts: Iterable[tuple[str, Iterable[Any]]]) -> list:
    out = []
    for predicate, args in facts:
        if not _IDENT.match(predicate):
            raise ValueError(f"invalid fact predicate {predicate!r}")
        values = [_scalar(arg) for arg in args]
        if not 1 <= len(values) <= 16 or any(value is None for value in values):
            raise ValueError(f"fact {predicate} has invalid arguments")
        out.append({"predicate": predicate, "args": values})
    return out


@dataclass
class Decision:
    decision: str
    reason: str
    obligations: list = field(default_factory=list)
    request: Optional[dict] = None

    @property
    def allowed(self) -> bool:
        return self.decision == "ALLOW"

    @property
    def blocked(self) -> bool:
        """Did the call fail to run?  Both DENY and an unapproved REQUIRE_APPROVAL do."""
        return self.decision != "ALLOW"

    @property
    def needs_human(self) -> bool:
        return self.decision == "REQUIRE_APPROVAL"


class ToolGuard:
    """Evaluate ``run_tool(Agent, Tool)`` with the agent's arguments as ``arg("input.*")``."""

    def __init__(self, policy: str, *, action: str = "run_tool", actor: str = "agent"):
        self.policy = policy
        self.action = action
        self.actor = actor
        self._pdp = ReferencePDP(policy)

    def check(self, tool: str, arguments: Optional[Mapping[str, Any]] = None,
              facts: Iterable[tuple[str, Iterable[Any]]] = ()) -> Decision:
        try:
            request = {
                "actor": self.actor,
                "action": self.action,
                "resource": tool,
                "args": {"input": sanitize_arguments(dict(arguments or {}))},
                "facts": facts_array(facts),
            }
        except Exception as exc:                       # an argument we cannot represent is a refusal
            return Decision("DENY", f"malformed tool call: {type(exc).__name__}: {exc}")

        try:
            result = self._pdp.check(request)
        except Exception as exc:
            return Decision("DENY", f"policy decision unavailable: {type(exc).__name__}: {exc}", request=request)

        if not isinstance(result, dict):
            return Decision("DENY", "bad policy response", request=request)
        if "error" in result:
            message = (result.get("error") or {}).get("message", "policy error")
            return Decision("DENY", f"policy error: {message}", request=request)
        decision = result.get("decision")
        if decision not in ("ALLOW", "DENY", "REQUIRE_APPROVAL"):
            return Decision("DENY", f"unknown decision {decision!r}", request=request)
        obligations = result.get("obligations") if isinstance(result.get("obligations"), list) else []
        return Decision(decision, str(result.get("reason", "")), obligations, request)

    def check_json(self, request: Mapping[str, Any]) -> Decision:
        """Check a raw YOG request (used by tests and the InjecAgent loader)."""
        try:
            result = self._pdp.check(dict(request))
        except Exception as exc:
            return Decision("DENY", f"policy decision unavailable: {type(exc).__name__}: {exc}")
        if "error" in result:
            return Decision("DENY", f"policy error: {(result.get('error') or {}).get('message', '')}")
        return Decision(str(result.get("decision", "DENY")), str(result.get("reason", "")),
                        result.get("obligations") or [])


def summarize(decisions: Iterable[Decision]) -> dict:
    """Counts used by both evaluators."""
    rows = list(decisions)
    total = len(rows)
    allow = sum(1 for d in rows if d.decision == "ALLOW")
    approval = sum(1 for d in rows if d.decision == "REQUIRE_APPROVAL")
    deny = sum(1 for d in rows if d.decision == "DENY")
    return {
        "total": total,
        "allow": allow,
        "require_approval": approval,
        "deny": deny,
        "allowed_rate": round(allow / total, 4) if total else 0.0,
        "not_executed_rate": round((approval + deny) / total, 4) if total else 0.0,
        "assisted_rate": round((allow + approval) / total, 4) if total else 0.0,
    }


def dump_json(path: str, payload: Any) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
