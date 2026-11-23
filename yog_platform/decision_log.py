"""Decision logs in the shape OPA uses, so existing log pipelines can ingest them.

One JSON object per line::

    {"decision_id": "...", "timestamp": "2026-11-23T10:00:00.123456Z", "path": "yog/run_tool",
     "input_hash": "<sha256 of the canonical request>", "result": {"decision": "DENY", "reason": "...",
     "obligations": [], "matched_line": 12}, "bundles": {"policy": {"revision": "<policy hash>"}},
     "metrics": {"timer_decision_ns": 81234}, "labels": {"component": "yog-sidecar", "policy_version": 3}}

The request itself is **not** logged by default (it can hold secrets and personal data).  Turn on
``include_input`` to add an ``input`` field, and pass ``redact`` (a function that returns a copy with sensitive
values removed) to control what is written.  A failure to write the log is reported to the caller; the sidecar
counts it and does not change the decision, because this is observability, not the audit trail (the
hash-chained audit log is what a deny-on-failure policy relies on).
"""
from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone
from typing import Callable, Optional


def redact_values(request: dict, keys=("args", "env", "state")) -> dict:
    """A ready-made ``redact``: keeps the request's shape but replaces every leaf under ``args``, ``env`` and
    ``state`` with a placeholder."""
    def scrub(value):
        if isinstance(value, dict):
            return {k: scrub(v) for k, v in value.items()}
        if isinstance(value, list):
            return [scrub(v) for v in value]
        return "<redacted>"
    return {k: (scrub(v) if k in keys else v) for k, v in request.items()}


class DecisionLog:
    def __init__(self, path: str, *, include_input: bool = False, redact: Optional[Callable[[dict], dict]] = None,
                 component: str = "yog-sidecar"):
        self._path = path
        self._include_input = include_input
        self._redact = redact
        self._component = component
        self._lock = threading.Lock()

    def entry(self, request: dict, result: dict, *, request_hash: str, policy_hash: str, policy_version: int,
              duration_ns: int) -> dict:
        action = request.get("action") if isinstance(request.get("action"), str) else "unknown"
        out = {
            "decision_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "path": f"yog/{action}",
            "input_hash": request_hash,
            "result": {"decision": result.get("decision"), "reason": result.get("reason", ""),
                       "obligations": result.get("obligations", []), "matched_line": result.get("matched_line", 0)},
            "bundles": {"policy": {"revision": policy_hash}},
            "metrics": {"timer_decision_ns": int(duration_ns)},
            "labels": {"component": self._component, "policy_version": policy_version},
        }
        if "error" in result:
            out["error"] = result["error"] if isinstance(result["error"], dict) else {"message": str(result["error"])}
        if self._include_input:
            out["input"] = self._redact(request) if self._redact else request
        return out

    def write(self, entry: dict) -> None:
        line = json.dumps(entry, separators=(",", ":"), ensure_ascii=False)
        with self._lock, open(self._path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
