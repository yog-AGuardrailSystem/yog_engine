"""Turns the engine's text trace into structured events.

The C engine writes a line-oriented trace (``?- goal``, ``try rule p/2 (line 7)``, ``-> DENY (...)``).  This
parses it into a list of events a UI or log pipeline can use.  Traces contain request values: treat them as
sensitive, and keep them out of shared logs (docs/THREAT_MODEL.md, T13).
"""
from __future__ import annotations

import re

MAX_EVENTS = 10_000
_TRY = re.compile(r"^try (fact|rule|decision) (\S+) \(line (\d+)\)$")
_DECISION = re.compile(r"^-> (ALLOW|DENY|REQUIRE_APPROVAL) \((.*)\)$")


def to_events(trace: str) -> dict:
    events, truncated = [], False
    for number, raw in enumerate((trace or "").splitlines()):
        line = raw[1:].strip() if raw.startswith(">") else raw.strip()
        if not line:
            continue
        if len(events) >= MAX_EVENTS:
            truncated = True
            break
        match = _TRY.match(line)
        decision = _DECISION.match(line)
        if match:
            events.append({"id": len(events), "kind": "try_clause", "clause_kind": match.group(1),
                           "predicate": match.group(2), "line": int(match.group(3))})
        elif decision:
            events.append({"id": len(events), "kind": "decision", "decision": decision.group(1),
                           "reason": decision.group(2)})
        elif line.startswith("?- "):
            events.append({"id": len(events), "kind": "goal", "text": line[3:]})
        else:
            events.append({"id": len(events), "kind": "note", "text": line})
    return {"events": events, "truncated": truncated}
