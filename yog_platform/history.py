"""Temporal and sequence-history policy support for YOG.

Maintains a bounded per-agent event log of tool calls with timestamps and
projects deterministic facts into ``request["facts"]`` so policies can reason
about sequences, sliding-window counts, and cooldowns without adding mutable
state or wall-clock I/O to the YOG core engine:

* ``recent_call(Agent, Tool, Count, WindowSeconds)``
* ``recent_calls_total(Agent, Count, WindowSeconds)``
* ``last_call_age(Agent, Tool, AgeSeconds)``
* ``sequence_followed(Agent, PriorTool, CurrentTool, WindowSeconds)``
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Deque, Iterable, List, Tuple


@dataclass(frozen=True)
class HistoryEvent:
    timestamp: int
    agent: str
    tool: str
    decision: str


class EventHistory:
    """Bounded sliding-window history of tool calls per agent."""

    def __init__(self, *, windows: Iterable[int] = (60, 300, 3600), max_events: int = 1000):
        self._windows: Tuple[int, ...] = tuple(sorted({int(w) for w in windows if int(w) > 0}))
        self._max_events = max(1, int(max_events))
        self._events: Deque[HistoryEvent] = deque(maxlen=self._max_events)

    def record(self, agent: str, tool: str, decision: str, timestamp: int) -> None:
        self._events.append(
            HistoryEvent(
                timestamp=int(timestamp),
                agent=str(agent),
                tool=str(tool),
                decision=str(decision),
            )
        )

    def _agent_events(self, agent: str, now: int) -> List[HistoryEvent]:
        max_win = self._windows[-1] if self._windows else 0
        cutoff = int(now) - max_win if max_win else 0
        return [
            ev for ev in self._events
            if ev.agent == agent and (not max_win or ev.timestamp >= cutoff) and ev.timestamp <= now
        ]

    def facts_for(self, agent: str, current_tool: str, now: int) -> list[dict]:
        """Return YOG JSON facts summarizing ``agent``'s recent history up to ``now``."""
        now_i = int(now)
        events = self._agent_events(agent, now_i)
        facts: list[dict] = []

        # Per-window counts and sequence checks.
        for window in self._windows:
            cutoff = now_i - window
            in_win = [ev for ev in events if ev.timestamp >= cutoff]
            facts.append({
                "predicate": "recent_calls_total",
                "args": [agent, len(in_win), window],
            })
            per_tool: dict[str, int] = {}
            for ev in in_win:
                per_tool[ev.tool] = per_tool.get(ev.tool, 0) + 1
            for tool_name, count in sorted(per_tool.items()):
                facts.append({
                    "predicate": "recent_call",
                    "args": [agent, tool_name, count, window],
                })
                facts.append({
                    "predicate": "sequence_followed",
                    "args": [agent, tool_name, current_tool, window],
                })

        # Most recent call age per tool.
        last_seen: dict[str, int] = {}
        for ev in events:
            if ev.tool not in last_seen or ev.timestamp > last_seen[ev.tool]:
                last_seen[ev.tool] = ev.timestamp
        for tool_name, ts in sorted(last_seen.items()):
            facts.append({
                "predicate": "last_call_age",
                "args": [agent, tool_name, max(0, now_i - ts)],
            })

        return facts
